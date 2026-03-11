import signal
import time
from typing import Any
from urllib.parse import urlparse

from fingerprint_worker.config.env import WorkerConfig
from fingerprint_worker.providers.http_provider import fetch_http
from fingerprint_worker.providers.logging_provider import LOGGER
from fingerprint_worker.providers.tls_provider import jarm_runtime_error, load_asn_db
from fingerprint_worker.runtime.reporting import (
    call_stage_mutation,
    finalize_run,
    record_run_issue,
)
from fingerprint_worker.service.http_analysis import analyze_content, build_http_payload
from fingerprint_worker.service.fingerprint_core import strip_nones
from fingerprint_worker.service.runtime_helpers import (
    build_run_outcome,
    clamp_text,
    map_outcome_kind_to_run_status,
    now_ms,
)
from fingerprint_worker.service.tls_analysis import build_tls_payload
from fingerprint_worker.types.runtime import (
    ISSUE_DETAIL_MAX_LEN,
    RUN_ISSUE_CODE_PROCESSING_EXCEPTION,
    RUN_ISSUE_STAGE_PROCESSING,
    RUN_ISSUE_STAGE_UPSERT_ANALYTICS,
    RUN_ISSUE_STAGE_UPSERT_ASSETS,
    RUN_ISSUE_STAGE_UPSERT_FAVICON,
    RUN_ISSUE_STAGE_UPSERT_HTML,
    RUN_ISSUE_STAGE_UPSERT_HTTP,
    RUN_ISSUE_STAGE_UPSERT_TLS,
    RUN_OUTCOME_WORKER_EXCEPTION,
    RUN_STATUS_ERROR,
)


def get_job_record_id(item: dict[str, object]) -> str | None:
    value = item.get("networkArtifactId")
    return value if isinstance(value, str) else None


def get_job_host(item: dict[str, object]) -> str | None:
    value = item.get("websiteHost")
    return value if isinstance(value, str) else None


def get_job_url(item: dict[str, object]) -> str | None:
    url = item.get("websiteUrl")
    if isinstance(url, str) and url:
        return url
    host = get_job_host(item)
    return f"https://{host}" if host else None


def process_item(
    config: WorkerConfig,
    sink: Any,
    item: dict[str, object],
    asn_db: Any | None,
    asn_error: str | None,
) -> None:
    scan_id = item.get("runId")
    scan_id = scan_id if isinstance(scan_id, str) else None
    record_id = get_job_record_id(item)
    host = get_job_host(item)
    requested_url = get_job_url(item) or "https://unknown"
    fetched_at = now_ms()
    run_status = RUN_STATUS_ERROR
    outcome = None
    error_message = None
    stage_errors: list[str] = []

    LOGGER.debug(
        "processing host=%s recordId=%s runId=%s requestedUrl=%s",
        host,
        record_id,
        scan_id,
        requested_url,
    )
    try:
        http_result = fetch_http(
            requested_url,
            config.fingerprint_timeout_ms,
            config.fingerprint_html_max_bytes,
            config.fingerprint_user_agent,
            config.fingerprint_max_headers,
            config.fingerprint_header_value_max,
            config.fingerprint_max_set_cookie,
            config.fingerprint_set_cookie_max,
        )
        body_bytes = http_result.get("body_bytes", b"")
        if not isinstance(body_bytes, bytes):
            body_bytes = b""
        sample_bytes = body_bytes[: config.fingerprint_sample_bytes]
        sample_truncated = len(body_bytes) > len(sample_bytes)
        outcome = build_run_outcome(http_result, sample_bytes, sample_truncated)
        run_status = map_outcome_kind_to_run_status(str(outcome.get("kind")))
        detail = outcome.get("detail")
        error_message = detail if isinstance(detail, str) else None

        LOGGER.debug(
            "http result host=%s runId=%s outcomeKind=%s runStatus=%s httpStatus=%s durationMs=%s bodyBytes=%s",
            host,
            scan_id,
            outcome.get("kind"),
            run_status,
            http_result.get("status"),
            http_result.get("duration_ms"),
            len(body_bytes),
        )
        if config.log_http_details:
            LOGGER.debug(
                "http details host=%s runId=%s finalUrl=%s redirects=%s headers=%s",
                host,
                scan_id,
                http_result.get("final_url"),
                http_result.get("redirect_chain") or [],
                http_result.get("headers") or [],
            )

        call_stage_mutation(
            sink,
            "fingerprints:upsertHttpFingerprint",
            build_http_payload(scan_id, record_id, fetched_at, http_result),
            scan_id,
            record_id,
            config.worker_id,
            RUN_ISSUE_STAGE_UPSERT_HTTP,
            stage_errors,
        )

        content: dict[str, Any] = analyze_content(
            config,
            scan_id,
            record_id,
            requested_url,
            fetched_at,
            http_result,
        )
        LOGGER.debug(
            "html fingerprint host=%s runId=%s htmlOk=%s htmlLength=%s",
            host,
            scan_id,
            content["html_ok"],
            len(body_bytes),
        )
        call_stage_mutation(
            sink,
            "fingerprints:upsertHtmlFingerprint",
            content["html_payload"],
            scan_id,
            record_id,
            config.worker_id,
            RUN_ISSUE_STAGE_UPSERT_HTML,
            stage_errors,
        )
        call_stage_mutation(
            sink,
            "fingerprints:upsertAssetsFingerprint",
            content["assets_payload"],
            scan_id,
            record_id,
            config.worker_id,
            RUN_ISSUE_STAGE_UPSERT_ASSETS,
            stage_errors,
        )
        call_stage_mutation(
            sink,
            "fingerprints:upsertAnalyticsFingerprint",
            content["analytics_payload"],
            scan_id,
            record_id,
            config.worker_id,
            RUN_ISSUE_STAGE_UPSERT_ANALYTICS,
            stage_errors,
        )
        call_stage_mutation(
            sink,
            "fingerprints:upsertFaviconFingerprint",
            content["favicon_payload"],
            scan_id,
            record_id,
            config.worker_id,
            RUN_ISSUE_STAGE_UPSERT_FAVICON,
            stage_errors,
        )

        tls_payload = build_tls_payload(
            config,
            scan_id,
            record_id,
            fetched_at,
            str(content["base_url"]),
            asn_db,
            asn_error,
        )
        parsed_host = urlparse(str(content["base_url"])).hostname or ""
        LOGGER.debug(
            "tls fingerprint host=%s runId=%s errorType=%s",
            parsed_host,
            scan_id,
            tls_payload.get("errorType"),
        )
        call_stage_mutation(
            sink,
            "fingerprints:upsertTlsFingerprint",
            tls_payload,
            scan_id,
            record_id,
            config.worker_id,
            RUN_ISSUE_STAGE_UPSERT_TLS,
            stage_errors,
        )
    except Exception as error:
        error_detail = clamp_text(error, ISSUE_DETAIL_MAX_LEN) or "unknown_error"
        LOGGER.exception(
            "processing failed host=%s runId=%s error=%s",
            host,
            scan_id,
            error,
        )
        run_status = RUN_STATUS_ERROR
        error_message = f"processing_exception: {error_detail}"
        outcome = {"kind": RUN_OUTCOME_WORKER_EXCEPTION, "detail": error_detail}
        record_run_issue(
            sink,
            scan_id,
            record_id,
            config.worker_id,
            RUN_ISSUE_STAGE_PROCESSING,
            RUN_ISSUE_CODE_PROCESSING_EXCEPTION,
            "unexpected worker exception during processing",
            error_detail,
        )
    finally:
        if stage_errors:
            run_status = RUN_STATUS_ERROR
            joined_stage_errors = clamp_text(
                "; ".join(stage_errors), ISSUE_DETAIL_MAX_LEN
            )
            if error_message:
                error_message = clamp_text(
                    f"{error_message}; stageErrors={joined_stage_errors}",
                    500,
                )
            else:
                error_message = clamp_text(f"stageErrors={joined_stage_errors}", 500)
        if outcome is None:
            outcome = {"kind": RUN_STATUS_ERROR, "detail": "missing_outcome"}
        finalize_run(
            sink,
            host,
            scan_id,
            record_id,
            config.worker_id,
            run_status,
            strip_nones(outcome),
            error_message,
        )


def run_worker(
    config: WorkerConfig,
    job_source: Any,
    sink: Any,
    install_signal_handlers: bool = True,
) -> None:
    shutting_down = {"value": False}

    def handle_signal(_signum: int, _frame: object) -> None:
        shutting_down["value"] = True
        LOGGER.info("shutdown requested")

    if install_signal_handlers:
        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

    LOGGER.info(
        "starting id=%s env=%s logLevel=%s batchSize=%s pollIntervalMs=%s fingerprintTimeoutMs=%s htmlMaxBytes=%s",
        config.worker_id,
        config.worker_environment,
        config.log_level,
        config.batch_size,
        config.poll_interval_ms,
        config.fingerprint_timeout_ms,
        config.fingerprint_html_max_bytes,
    )

    asn_db = None
    asn_error = None
    if not config.fingerprint_disable_tls:
        asn_db, asn_error = load_asn_db(config.fingerprint_asn_db_path)
        if asn_error:
            LOGGER.warning(
                "ASN lookup unavailable path=%s reason=%s",
                config.fingerprint_asn_db_path or "<unset>",
                asn_error,
            )
        if config.fingerprint_disable_jarm:
            LOGGER.info("JARM disabled via FINGERPRINT_DISABLE_JARM=1")
        else:
            startup_jarm_error = jarm_runtime_error()
            if startup_jarm_error:
                LOGGER.warning("JARM unavailable: %s", startup_jarm_error)
    else:
        LOGGER.info("TLS fingerprinting disabled via FINGERPRINT_DISABLE_TLS=1")

    loop_count = 0
    while not shutting_down["value"]:
        loop_count += 1
        try:
            claim = job_source.claim(
                config.worker_id, config.batch_size, config.lease_duration_ms
            )
            work = claim.work
            lease_expires_at = claim.lease_expires_at
            if not work:
                LOGGER.debug("idle loop=%s", loop_count)
                if config.max_loops and loop_count >= config.max_loops:
                    break
                time.sleep(config.poll_interval_ms / 1000)
                continue

            expires = (
                time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", time.gmtime(lease_expires_at / 1000)
                )
                if lease_expires_at
                else "unknown"
            )
            LOGGER.info("claimed count=%s leaseExpiresAt=%s", len(work), expires)

            for item in work:
                if shutting_down["value"]:
                    break
                process_item(config, sink, item, asn_db, asn_error)

            if config.max_loops and loop_count >= config.max_loops:
                break
        except Exception as error:
            LOGGER.exception("loop error=%s", error)
            if config.max_loops and loop_count >= config.max_loops:
                break
            time.sleep(config.poll_interval_ms / 1000)

    sink.close()
    LOGGER.info("stopped")
