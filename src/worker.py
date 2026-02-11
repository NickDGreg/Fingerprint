import base64
import logging
import os
import signal
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Any, cast
from urllib.parse import urlparse

import mmh3
from convex import ConvexClient

from fingerprint_core import (
    DEFAULT_EXTERNAL_ALLOWLIST,
    collect_asset_urls,
    compute_fuzzy_hash,
    compute_sha256,
    decode_bytes,
    extract_base_url,
    extract_trackers,
    find_favicon_url,
    host_matches,
    is_allowed_domain,
    join_errors,
    looks_like_html,
    normalize_host,
    normalize_html_text,
    strip_nones,
)
from fingerprint_http import fetch_binary, fetch_http
from fingerprint_tls import (
    collect_tls_info,
    compute_jarm,
    load_asn_db,
    lookup_asn,
    resolve_ips,
)
from worker_io import (
    ConvexJobSource,
    ConvexResultSink,
    FileJobSource,
    FileResultSink,
    MemoryResultSink,
)

LOGGER = logging.getLogger("fingerprint.worker")
VALID_LOG_LEVELS = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}


def now_ms():
    return int(time.time() * 1000)


def parse_number(raw_value, fallback, minimum=None):
    if raw_value is None or raw_value == "":
        return fallback
    try:
        value = int(raw_value)
    except ValueError:
        return fallback
    if minimum is not None and value < minimum:
        return minimum
    return value


def parse_bool(raw_value, fallback):
    if raw_value is None or raw_value == "":
        return fallback
    normalized = raw_value.strip().lower()
    return normalized in {"1", "true", "yes", "on"}


def call_mutation(sink, name, payload):
    try:
        result = sink.mutation(name, payload)
        LOGGER.debug("mutation succeeded name=%s", name)
        return result
    except Exception as error:
        LOGGER.exception("mutation failed name=%s error=%s", name, error)
        return None


def build_run_outcome(http_result, sample_bytes, sample_truncated):
    if http_result.get("ok"):
        status = http_result.get("status") or 0
        kind = "http_content" if status < 400 else "http_error"
        detail = f"http_status {status}" if status >= 400 else None
        return strip_nones(
            {
                "kind": kind,
                "detail": detail,
                "httpStatus": status,
                "finalUrl": http_result.get("final_url"),
                "contentType": http_result.get("content_type"),
                "contentLength": http_result.get("content_length"),
                "sample": decode_bytes(
                    sample_bytes, http_result.get("encoding", "utf-8")
                ),
                "sampleTruncated": sample_truncated,
                "durationMs": http_result.get("duration_ms"),
            }
        )
    return strip_nones(
        {
            "kind": "unreachable",
            "detail": http_result.get("error_detail"),
            "errorType": http_result.get("error_type"),
            "durationMs": http_result.get("duration_ms"),
        }
    )


@dataclass
class WorkerConfig:
    worker_id: str
    poll_interval_ms: int
    batch_size: int
    lease_duration_ms: int
    fingerprint_timeout_ms: int
    fingerprint_html_max_bytes: int
    fingerprint_sample_bytes: int
    fingerprint_max_headers: int
    fingerprint_header_value_max: int
    fingerprint_max_set_cookie: int
    fingerprint_set_cookie_max: int
    fingerprint_asset_timeout_ms: int
    fingerprint_asset_max_bytes: int
    fingerprint_max_assets: int
    fingerprint_max_external_domains: int
    fingerprint_favicon_timeout_ms: int
    fingerprint_favicon_max_bytes: int
    fingerprint_asn_db_path: str | None
    fingerprint_jarm_timeout_ms: int
    fingerprint_disable_jarm: bool
    fingerprint_disable_tls: bool
    fingerprint_user_agent: str
    worker_environment: str
    log_level: str
    log_http_details: bool
    max_loops: int | None


def build_config(env):
    worker_environment_raw = (env.get("WORKER_ENV") or "production").strip().lower()
    if worker_environment_raw in {"dev", "development"}:
        worker_environment = "development"
    else:
        worker_environment = "production"

    default_log_level = "DEBUG" if worker_environment == "development" else "INFO"
    log_level = (env.get("WORKER_LOG_LEVEL") or default_log_level).upper()
    if log_level not in VALID_LOG_LEVELS:
        log_level = default_log_level

    log_http_details = parse_bool(
        env.get("WORKER_LOG_HTTP_DETAILS"), worker_environment == "development"
    )

    worker_id = env.get("WORKER_ID") or f"worker-{uuid.uuid4()}"
    poll_interval_ms = parse_number(env.get("WORKER_POLL_INTERVAL_MS"), 5000, 1000)
    batch_size = parse_number(env.get("WORKER_BATCH_SIZE"), 1, 1)
    lease_duration_ms = parse_number(env.get("WORKER_LEASE_DURATION_MS"), 60000, 1000)
    fingerprint_timeout_ms = parse_number(env.get("FINGERPRINT_TIMEOUT_MS"), 8000, 1000)
    fingerprint_html_max_bytes = parse_number(
        env.get("FINGERPRINT_HTML_MAX_BYTES"), 512000, 4096
    )
    fingerprint_sample_bytes = parse_number(
        env.get("FINGERPRINT_SAMPLE_BYTES"), 2048, 256
    )
    fingerprint_max_headers = parse_number(env.get("FINGERPRINT_MAX_HEADERS"), 50, 10)
    fingerprint_header_value_max = parse_number(
        env.get("FINGERPRINT_HEADER_VALUE_MAX"), 512, 64
    )
    fingerprint_max_set_cookie = parse_number(
        env.get("FINGERPRINT_MAX_SET_COOKIE"), 5, 1
    )
    fingerprint_set_cookie_max = parse_number(
        env.get("FINGERPRINT_SET_COOKIE_MAX"), 512, 64
    )
    fingerprint_asset_timeout_ms = parse_number(
        env.get("FINGERPRINT_ASSET_TIMEOUT_MS"), 5000, 1000
    )
    fingerprint_asset_max_bytes = parse_number(
        env.get("FINGERPRINT_ASSET_MAX_BYTES"), 256000, 4096
    )
    fingerprint_max_assets = parse_number(env.get("FINGERPRINT_MAX_ASSETS"), 10, 1)
    fingerprint_max_external_domains = parse_number(
        env.get("FINGERPRINT_MAX_EXTERNAL_DOMAINS"), 50, 10
    )
    fingerprint_favicon_timeout_ms = parse_number(
        env.get("FINGERPRINT_FAVICON_TIMEOUT_MS"), 5000, 1000
    )
    fingerprint_favicon_max_bytes = parse_number(
        env.get("FINGERPRINT_FAVICON_MAX_BYTES"), 100000, 1024
    )
    fingerprint_asn_db_path = env.get("FINGERPRINT_ASN_DB_PATH")
    fingerprint_jarm_timeout_ms = parse_number(
        env.get("FINGERPRINT_JARM_TIMEOUT_MS"), fingerprint_timeout_ms, 1000
    )
    fingerprint_disable_jarm = env.get("FINGERPRINT_DISABLE_JARM") == "1"
    fingerprint_disable_tls = env.get("FINGERPRINT_DISABLE_TLS") == "1"
    fingerprint_user_agent = env.get("FINGERPRINT_USER_AGENT") or (
        "TracehammerFingerprint/0.2"
    )

    max_loops = parse_number(env.get("WORKER_MAX_LOOPS"), None, 1)
    if env.get("WORKER_ONCE") == "1":
        max_loops = 1

    return WorkerConfig(
        worker_id=worker_id,
        poll_interval_ms=poll_interval_ms,
        batch_size=batch_size,
        lease_duration_ms=lease_duration_ms,
        fingerprint_timeout_ms=fingerprint_timeout_ms,
        fingerprint_html_max_bytes=fingerprint_html_max_bytes,
        fingerprint_sample_bytes=fingerprint_sample_bytes,
        fingerprint_max_headers=fingerprint_max_headers,
        fingerprint_header_value_max=fingerprint_header_value_max,
        fingerprint_max_set_cookie=fingerprint_max_set_cookie,
        fingerprint_set_cookie_max=fingerprint_set_cookie_max,
        fingerprint_asset_timeout_ms=fingerprint_asset_timeout_ms,
        fingerprint_asset_max_bytes=fingerprint_asset_max_bytes,
        fingerprint_max_assets=fingerprint_max_assets,
        fingerprint_max_external_domains=fingerprint_max_external_domains,
        fingerprint_favicon_timeout_ms=fingerprint_favicon_timeout_ms,
        fingerprint_favicon_max_bytes=fingerprint_favicon_max_bytes,
        fingerprint_asn_db_path=fingerprint_asn_db_path,
        fingerprint_jarm_timeout_ms=fingerprint_jarm_timeout_ms,
        fingerprint_disable_jarm=fingerprint_disable_jarm,
        fingerprint_disable_tls=fingerprint_disable_tls,
        fingerprint_user_agent=fingerprint_user_agent,
        worker_environment=worker_environment,
        log_level=log_level,
        log_http_details=log_http_details,
        max_loops=max_loops,
    )


def configure_logging(config):
    level = getattr(logging, config.log_level, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [worker] %(message)s",
    )


def build_convex_client(env):
    convex_url = env.get("CONVEX_URL")
    if not convex_url:
        return None
    admin_key = env.get("CONVEX_ADMIN_KEY")
    auth_token = env.get("CONVEX_AUTH_TOKEN")
    client = None
    if admin_key or auth_token:
        try:
            client = cast(Any, ConvexClient)(
                convex_url, admin_key=admin_key, auth_token=auth_token
            )
        except TypeError:
            client = None
    if client is None:
        client = ConvexClient(convex_url)
        if auth_token and hasattr(client, "set_auth"):
            client.set_auth(auth_token)
        elif auth_token:
            LOGGER.warning(
                "auth token provided but Convex SDK does not support set_auth"
            )
        if admin_key:
            LOGGER.warning(
                "admin key provided but Convex SDK did not accept it in constructor"
            )
    return client


def run_worker(config, job_source, sink, install_signal_handlers=True):
    shutting_down = {"value": False}

    def handle_signal(_signum, _frame):
        shutting_down["value"] = True
        LOGGER.info("shutdown requested")

    if install_signal_handlers:
        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

    LOGGER.info(
        "starting id=%s env=%s logLevel=%s batchSize=%s pollIntervalMs=%s "
        "fingerprintTimeoutMs=%s htmlMaxBytes=%s",
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
            LOGGER.warning("ASN lookup disabled: %s", asn_error)
        if config.fingerprint_disable_jarm:
            LOGGER.info("JARM disabled via FINGERPRINT_DISABLE_JARM=1")
    if config.fingerprint_disable_tls:
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
                scan_id = item.get("runId")
                domain_id = item.get("domainId")
                requested_url = item.get("url") or f"https://{item.get('host')}"
                fetched_at = now_ms()
                LOGGER.debug(
                    "processing host=%s domainId=%s runId=%s requestedUrl=%s",
                    item.get("host"),
                    domain_id,
                    scan_id,
                    requested_url,
                )

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

                body_bytes = http_result.get("body_bytes", b"") if http_result else b""
                encoding = http_result.get("encoding", "utf-8")
                sample_bytes = body_bytes[: config.fingerprint_sample_bytes]
                sample_truncated = len(body_bytes) > len(sample_bytes)
                outcome = build_run_outcome(
                    http_result,
                    sample_bytes,
                    sample_truncated,
                )
                status = outcome.get("kind")
                error_message = outcome.get("detail")
                LOGGER.debug(
                    "http result host=%s runId=%s status=%s httpStatus=%s durationMs=%s bodyBytes=%s",
                    item.get("host"),
                    scan_id,
                    status,
                    http_result.get("status"),
                    http_result.get("duration_ms"),
                    len(body_bytes),
                )
                if config.log_http_details:
                    LOGGER.debug(
                        "http details host=%s runId=%s finalUrl=%s redirects=%s headers=%s",
                        item.get("host"),
                        scan_id,
                        http_result.get("final_url"),
                        http_result.get("redirect_chain") or [],
                        http_result.get("headers") or [],
                    )

                http_payload = strip_nones(
                    {
                        "scanId": scan_id,
                        "domainId": domain_id,
                        "requestedUrl": http_result.get("requested_url"),
                        "finalUrl": http_result.get("final_url"),
                        "status": http_result.get("status"),
                        "redirectChain": http_result.get("redirect_chain") or [],
                        "headers": http_result.get("headers") or [],
                        "headersTruncated": http_result.get("headers_truncated"),
                        "contentType": http_result.get("content_type"),
                        "contentLength": http_result.get("content_length"),
                        "durationMs": http_result.get("duration_ms"),
                        "recordedAt": fetched_at,
                        "server": http_result.get("server"),
                        "poweredBy": http_result.get("powered_by"),
                        "setCookie": http_result.get("set_cookie") or [],
                        "errorType": http_result.get("error_type"),
                        "errorDetail": http_result.get("error_detail"),
                    }
                )
                call_mutation(sink, "fingerprints:upsertHttpFingerprint", http_payload)

                html_text = ""
                html_ok = False
                if body_bytes:
                    html_text = decode_bytes(body_bytes, encoding)
                    html_ok = looks_like_html(
                        http_result.get("content_type"), html_text
                    )

                html_payload = {
                    "scanId": scan_id,
                    "domainId": domain_id,
                    "recordedAt": fetched_at,
                }

                if html_ok:
                    sha256 = compute_sha256(body_bytes)
                    normalized = normalize_html_text(html_text)
                    normalized_sha256 = compute_sha256(normalized.encode("utf-8"))
                    fuzzy_hash, fuzzy_todo = compute_fuzzy_hash(html_text)
                    html_payload.update(
                        {
                            "sha256": sha256,
                            "normalizedSha256": normalized_sha256,
                            "fuzzyHash": fuzzy_hash,
                            "fuzzyHashTodo": fuzzy_todo,
                            "htmlLength": len(body_bytes),
                            "truncated": http_result.get("body_truncated"),
                            "storageTodo": True,
                        }
                    )
                else:
                    html_payload.update(
                        {"errorType": "no_html", "errorDetail": "no html body"}
                    )
                LOGGER.debug(
                    "html fingerprint host=%s runId=%s htmlOk=%s htmlLength=%s",
                    item.get("host"),
                    scan_id,
                    html_ok,
                    len(body_bytes),
                )

                call_mutation(
                    sink,
                    "fingerprints:upsertHtmlFingerprint",
                    strip_nones(html_payload),
                )

                assets_payload = {
                    "scanId": scan_id,
                    "domainId": domain_id,
                    "localAssets": [],
                    "localAssetCount": 0,
                    "externalDomains": [],
                    "externalDomainsFiltered": [],
                    "recordedAt": fetched_at,
                }

                analytics_payload = {
                    "scanId": scan_id,
                    "domainId": domain_id,
                    "googleAnalyticsIds": [],
                    "googleAnalytics4Ids": [],
                    "gtmIds": [],
                    "facebookPixelIds": [],
                    "recordedAt": fetched_at,
                }

                favicon_payload = None

                base_url = http_result.get("final_url") or requested_url
                if html_ok:
                    base_url = extract_base_url(base_url, html_text)
                    asset_urls = collect_asset_urls(html_text, base_url)
                    base_host = urlparse(base_url).hostname or ""
                    local_assets = []
                    external_domains = []

                    for asset_url in asset_urls:
                        parsed = urlparse(asset_url)
                        host = parsed.hostname or ""
                        if host_matches(host, base_host):
                            local_assets.append(asset_url)
                        else:
                            external_domains.append(normalize_host(host))

                    external_domains = list(
                        dict.fromkeys(filter(None, external_domains))
                    )
                    filtered_external = [
                        domain
                        for domain in external_domains
                        if not is_allowed_domain(domain, DEFAULT_EXTERNAL_ALLOWLIST)
                    ]

                    assets_payload["localAssetCount"] = len(local_assets)
                    assets_payload["externalDomains"] = external_domains[
                        : config.fingerprint_max_external_domains
                    ]
                    assets_payload["externalDomainsFiltered"] = filtered_external[
                        : config.fingerprint_max_external_domains
                    ]
                    assets_payload["localAssetsTruncated"] = (
                        len(local_assets) > config.fingerprint_max_assets
                    )

                    for asset_url in local_assets[: config.fingerprint_max_assets]:
                        asset_result = fetch_binary(
                            asset_url,
                            config.fingerprint_asset_timeout_ms,
                            config.fingerprint_asset_max_bytes,
                            config.fingerprint_user_agent,
                        )
                        if asset_result.get("ok"):
                            body = asset_result.get("body_bytes", b"")
                            assets_payload["localAssets"].append(
                                strip_nones(
                                    {
                                        "url": asset_url,
                                        "sha256": compute_sha256(body)
                                        if body
                                        else None,
                                        "contentType": asset_result.get("content_type"),
                                        "contentLength": asset_result.get(
                                            "content_length"
                                        ),
                                        "truncated": asset_result.get("body_truncated"),
                                    }
                                )
                            )
                        else:
                            assets_payload["localAssets"].append(
                                strip_nones(
                                    {
                                        "url": asset_url,
                                        "errorType": asset_result.get("error_type"),
                                    }
                                )
                            )

                    ga_ids, ga4_ids, gtm_ids, fb_ids = extract_trackers(html_text)
                    analytics_payload.update(
                        {
                            "googleAnalyticsIds": ga_ids,
                            "googleAnalytics4Ids": ga4_ids,
                            "gtmIds": gtm_ids,
                            "facebookPixelIds": fb_ids,
                        }
                    )

                    favicon_url = find_favicon_url(base_url, html_text)
                    LOGGER.debug(
                        "asset analysis host=%s runId=%s localAssets=%s externalDomains=%s filteredExternalDomains=%s",
                        item.get("host"),
                        scan_id,
                        len(local_assets),
                        len(external_domains),
                        len(filtered_external),
                    )
                else:
                    assets_payload.update(
                        {"errorType": "no_html", "errorDetail": "no html body"}
                    )
                    analytics_payload.update(
                        {"errorType": "no_html", "errorDetail": "no html body"}
                    )
                    favicon_url = (
                        urlparse(base_url)._replace(path="/favicon.ico").geturl()
                    )
                    LOGGER.debug(
                        "asset analysis skipped host=%s runId=%s reason=no_html",
                        item.get("host"),
                        scan_id,
                    )

                call_mutation(
                    sink, "fingerprints:upsertAssetsFingerprint", assets_payload
                )
                call_mutation(
                    sink, "fingerprints:upsertAnalyticsFingerprint", analytics_payload
                )

                favicon_result = fetch_binary(
                    favicon_url,
                    config.fingerprint_favicon_timeout_ms,
                    config.fingerprint_favicon_max_bytes,
                    config.fingerprint_user_agent,
                )
                if favicon_result.get("ok"):
                    icon_bytes = favicon_result.get("body_bytes", b"")
                    mmh3_hash = None
                    if icon_bytes:
                        mmh3_hash = mmh3.hash(
                            base64.b64encode(icon_bytes), signed=False
                        )
                    favicon_payload = strip_nones(
                        {
                            "scanId": scan_id,
                            "domainId": domain_id,
                            "url": favicon_result.get("final_url") or favicon_url,
                            "status": favicon_result.get("status"),
                            "contentType": favicon_result.get("content_type"),
                            "contentLength": favicon_result.get("content_length"),
                            "sha256": compute_sha256(icon_bytes)
                            if icon_bytes
                            else None,
                            "mmh3": mmh3_hash,
                            "storageTodo": True,
                            "recordedAt": fetched_at,
                        }
                    )
                    LOGGER.debug(
                        "favicon fingerprint host=%s runId=%s status=%s contentLength=%s",
                        item.get("host"),
                        scan_id,
                        favicon_result.get("status"),
                        favicon_result.get("content_length"),
                    )
                else:
                    favicon_payload = strip_nones(
                        {
                            "scanId": scan_id,
                            "domainId": domain_id,
                            "url": favicon_url,
                            "errorType": favicon_result.get("error_type"),
                            "errorDetail": favicon_result.get("error_detail"),
                            "recordedAt": fetched_at,
                        }
                    )
                    LOGGER.debug(
                        "favicon fetch failed host=%s runId=%s errorType=%s",
                        item.get("host"),
                        scan_id,
                        favicon_result.get("error_type"),
                    )

                call_mutation(
                    sink, "fingerprints:upsertFaviconFingerprint", favicon_payload
                )

                parsed_host = urlparse(base_url).hostname or ""

                if config.fingerprint_disable_tls:
                    tls_payload = strip_nones(
                        {
                            "scanId": scan_id,
                            "domainId": domain_id,
                            "hostname": parsed_host or None,
                            "ipAddresses": [],
                            "jarmTodo": True,
                            "asnTodo": True,
                            "errorType": "disabled",
                            "errorDetail": "tls_disabled",
                            "recordedAt": fetched_at,
                        }
                    )
                    LOGGER.debug(
                        "tls fingerprint skipped host=%s runId=%s reason=tls_disabled",
                        item.get("host"),
                        scan_id,
                    )
                else:
                    ip_addresses = resolve_ips(parsed_host)
                    tls_info = collect_tls_info(
                        parsed_host, config.fingerprint_timeout_ms
                    )
                    asn_value = lookup_asn(asn_db, ip_addresses)
                    asn_todo = asn_value is None
                    asn_error_detail = asn_error if asn_todo else None
                    if config.fingerprint_disable_jarm:
                        jarm_value = None
                        jarm_error = "jarm_disabled"
                    else:
                        jarm_value, jarm_error = compute_jarm(
                            parsed_host, 443, config.fingerprint_jarm_timeout_ms
                        )
                    jarm_todo = jarm_value is None
                    tls_payload = strip_nones(
                        {
                            "scanId": scan_id,
                            "domainId": domain_id,
                            "hostname": parsed_host or None,
                            "ipAddresses": ip_addresses,
                            "certSha1": tls_info.get("cert_sha1"),
                            "certSha256": tls_info.get("cert_sha256"),
                            "certSubject": tls_info.get("cert_subject"),
                            "certIssuer": tls_info.get("cert_issuer"),
                            "certNotBefore": tls_info.get("cert_not_before"),
                            "certNotAfter": tls_info.get("cert_not_after"),
                            "jarm": jarm_value,
                            "jarmTodo": jarm_todo,
                            "asn": asn_value,
                            "asnTodo": asn_todo,
                            "errorType": tls_info.get("error_type"),
                            "errorDetail": join_errors(
                                tls_info.get("error_detail"),
                                asn_error_detail,
                                jarm_error if jarm_todo else None,
                            ),
                            "recordedAt": fetched_at,
                        }
                    )
                    LOGGER.debug(
                        "tls fingerprint host=%s runId=%s ipCount=%s jarmTodo=%s asnTodo=%s",
                        parsed_host,
                        scan_id,
                        len(ip_addresses),
                        jarm_todo,
                        asn_todo,
                    )

                call_mutation(sink, "fingerprints:upsertTlsFingerprint", tls_payload)

                try:
                    sink.mutation(
                        "fingerprints:reportResult",
                        strip_nones(
                            {
                                "domainId": domain_id,
                                "runId": scan_id,
                                "workerId": config.worker_id,
                                "status": status,
                                "outcome": outcome,
                                "error": error_message,
                            }
                        ),
                    )
                    LOGGER.info(
                        "processed host=%s runId=%s status=%s",
                        item.get("host"),
                        scan_id,
                        status,
                    )
                except Exception as error:
                    LOGGER.exception(
                        "failed host=%s runId=%s error=%s",
                        item.get("host"),
                        scan_id,
                        error,
                    )

            if config.max_loops and loop_count >= config.max_loops:
                break
        except Exception as error:
            LOGGER.exception("loop error=%s", error)
            if config.max_loops and loop_count >= config.max_loops:
                break
            time.sleep(config.poll_interval_ms / 1000)

    sink.close()
    LOGGER.info("stopped")


def main():
    env = os.environ
    config = build_config(env)
    configure_logging(config)

    job_source_kind = (env.get("JOB_SOURCE") or "convex").lower()
    result_sink_kind = env.get("RESULT_SINK")
    job_file = env.get("JOB_FILE") or "tests/fixtures/jobs.json"
    results_file = env.get("RESULTS_FILE") or "tests/fixtures/results.json"

    needs_convex = job_source_kind == "convex"
    if result_sink_kind is None:
        result_sink_kind = "convex" if needs_convex else "file"
    result_sink_kind = result_sink_kind.lower()
    needs_convex = needs_convex or result_sink_kind == "convex"

    client = build_convex_client(env) if needs_convex else None
    if needs_convex and client is None:
        LOGGER.error("Missing CONVEX_URL; set it to your Convex deployment URL.")
        sys.exit(1)

    if job_source_kind == "convex":
        job_source = ConvexJobSource(client)
    elif job_source_kind == "file":
        job_source = FileJobSource(job_file)
    else:
        LOGGER.error("Unknown JOB_SOURCE=%s", job_source_kind)
        sys.exit(1)

    if result_sink_kind == "convex":
        sink = ConvexResultSink(client)
    elif result_sink_kind == "file":
        sink = FileResultSink(results_file)
    elif result_sink_kind == "memory":
        sink = MemoryResultSink()
    else:
        LOGGER.error("Unknown RESULT_SINK=%s", result_sink_kind)
        sys.exit(1)

    run_worker(config, job_source, sink, install_signal_handlers=True)


if __name__ == "__main__":
    main()
