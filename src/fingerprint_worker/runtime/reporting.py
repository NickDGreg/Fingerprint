from typing import Any

from fingerprint_worker.providers.logging_provider import LOGGER
from fingerprint_worker.service.fingerprint_core import strip_nones
from fingerprint_worker.service.runtime_helpers import clamp_text
from fingerprint_worker.types.runtime import (
    ISSUE_DETAIL_MAX_LEN,
    ISSUE_MESSAGE_MAX_LEN,
    RUN_ERROR_MAX_LEN,
    RUN_ISSUE_CODE_MUTATION_EXCEPTION,
    RUN_ISSUE_CODE_REPORT_RESULT_EXCEPTION,
    RUN_ISSUE_CODE_REPORT_RESULT_REJECTED,
    RUN_ISSUE_STAGE_REPORT_RESULT,
)


def build_issue_dedupe_key(run_id: str | None, stage: str, code: str) -> str:
    return f"fp-issue:{run_id}:{stage}:{code}"


def record_run_issue(
    sink: Any,
    run_id: str | None,
    record_id: str | None,
    worker_id: str,
    stage: str,
    code: str,
    message: str,
    detail: str | None = None,
) -> bool:
    payload = strip_nones(
        {
            "runId": run_id,
            "networkArtifactId": record_id,
            "workerId": worker_id,
            "stage": stage,
            "code": code,
            "message": clamp_text(message, ISSUE_MESSAGE_MAX_LEN)
            or "fingerprint issue",
            "detail": clamp_text(detail, ISSUE_DETAIL_MAX_LEN),
            "dedupeKey": build_issue_dedupe_key(run_id, stage, code),
        }
    )
    try:
        sink.mutation("fingerprints:recordRunIssue", payload)
        LOGGER.debug(
            "mutation succeeded name=fingerprints:recordRunIssue stage=%s code=%s",
            stage,
            code,
        )
        return True
    except Exception as error:
        LOGGER.exception(
            "mutation failed name=fingerprints:recordRunIssue stage=%s code=%s error=%s",
            stage,
            code,
            error,
        )
        return False


def call_stage_mutation(
    sink: Any,
    mutation_name: str,
    payload: dict[str, object],
    run_id: str | None,
    record_id: str | None,
    worker_id: str,
    stage: str,
    stage_errors: list[str],
) -> object | None:
    try:
        result = sink.mutation(mutation_name, payload)
        LOGGER.debug("mutation succeeded name=%s", mutation_name)
        return result
    except Exception as error:
        error_text = clamp_text(error, ISSUE_DETAIL_MAX_LEN) or "unknown_error"
        LOGGER.exception("mutation failed name=%s error=%s", mutation_name, error)
        stage_errors.append(f"{stage}:{error_text}")
        record_run_issue(
            sink,
            run_id,
            record_id,
            worker_id,
            stage,
            RUN_ISSUE_CODE_MUTATION_EXCEPTION,
            f"{mutation_name} failed",
            error_text,
        )
        return None


def finalize_run(
    sink: Any,
    host: str | None,
    run_id: str | None,
    record_id: str | None,
    worker_id: str,
    status: str,
    outcome: dict[str, object],
    error_message: str | None,
) -> bool:
    payload = strip_nones(
        {
            "networkArtifactId": record_id,
            "runId": run_id,
            "workerId": worker_id,
            "status": status,
            "outcome": outcome,
            "error": clamp_text(error_message, RUN_ERROR_MAX_LEN),
        }
    )
    try:
        result = sink.mutation("fingerprints:reportResult", payload)
        if isinstance(result, dict) and result.get("ok") is False:
            reason = str(result.get("reason") or "unknown_reason")
            LOGGER.error(
                "reportResult rejected host=%s runId=%s reason=%s",
                host,
                run_id,
                reason,
            )
            record_run_issue(
                sink,
                run_id,
                record_id,
                worker_id,
                RUN_ISSUE_STAGE_REPORT_RESULT,
                RUN_ISSUE_CODE_REPORT_RESULT_REJECTED,
                "reportResult returned ok=false",
                f"reason={reason}",
            )
            return False
        LOGGER.info("processed host=%s runId=%s status=%s", host, run_id, status)
        return True
    except Exception as error:
        error_text = clamp_text(error, ISSUE_DETAIL_MAX_LEN) or "unknown_error"
        LOGGER.exception(
            "reportResult failed host=%s runId=%s error=%s",
            host,
            run_id,
            error,
        )
        record_run_issue(
            sink,
            run_id,
            record_id,
            worker_id,
            RUN_ISSUE_STAGE_REPORT_RESULT,
            RUN_ISSUE_CODE_REPORT_RESULT_EXCEPTION,
            "reportResult mutation failed",
            error_text,
        )
        return False
