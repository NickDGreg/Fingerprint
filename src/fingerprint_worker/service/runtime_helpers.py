import time

from fingerprint_worker.service.fingerprint_core import decode_bytes, strip_nones
from fingerprint_worker.types.runtime import (
    RUN_OUTCOME_HTTP_CONTENT,
    RUN_OUTCOME_HTTP_ERROR,
    RUN_OUTCOME_UNREACHABLE,
    RUN_STATUS_FAILED,
    RUN_STATUS_SUCCESS,
    RUN_STATUS_UNREACHABLE,
)


def now_ms() -> int:
    return int(time.time() * 1000)


def clamp_text(value: object, max_len: int) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text[:max_len]


def map_outcome_kind_to_run_status(kind: str) -> str:
    if kind in {RUN_OUTCOME_HTTP_CONTENT, RUN_OUTCOME_HTTP_ERROR}:
        return RUN_STATUS_SUCCESS
    if kind == RUN_OUTCOME_UNREACHABLE:
        return RUN_STATUS_UNREACHABLE
    return RUN_STATUS_FAILED


def build_run_outcome(
    http_result: dict[str, object],
    sample_bytes: bytes,
    sample_truncated: bool,
) -> dict[str, object]:
    if http_result.get("ok"):
        status_raw = http_result.get("status")
        status = int(status_raw) if isinstance(status_raw, int | str) else 0
        kind = RUN_OUTCOME_HTTP_CONTENT if status < 400 else RUN_OUTCOME_HTTP_ERROR
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
                    sample_bytes,
                    str(http_result.get("encoding", "utf-8")),
                ),
                "sampleTruncated": sample_truncated,
                "durationMs": http_result.get("duration_ms"),
            }
        )
    return strip_nones(
        {
            "kind": RUN_OUTCOME_UNREACHABLE,
            "detail": http_result.get("error_detail"),
            "errorType": http_result.get("error_type"),
            "durationMs": http_result.get("duration_ms"),
        }
    )
