import uuid
from dataclasses import dataclass
from os import environ
from typing import Mapping

VALID_LOG_LEVELS = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}


def parse_number(
    raw_value: str | None,
    fallback: int | None,
    minimum: int | None = None,
) -> int | None:
    if raw_value is None or raw_value == "":
        return fallback
    try:
        value = int(raw_value)
    except ValueError:
        return fallback
    if minimum is not None and value < minimum:
        return minimum
    return value


def parse_bool(raw_value: str | None, fallback: bool) -> bool:
    if raw_value is None or raw_value == "":
        return fallback
    normalized = raw_value.strip().lower()
    return normalized in {"1", "true", "yes", "on"}


@dataclass(slots=True)
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


def build_config(env: Mapping[str, str] | None = None) -> WorkerConfig:
    source = environ if env is None else env
    worker_environment_raw = (source.get("WORKER_ENV") or "production").strip().lower()
    if worker_environment_raw in {"dev", "development"}:
        worker_environment = "development"
    else:
        worker_environment = "production"

    default_log_level = "DEBUG" if worker_environment == "development" else "INFO"
    log_level = (source.get("WORKER_LOG_LEVEL") or default_log_level).upper()
    if log_level not in VALID_LOG_LEVELS:
        log_level = default_log_level

    log_http_details = parse_bool(
        source.get("WORKER_LOG_HTTP_DETAILS"),
        worker_environment == "development",
    )
    worker_id = source.get("WORKER_ID") or f"worker-{uuid.uuid4()}"
    default_poll_interval_ms = (
        3600000 if worker_environment == "development" else 300000
    )
    fingerprint_timeout_ms = parse_number(
        source.get("FINGERPRINT_TIMEOUT_MS"),
        8000,
        1000,
    )
    assert fingerprint_timeout_ms is not None
    max_loops = parse_number(source.get("WORKER_MAX_LOOPS"), None, 1)
    if source.get("WORKER_ONCE") == "1":
        max_loops = 1

    return WorkerConfig(
        worker_id=worker_id,
        poll_interval_ms=parse_number(
            source.get("WORKER_POLL_INTERVAL_MS"),
            default_poll_interval_ms,
            1000,
        )
        or default_poll_interval_ms,
        batch_size=parse_number(source.get("WORKER_BATCH_SIZE"), 1, 1) or 1,
        lease_duration_ms=parse_number(
            source.get("WORKER_LEASE_DURATION_MS"),
            60000,
            1000,
        )
        or 60000,
        fingerprint_timeout_ms=fingerprint_timeout_ms,
        fingerprint_html_max_bytes=parse_number(
            source.get("FINGERPRINT_HTML_MAX_BYTES"),
            512000,
            4096,
        )
        or 512000,
        fingerprint_sample_bytes=parse_number(
            source.get("FINGERPRINT_SAMPLE_BYTES"),
            2048,
            256,
        )
        or 2048,
        fingerprint_max_headers=parse_number(
            source.get("FINGERPRINT_MAX_HEADERS"),
            50,
            10,
        )
        or 50,
        fingerprint_header_value_max=parse_number(
            source.get("FINGERPRINT_HEADER_VALUE_MAX"),
            512,
            64,
        )
        or 512,
        fingerprint_max_set_cookie=parse_number(
            source.get("FINGERPRINT_MAX_SET_COOKIE"),
            5,
            1,
        )
        or 5,
        fingerprint_set_cookie_max=parse_number(
            source.get("FINGERPRINT_SET_COOKIE_MAX"),
            512,
            64,
        )
        or 512,
        fingerprint_asset_timeout_ms=parse_number(
            source.get("FINGERPRINT_ASSET_TIMEOUT_MS"),
            5000,
            1000,
        )
        or 5000,
        fingerprint_asset_max_bytes=parse_number(
            source.get("FINGERPRINT_ASSET_MAX_BYTES"),
            256000,
            4096,
        )
        or 256000,
        fingerprint_max_assets=parse_number(
            source.get("FINGERPRINT_MAX_ASSETS"),
            10,
            1,
        )
        or 10,
        fingerprint_max_external_domains=parse_number(
            source.get("FINGERPRINT_MAX_EXTERNAL_DOMAINS"),
            50,
            10,
        )
        or 50,
        fingerprint_favicon_timeout_ms=parse_number(
            source.get("FINGERPRINT_FAVICON_TIMEOUT_MS"),
            5000,
            1000,
        )
        or 5000,
        fingerprint_favicon_max_bytes=parse_number(
            source.get("FINGERPRINT_FAVICON_MAX_BYTES"),
            100000,
            1024,
        )
        or 100000,
        fingerprint_asn_db_path=source.get("FINGERPRINT_ASN_DB_PATH"),
        fingerprint_jarm_timeout_ms=parse_number(
            source.get("FINGERPRINT_JARM_TIMEOUT_MS"),
            fingerprint_timeout_ms,
            1000,
        )
        or fingerprint_timeout_ms,
        fingerprint_disable_jarm=source.get("FINGERPRINT_DISABLE_JARM") == "1",
        fingerprint_disable_tls=source.get("FINGERPRINT_DISABLE_TLS") == "1",
        fingerprint_user_agent=source.get("FINGERPRINT_USER_AGENT")
        or "TracehammerFingerprint/0.2",
        worker_environment=worker_environment,
        log_level=log_level,
        log_http_details=log_http_details,
        max_loops=max_loops,
    )
