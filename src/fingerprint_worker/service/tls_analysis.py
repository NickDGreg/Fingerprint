from urllib.parse import urlparse

from fingerprint_worker.config.env import WorkerConfig
from fingerprint_worker.providers.tls_provider import (
    collect_tls_info,
    compute_jarm,
    lookup_asn,
    resolve_ips,
)
from fingerprint_worker.service.fingerprint_core import join_errors, strip_nones


def build_tls_payload(
    config: WorkerConfig,
    scan_id: str | None,
    record_id: str | None,
    fetched_at: int,
    base_url: str,
    asn_db: object | None,
    asn_error: str | None,
) -> dict[str, object]:
    parsed_host = urlparse(base_url).hostname or ""
    if config.fingerprint_disable_tls:
        return strip_nones(
            {
                "scanId": scan_id,
                "networkArtifactId": record_id,
                "hostname": parsed_host or None,
                "ipAddresses": [],
                "jarmTodo": True,
                "asnTodo": True,
                "errorType": "disabled",
                "errorDetail": "tls_disabled",
                "recordedAt": fetched_at,
            }
        )

    ip_addresses = resolve_ips(parsed_host)
    tls_info = collect_tls_info(parsed_host, config.fingerprint_timeout_ms)
    tls_error_detail = tls_info.get("error_detail")
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

    return strip_nones(
        {
            "scanId": scan_id,
            "networkArtifactId": record_id,
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
                tls_error_detail if isinstance(tls_error_detail, str) else None,
                asn_error_detail,
                jarm_error if jarm_todo else None,
            ),
            "recordedAt": fetched_at,
        }
    )
