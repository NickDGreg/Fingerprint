import hashlib
import importlib
import os
import socket
import ssl
from typing import Any

_PYASN_IMPORT_ERROR: str | None = None
try:
    pyasn: Any = importlib.import_module("pyasn")
except Exception as error:
    pyasn = None
    _PYASN_IMPORT_ERROR = f"{type(error).__name__}: {error}"

_JARM_IMPORT_ERROR: str | None = None
_JARM_SCANNER_PATH: str | None = None
try:
    jarm_scanner_module: Any = importlib.import_module("jarm.scanner.scanner")
    jarm_scanner: Any = getattr(jarm_scanner_module, "Scanner", None)
    _JARM_SCANNER_PATH = getattr(jarm_scanner_module, "__file__", None)
except Exception as error:
    jarm_scanner = None
    _JARM_IMPORT_ERROR = f"{type(error).__name__}: {error}"


def resolve_ips(hostname):
    try:
        infos = socket.getaddrinfo(hostname, None)
    except Exception:
        return []
    addresses = []
    for entry in infos:
        address = entry[4][0]
        if address not in addresses:
            addresses.append(address)
    return addresses


def load_asn_db(db_path):
    if not db_path:
        return None, "asn_db_path_missing"
    if not pyasn:
        if _PYASN_IMPORT_ERROR:
            return None, f"asn_module_unavailable: {_PYASN_IMPORT_ERROR}"
        return None, "asn_module_unavailable"
    if not os.path.isfile(db_path):
        return None, f"asn_db_not_found: {db_path}"
    try:
        return pyasn.pyasn(db_path), None
    except Exception as error:
        return None, f"asn_db_error: {type(error).__name__}: {error}"


def lookup_asn(db, ip_addresses):
    if not db or not ip_addresses:
        return None
    asns = []
    for ip in ip_addresses:
        try:
            asn, _ = db.lookup(ip)
        except Exception:
            asn = None
        if asn:
            label = f"AS{asn}"
            if label not in asns:
                asns.append(label)
    return ", ".join(asns) if asns else None


def jarm_runtime_error():
    if not jarm_scanner:
        if _JARM_IMPORT_ERROR:
            return f"jarm_module_unavailable: {_JARM_IMPORT_ERROR}"
        return "jarm_module_unavailable"
    if callable(getattr(jarm_scanner, "scan", None)):
        return None
    return f"jarm_api_unavailable: scanner={_JARM_SCANNER_PATH or 'unknown'}"


def compute_jarm(hostname, port, timeout_ms):
    if not hostname:
        return None, "jarm_no_host"
    runtime_error = jarm_runtime_error()
    if runtime_error:
        return None, runtime_error
    scan = getattr(jarm_scanner, "scan", None)
    if not callable(scan):
        return None, "jarm_api_unavailable: scanner=unknown"

    timeout_seconds = max(1, int(timeout_ms / 1000))
    try:
        result = scan(
            dest_host=hostname,
            dest_port=port,
            timeout=timeout_seconds,
            suppress=True,
        )
    except Exception as error:
        return None, f"jarm_scan_error: {type(error).__name__}: {error}"

    if isinstance(result, str) and result:
        return result, None
    if isinstance(result, (tuple, list)) and result:
        first = result[0]
        if isinstance(first, str) and first:
            return first, None
    if isinstance(result, dict):
        for key in ("jarm", "hash", "fingerprint"):
            value = result.get(key)
            if isinstance(value, str) and value:
                return value, None
    return None, "jarm_scan_empty"


def format_x509_name(name):
    if not name:
        return None
    parts = []
    for entry in name:
        for key, value in entry:
            parts.append(f"{key}={value}")
    return ", ".join(parts) if parts else None


def collect_tls_info(hostname, timeout_ms):
    if not hostname:
        return {"error_type": "no_host"}
    try:
        context = ssl.create_default_context()
        with socket.create_connection(
            (hostname, 443), timeout=timeout_ms / 1000
        ) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert_der = tls_sock.getpeercert(binary_form=True)
                cert = tls_sock.getpeercert() or {}
                sha1 = hashlib.sha1(cert_der).hexdigest() if cert_der else None
                sha256 = hashlib.sha256(cert_der).hexdigest() if cert_der else None
                subject = format_x509_name(cert.get("subject"))
                issuer = format_x509_name(cert.get("issuer"))
                return {
                    "cert_sha1": sha1,
                    "cert_sha256": sha256,
                    "cert_subject": subject,
                    "cert_issuer": issuer,
                    "cert_not_before": cert.get("notBefore"),
                    "cert_not_after": cert.get("notAfter"),
                }
    except Exception as error:
        return {"error_type": "tls_error", "error_detail": str(error)[:200]}
