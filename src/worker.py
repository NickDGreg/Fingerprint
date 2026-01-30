import base64
import hashlib
import os
import re
import signal
import socket
import ssl
import sys
import time
import uuid
from urllib.parse import urljoin, urlparse

import mmh3
import requests
from bs4 import BeautifulSoup
from convex import ConvexClient

try:
    import pyasn
except Exception:
    pyasn = None

try:
    import jarm
except Exception:
    jarm = None

try:
    import ssdeep
except Exception:
    ssdeep = None

DEFAULT_EXTERNAL_ALLOWLIST = {
    "cloudflare.com",
    "cloudflareinsights.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "gstatic.com",
    "google-analytics.com",
    "google.com",
    "googletagmanager.com",
    "jsdelivr.net",
    "unpkg.com",
}

UA_REGEX = re.compile(r"\bUA-\d{4,10}-\d+\b", re.IGNORECASE)
GA4_REGEX = re.compile(r"\bG-[A-Z0-9]{4,12}\b")
GTM_REGEX = re.compile(r"\bGTM-[A-Z0-9]{4,10}\b")
FB_PIXEL_REGEX = re.compile(
    r"fbq\(['\"]init['\"],\s*['\"](\d{5,})['\"]\)|facebook\.com/tr\?id=(\d{5,})",
    re.IGNORECASE,
)


def now_ms():
    return int(time.time() * 1000)


def parse_number(raw_value, fallback, minimum=None):
    if not raw_value:
        return fallback
    try:
        value = int(raw_value)
    except ValueError:
        return fallback
    if minimum is not None and value < minimum:
        return minimum
    return value


def strip_nones(payload):
    return {key: value for key, value in payload.items() if value is not None}


def join_errors(*messages):
    filtered = [message for message in messages if message]
    return "; ".join(filtered) if filtered else None


def truncate_value(value, max_len):
    if value is None:
        return None
    if len(value) <= max_len:
        return value
    return value[:max_len]


def read_response_bytes(response, max_bytes):
    data = bytearray()
    truncated = False
    for chunk in response.iter_content(chunk_size=16384):
        if not chunk:
            continue
        remaining = max_bytes - len(data)
        if remaining <= 0:
            truncated = True
            break
        if len(chunk) > remaining:
            data.extend(chunk[:remaining])
            truncated = True
            break
        data.extend(chunk)
    return bytes(data), truncated


def decode_bytes(sample_bytes, encoding):
    try:
        return sample_bytes.decode(encoding, errors="replace")
    except Exception:
        return sample_bytes.decode("utf-8", errors="replace")


def normalize_html_text(text):
    collapsed = re.sub(r"\s+", " ", text)
    return collapsed.strip()


def compute_sha256(data_bytes):
    digest = hashlib.sha256()
    digest.update(data_bytes)
    return digest.hexdigest()


def compute_fuzzy_hash(text):
    if ssdeep is None:
        return None, True
    try:
        return ssdeep.hash(text), False
    except Exception:
        return None, True


def normalize_host(hostname):
    if not hostname:
        return ""
    host = hostname.lower().strip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


def host_matches(left, right):
    return normalize_host(left) == normalize_host(right)


def build_headers(headers, max_headers, max_value_len):
    entries = []
    for key, value in headers.items():
        entries.append(
            {
                "key": key,
                "value": truncate_value(str(value), max_value_len),
            }
        )
        if len(entries) >= max_headers:
            break
    truncated = len(headers) > len(entries)
    return entries, truncated


def build_set_cookie_list(response, max_entries, max_value_len):
    values = []
    try:
        raw_headers = response.raw.headers
        if hasattr(raw_headers, "get_all"):
            values = raw_headers.get_all("Set-Cookie") or []
    except Exception:
        values = []
    if not values:
        header_value = response.headers.get("Set-Cookie")
        if header_value:
            values = [header_value]
    trimmed = [truncate_value(value, max_value_len) for value in values[:max_entries]]
    return [value for value in trimmed if value]


def classify_request_error(error):
    if isinstance(error, requests.exceptions.Timeout):
        return "timeout"
    if isinstance(error, requests.exceptions.SSLError):
        return "tls"
    if isinstance(error, requests.exceptions.ConnectionError):
        return "connection_error"
    return "request_failed"


def fetch_http(
    url,
    timeout_ms,
    max_html_bytes,
    user_agent,
    max_headers,
    max_header_value_len,
    max_set_cookie,
    max_set_cookie_len,
):
    start = time.monotonic()
    try:
        with requests.get(
            url,
            headers={"User-Agent": user_agent},
            timeout=timeout_ms / 1000,
            allow_redirects=True,
            stream=True,
        ) as response:
            response.raw.decode_content = True
            body_bytes, body_truncated = read_response_bytes(response, max_html_bytes)
            duration_ms = int((time.monotonic() - start) * 1000)
            content_length = response.headers.get("Content-Length")
            try:
                content_length = (
                    int(content_length) if content_length is not None else None
                )
            except ValueError:
                content_length = None
            headers, headers_truncated = build_headers(
                response.headers, max_headers, max_header_value_len
            )
            set_cookie = build_set_cookie_list(
                response, max_set_cookie, max_set_cookie_len
            )
            redirect_chain = [
                {"url": prior.url, "status": prior.status_code}
                for prior in response.history
            ]
            return {
                "ok": True,
                "status": response.status_code,
                "requested_url": url,
                "final_url": response.url,
                "headers": headers,
                "headers_truncated": headers_truncated,
                "redirect_chain": redirect_chain,
                "content_type": response.headers.get("Content-Type"),
                "content_length": content_length,
                "server": response.headers.get("Server"),
                "powered_by": response.headers.get("X-Powered-By"),
                "set_cookie": set_cookie,
                "duration_ms": duration_ms,
                "body_bytes": body_bytes,
                "body_truncated": body_truncated,
                "encoding": response.encoding or "utf-8",
            }
    except requests.RequestException as error:
        return {
            "ok": False,
            "requested_url": url,
            "error_type": classify_request_error(error),
            "error_detail": str(error)[:200],
            "duration_ms": int((time.monotonic() - start) * 1000),
        }


def looks_like_html(content_type, body_text):
    if content_type and "html" in content_type.lower():
        return True
    sample = body_text.lower()
    return "<html" in sample or "<head" in sample


def extract_base_url(final_url, html_text):
    try:
        soup = BeautifulSoup(html_text, "html.parser")
        base = soup.find("base", href=True)
        if base and base.get("href"):
            return urljoin(final_url, base["href"])
    except Exception:
        return final_url
    return final_url


def find_favicon_url(final_url, html_text):
    try:
        soup = BeautifulSoup(html_text, "html.parser")
        links = soup.find_all("link", href=True)
        for link in links:
            rel = " ".join(link.get("rel", [])).lower()
            if "icon" in rel:
                return urljoin(final_url, link["href"])
    except Exception:
        return urljoin(final_url, "/favicon.ico")
    return urljoin(final_url, "/favicon.ico")


def is_allowed_domain(domain, allowlist):
    for allowed in allowlist:
        if domain == allowed or domain.endswith(f".{allowed}"):
            return True
    return False


def collect_asset_urls(html_text, base_url):
    soup = BeautifulSoup(html_text, "html.parser")
    urls = []
    for tag in soup.find_all("script", src=True):
        urls.append(tag["src"])
    for tag in soup.find_all("link", href=True):
        rel = " ".join(tag.get("rel", [])).lower()
        if "stylesheet" in rel:
            urls.append(tag["href"])
    for tag in soup.find_all("img", src=True):
        urls.append(tag["src"])
    for tag in soup.find_all("iframe", src=True):
        urls.append(tag["src"])

    normalized = []
    for raw in urls:
        if not raw or raw.startswith("data:") or raw.startswith("javascript:"):
            continue
        absolute = urljoin(base_url, raw)
        parsed = urlparse(absolute)
        if parsed.scheme not in {"http", "https"}:
            continue
        normalized.append(absolute)
    return list(dict.fromkeys(normalized))


def fetch_binary(url, timeout_ms, max_bytes, user_agent):
    start = time.monotonic()
    try:
        with requests.get(
            url,
            headers={"User-Agent": user_agent},
            timeout=timeout_ms / 1000,
            allow_redirects=True,
            stream=True,
        ) as response:
            response.raw.decode_content = True
            body_bytes, body_truncated = read_response_bytes(response, max_bytes)
            duration_ms = int((time.monotonic() - start) * 1000)
            content_length = response.headers.get("Content-Length")
            try:
                content_length = (
                    int(content_length) if content_length is not None else None
                )
            except ValueError:
                content_length = None
            return {
                "ok": True,
                "status": response.status_code,
                "final_url": response.url,
                "content_type": response.headers.get("Content-Type"),
                "content_length": content_length,
                "body_bytes": body_bytes,
                "body_truncated": body_truncated,
                "duration_ms": duration_ms,
            }
    except requests.RequestException as error:
        return {
            "ok": False,
            "error_type": classify_request_error(error),
            "error_detail": str(error)[:200],
            "duration_ms": int((time.monotonic() - start) * 1000),
        }


def extract_trackers(html_text):
    ga_ids = sorted(set(UA_REGEX.findall(html_text)))
    ga4_ids = sorted(set(GA4_REGEX.findall(html_text)))
    gtm_ids = sorted(set(GTM_REGEX.findall(html_text)))
    fb_ids = []
    for match in FB_PIXEL_REGEX.findall(html_text):
        for group in match:
            if group:
                fb_ids.append(group)
    fb_ids = sorted(set(fb_ids))
    return ga_ids, ga4_ids, gtm_ids, fb_ids


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
    if not db_path or not pyasn:
        return None, "asn_db_unavailable"
    try:
        return pyasn.pyasn(db_path), None
    except Exception as error:
        return None, f"asn_db_error: {error}"


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


def compute_jarm(hostname, port, timeout_ms):
    if not hostname:
        return None, "jarm_no_host"
    if not jarm:
        return None, "jarm_unavailable"

    candidates = [
        "get_jarm_hash",
        "jarm_hash",
        "hash",
        "fingerprint",
    ]
    timeout_seconds = max(1, int(timeout_ms / 1000))
    last_error = None

    for name in candidates:
        func = getattr(jarm, name, None)
        if not callable(func):
            continue
        for args in (
            (hostname, port, timeout_seconds),
            (hostname, port),
            (hostname, f"{hostname}:{port}"),
            (f"{hostname}:{port}",),
            (hostname,),
        ):
            try:
                result = func(*args)
            except Exception as error:
                last_error = str(error)
                continue

            if isinstance(result, str) and result:
                return result, None
            if isinstance(result, (list, tuple)) and result:
                first = result[0]
                if isinstance(first, str) and first:
                    return first, None
            if isinstance(result, dict):
                for key in ("jarm", "hash", "fingerprint"):
                    value = result.get(key)
                    if isinstance(value, str) and value:
                        return value, None

    return None, last_error or "jarm_failed"


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
        with socket.create_connection((hostname, 443), timeout=timeout_ms / 1000) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert_der = tls_sock.getpeercert(binary_form=True)
                cert = tls_sock.getpeercert()
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
                "sample": decode_bytes(sample_bytes, http_result.get("encoding", "utf-8")),
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


def call_mutation(client, name, payload):
    try:
        return client.mutation(name, payload)
    except Exception as error:
        print(f"[worker] mutation failed name={name} error={error}")
        return None


def main():
    convex_url = os.environ.get("CONVEX_URL")
    if not convex_url:
        print("Missing CONVEX_URL; set it to your Convex deployment URL.")
        sys.exit(1)

    worker_id = os.environ.get("WORKER_ID") or f"worker-{uuid.uuid4()}"
    poll_interval_ms = parse_number(
        os.environ.get("WORKER_POLL_INTERVAL_MS"), 5000, 1000
    )
    batch_size = parse_number(os.environ.get("WORKER_BATCH_SIZE"), 1, 1)
    lease_duration_ms = parse_number(
        os.environ.get("WORKER_LEASE_DURATION_MS"), 60000, 1000
    )
    fingerprint_timeout_ms = parse_number(
        os.environ.get("FINGERPRINT_TIMEOUT_MS"), 8000, 1000
    )
    fingerprint_html_max_bytes = parse_number(
        os.environ.get("FINGERPRINT_HTML_MAX_BYTES"), 512000, 4096
    )
    fingerprint_sample_bytes = parse_number(
        os.environ.get("FINGERPRINT_SAMPLE_BYTES"), 2048, 256
    )
    fingerprint_max_headers = parse_number(
        os.environ.get("FINGERPRINT_MAX_HEADERS"), 50, 10
    )
    fingerprint_header_value_max = parse_number(
        os.environ.get("FINGERPRINT_HEADER_VALUE_MAX"), 512, 64
    )
    fingerprint_max_set_cookie = parse_number(
        os.environ.get("FINGERPRINT_MAX_SET_COOKIE"), 5, 1
    )
    fingerprint_set_cookie_max = parse_number(
        os.environ.get("FINGERPRINT_SET_COOKIE_MAX"), 512, 64
    )
    fingerprint_asset_timeout_ms = parse_number(
        os.environ.get("FINGERPRINT_ASSET_TIMEOUT_MS"), 5000, 1000
    )
    fingerprint_asset_max_bytes = parse_number(
        os.environ.get("FINGERPRINT_ASSET_MAX_BYTES"), 256000, 4096
    )
    fingerprint_max_assets = parse_number(
        os.environ.get("FINGERPRINT_MAX_ASSETS"), 10, 1
    )
    fingerprint_max_external_domains = parse_number(
        os.environ.get("FINGERPRINT_MAX_EXTERNAL_DOMAINS"), 50, 10
    )
    fingerprint_favicon_timeout_ms = parse_number(
        os.environ.get("FINGERPRINT_FAVICON_TIMEOUT_MS"), 5000, 1000
    )
    fingerprint_favicon_max_bytes = parse_number(
        os.environ.get("FINGERPRINT_FAVICON_MAX_BYTES"), 100000, 1024
    )
    fingerprint_asn_db_path = os.environ.get("FINGERPRINT_ASN_DB_PATH")
    fingerprint_jarm_timeout_ms = parse_number(
        os.environ.get("FINGERPRINT_JARM_TIMEOUT_MS"), fingerprint_timeout_ms, 1000
    )
    fingerprint_disable_jarm = os.environ.get("FINGERPRINT_DISABLE_JARM") == "1"
    fingerprint_user_agent = os.environ.get("FINGERPRINT_USER_AGENT") or (
        "TracehammerFingerprint/0.2"
    )

    admin_key = os.environ.get("CONVEX_ADMIN_KEY")
    auth_token = os.environ.get("CONVEX_AUTH_TOKEN")
    client = None
    if admin_key or auth_token:
        try:
            client = ConvexClient(
                convex_url, admin_key=admin_key, auth_token=auth_token
            )
        except TypeError:
            client = None
    if client is None:
        client = ConvexClient(convex_url)
        if auth_token and hasattr(client, "set_auth"):
            client.set_auth(auth_token)
        elif auth_token:
            print(
                "[worker] auth token provided but Convex SDK does not support set_auth"
            )
        if admin_key:
            print(
                "[worker] admin key provided but Convex SDK did not accept it in constructor"
            )

    shutting_down = {"value": False}

    def handle_signal(_signum, _frame):
        shutting_down["value"] = True
        print("[worker] shutdown requested")

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    print(
        "[worker] starting "
        f"id={worker_id} batchSize={batch_size} pollIntervalMs={poll_interval_ms} "
        f"fingerprintTimeoutMs={fingerprint_timeout_ms} htmlMaxBytes={fingerprint_html_max_bytes}"
    )

    asn_db, asn_error = load_asn_db(fingerprint_asn_db_path)
    if asn_error:
        print(f"[worker] ASN lookup disabled: {asn_error}")
    if fingerprint_disable_jarm:
        print("[worker] JARM disabled via FINGERPRINT_DISABLE_JARM=1")
    elif jarm is None:
        print("[worker] JARM library unavailable; install jarm to enable TLS fingerprinting")
        sys.exit(1)

    while not shutting_down["value"]:
        try:
            result = client.mutation(
                "fingerprints:claimWork",
                {
                    "workerId": worker_id,
                    "limit": batch_size,
                    "leaseDurationMs": lease_duration_ms,
                },
            )
            work = result.get("work", [])
            lease_expires_at = result.get("leaseExpiresAt")

            if not work:
                print("[worker] idle")
                time.sleep(poll_interval_ms / 1000)
                continue

            expires = (
                time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", time.gmtime(lease_expires_at / 1000)
                )
                if lease_expires_at
                else "unknown"
            )
            print(f"[worker] claimed {len(work)} domains leaseExpiresAt={expires}")

            for item in work:
                if shutting_down["value"]:
                    break
                scan_id = item.get("runId")
                domain_id = item.get("domainId")
                requested_url = item.get("url")
                if not requested_url:
                    print("[worker] missing target url")
                    continue

                http_result = fetch_http(
                    requested_url,
                    fingerprint_timeout_ms,
                    fingerprint_html_max_bytes,
                    fingerprint_user_agent,
                    fingerprint_max_headers,
                    fingerprint_header_value_max,
                    fingerprint_max_set_cookie,
                    fingerprint_set_cookie_max,
                )

                fetched_at = now_ms()
                sample_bytes = b""
                sample_truncated = False
                body_bytes = None
                body_truncated = None
                encoding = "utf-8"

                if http_result.get("ok"):
                    body_bytes = http_result.get("body_bytes", b"")
                    body_truncated = http_result.get("body_truncated", False)
                    encoding = http_result.get("encoding", "utf-8")
                    sample_bytes = body_bytes[:fingerprint_sample_bytes]
                    sample_truncated = len(body_bytes) > fingerprint_sample_bytes

                outcome = build_run_outcome(http_result, sample_bytes, sample_truncated)
                status = "success" if outcome.get("kind") == "http_content" else "error"
                error_message = outcome.get("detail") if status == "error" else None

                http_payload = strip_nones(
                    {
                        "scanId": scan_id,
                        "domainId": domain_id,
                        "requestedUrl": requested_url,
                        "finalUrl": http_result.get("final_url"),
                        "status": http_result.get("status"),
                        "fetchedAt": fetched_at,
                        "durationMs": http_result.get("duration_ms"),
                        "headers": http_result.get("headers", []),
                        "headersTruncated": http_result.get("headers_truncated", False),
                        "redirectChain": http_result.get("redirect_chain", []),
                        "contentLength": http_result.get("content_length"),
                        "contentType": http_result.get("content_type"),
                        "server": http_result.get("server"),
                        "poweredBy": http_result.get("powered_by"),
                        "setCookie": http_result.get("set_cookie") or [],
                        "errorType": http_result.get("error_type"),
                        "errorDetail": http_result.get("error_detail"),
                    }
                )
                call_mutation(client, "fingerprints:upsertHttpFingerprint", http_payload)

                html_text = ""
                html_ok = False
                if body_bytes:
                    html_text = decode_bytes(body_bytes, encoding)
                    html_ok = looks_like_html(http_result.get("content_type"), html_text)

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
                            "truncated": body_truncated,
                            "storageTodo": True,
                        }
                    )
                else:
                    html_payload.update(
                        {"errorType": "no_html", "errorDetail": "no html body"}
                    )

                call_mutation(
                    client,
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

                    external_domains = list(dict.fromkeys(filter(None, external_domains)))
                    filtered_external = [
                        domain
                        for domain in external_domains
                        if not is_allowed_domain(domain, DEFAULT_EXTERNAL_ALLOWLIST)
                    ]

                    assets_payload["localAssetCount"] = len(local_assets)
                    assets_payload["externalDomains"] = external_domains[
                        :fingerprint_max_external_domains
                    ]
                    assets_payload["externalDomainsFiltered"] = filtered_external[
                        :fingerprint_max_external_domains
                    ]
                    assets_payload["localAssetsTruncated"] = len(
                        local_assets
                    ) > fingerprint_max_assets

                    for asset_url in local_assets[:fingerprint_max_assets]:
                        asset_result = fetch_binary(
                            asset_url,
                            fingerprint_asset_timeout_ms,
                            fingerprint_asset_max_bytes,
                            fingerprint_user_agent,
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
                                        "truncated": asset_result.get(
                                            "body_truncated"
                                        ),
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
                else:
                    assets_payload.update(
                        {"errorType": "no_html", "errorDetail": "no html body"}
                    )
                    analytics_payload.update(
                        {"errorType": "no_html", "errorDetail": "no html body"}
                    )
                    favicon_url = urljoin(base_url, "/favicon.ico")

                call_mutation(
                    client, "fingerprints:upsertAssetsFingerprint", assets_payload
                )
                call_mutation(
                    client, "fingerprints:upsertAnalyticsFingerprint", analytics_payload
                )

                favicon_result = fetch_binary(
                    favicon_url,
                    fingerprint_favicon_timeout_ms,
                    fingerprint_favicon_max_bytes,
                    fingerprint_user_agent,
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

                call_mutation(
                    client, "fingerprints:upsertFaviconFingerprint", favicon_payload
                )

                parsed_host = urlparse(base_url).hostname or ""
                ip_addresses = resolve_ips(parsed_host)
                tls_info = collect_tls_info(parsed_host, fingerprint_timeout_ms)
                asn_value = lookup_asn(asn_db, ip_addresses)
                asn_todo = asn_value is None
                asn_error_detail = asn_error if asn_todo else None
                if fingerprint_disable_jarm:
                    jarm_value = None
                    jarm_error = "jarm_disabled"
                else:
                    jarm_value, jarm_error = compute_jarm(
                        parsed_host, 443, fingerprint_jarm_timeout_ms
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
                call_mutation(client, "fingerprints:upsertTlsFingerprint", tls_payload)

                try:
                    client.mutation(
                        "fingerprints:reportResult",
                        strip_nones(
                            {
                                "domainId": domain_id,
                                "runId": scan_id,
                                "workerId": worker_id,
                                "status": status,
                                "outcome": outcome,
                                "error": error_message,
                            }
                        ),
                    )
                    print(
                        f"[worker] processed host={item.get('host')} runId={scan_id} status={status}"
                    )
                except Exception as error:
                    print(
                        f"[worker] failed host={item.get('host')} runId={scan_id} error={error}"
                    )
        except Exception as error:
            print(f"[worker] loop error={error}")
            time.sleep(poll_interval_ms / 1000)

    print("[worker] stopped")


if __name__ == "__main__":
    main()
