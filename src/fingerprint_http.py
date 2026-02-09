import time

import requests

from fingerprint_core import build_headers, truncate_value


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
