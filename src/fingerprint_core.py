import hashlib
import importlib
import re
from typing import Any
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

try:
    ssdeep: Any = importlib.import_module("ssdeep")
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
            rel_value = link.get("rel")
            if isinstance(rel_value, str):
                rel_list = [rel_value]
            elif isinstance(rel_value, list):
                rel_list = [str(item) for item in rel_value]
            else:
                rel_list = []
            rel = " ".join(rel_list).lower()
            if "icon" in rel:
                href = link.get("href")
                if isinstance(href, str):
                    return urljoin(final_url, href)
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
        src = tag.get("src")
        if isinstance(src, str):
            urls.append(src)
    for tag in soup.find_all("link", href=True):
        rel_value = tag.get("rel")
        if isinstance(rel_value, str):
            rel_list = [rel_value]
        elif isinstance(rel_value, list):
            rel_list = [str(item) for item in rel_value]
        else:
            rel_list = []
        rel = " ".join(rel_list).lower()
        if "stylesheet" in rel:
            href = tag.get("href")
            if isinstance(href, str):
                urls.append(href)
    for tag in soup.find_all("img", src=True):
        src = tag.get("src")
        if isinstance(src, str):
            urls.append(src)
    for tag in soup.find_all("iframe", src=True):
        src = tag.get("src")
        if isinstance(src, str):
            urls.append(src)

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
