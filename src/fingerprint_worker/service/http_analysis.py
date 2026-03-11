import base64
from typing import Any
from urllib.parse import urlparse

import mmh3

from fingerprint_worker.config.env import WorkerConfig
from fingerprint_worker.providers.http_provider import fetch_binary
from fingerprint_worker.service.fingerprint_core import (
    DEFAULT_EXTERNAL_ALLOWLIST,
    collect_asset_urls,
    compute_fuzzy_hash,
    compute_sha256,
    extract_base_url,
    extract_trackers,
    find_favicon_url,
    host_matches,
    is_allowed_domain,
    looks_like_html,
    normalize_host,
    normalize_html_text,
    strip_nones,
)


def build_http_payload(
    scan_id: str | None,
    record_id: str | None,
    fetched_at: int,
    http_result: dict[str, object],
) -> dict[str, object]:
    headers_truncated = http_result.get("headers_truncated")
    return strip_nones(
        {
            "scanId": scan_id,
            "networkArtifactId": record_id,
            "requestedUrl": http_result.get("requested_url"),
            "finalUrl": http_result.get("final_url"),
            "status": http_result.get("status"),
            "redirectChain": http_result.get("redirect_chain") or [],
            "headers": http_result.get("headers") or [],
            "contentType": http_result.get("content_type"),
            "contentLength": http_result.get("content_length"),
            "durationMs": http_result.get("duration_ms"),
            "fetchedAt": fetched_at,
            "server": http_result.get("server"),
            "poweredBy": http_result.get("powered_by"),
            "setCookie": http_result.get("set_cookie") or [],
            "errorType": http_result.get("error_type"),
            "errorDetail": http_result.get("error_detail"),
            "headersTruncated": bool(headers_truncated),
        }
    )


def analyze_content(
    config: WorkerConfig,
    scan_id: str | None,
    record_id: str | None,
    requested_url: str,
    fetched_at: int,
    http_result: dict[str, object],
) -> dict[str, Any]:
    body_bytes = http_result.get("body_bytes", b"") if http_result else b""
    if not isinstance(body_bytes, bytes):
        body_bytes = b""
    encoding = str(http_result.get("encoding", "utf-8"))
    html_text = body_bytes.decode(encoding, errors="replace") if body_bytes else ""
    html_ok = bool(body_bytes) and looks_like_html(
        http_result.get("content_type"), html_text
    )

    html_payload: dict[str, object] = {
        "scanId": scan_id,
        "networkArtifactId": record_id,
        "recordedAt": fetched_at,
    }
    if html_ok:
        normalized = normalize_html_text(html_text)
        fuzzy_hash, fuzzy_todo = compute_fuzzy_hash(html_text)
        html_payload.update(
            {
                "sha256": compute_sha256(body_bytes),
                "normalizedSha256": compute_sha256(normalized.encode("utf-8")),
                "fuzzyHash": fuzzy_hash,
                "fuzzyHashTodo": fuzzy_todo,
                "htmlLength": len(body_bytes),
                "truncated": http_result.get("body_truncated"),
                "storageTodo": True,
            }
        )
    else:
        html_payload.update({"errorType": "no_html", "errorDetail": "no html body"})

    assets_payload: dict[str, object] = {
        "scanId": scan_id,
        "networkArtifactId": record_id,
        "localAssets": [],
        "localAssetCount": 0,
        "externalDomains": [],
        "externalDomainsFiltered": [],
        "recordedAt": fetched_at,
    }
    analytics_payload: dict[str, object] = {
        "scanId": scan_id,
        "networkArtifactId": record_id,
        "googleAnalyticsIds": [],
        "googleAnalytics4Ids": [],
        "gtmIds": [],
        "facebookPixelIds": [],
        "recordedAt": fetched_at,
    }

    base_url = str(http_result.get("final_url") or requested_url)
    favicon_url = urlparse(base_url)._replace(path="/favicon.ico").geturl()
    if html_ok:
        base_url = extract_base_url(base_url, html_text)
        asset_urls = collect_asset_urls(html_text, base_url)
        base_host = urlparse(base_url).hostname or ""
        local_assets: list[str] = []
        external_domains: list[str] = []

        for asset_url in asset_urls:
            asset_host = urlparse(asset_url).hostname or ""
            if host_matches(asset_host, base_host):
                local_assets.append(asset_url)
            else:
                external_domains.append(normalize_host(asset_host))

        external_domains = list(dict.fromkeys(filter(None, external_domains)))
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
        local_asset_payloads = assets_payload["localAssets"]
        assert isinstance(local_asset_payloads, list)
        for asset_url in local_assets[: config.fingerprint_max_assets]:
            asset_result = fetch_binary(
                asset_url,
                config.fingerprint_asset_timeout_ms,
                config.fingerprint_asset_max_bytes,
                config.fingerprint_user_agent,
            )
            if asset_result.get("ok"):
                asset_body = asset_result.get("body_bytes", b"")
                if not isinstance(asset_body, bytes):
                    asset_body = b""
                local_asset_payloads.append(
                    strip_nones(
                        {
                            "url": asset_url,
                            "sha256": compute_sha256(asset_body)
                            if asset_body
                            else None,
                            "contentType": asset_result.get("content_type"),
                            "contentLength": asset_result.get("content_length"),
                            "truncated": asset_result.get("body_truncated"),
                        }
                    )
                )
            else:
                local_asset_payloads.append(
                    strip_nones(
                        {"url": asset_url, "errorType": asset_result.get("error_type")}
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
        assets_payload.update({"errorType": "no_html", "errorDetail": "no html body"})
        analytics_payload.update(
            {"errorType": "no_html", "errorDetail": "no html body"}
        )

    favicon_result = fetch_binary(
        favicon_url,
        config.fingerprint_favicon_timeout_ms,
        config.fingerprint_favicon_max_bytes,
        config.fingerprint_user_agent,
    )
    favicon_payload: dict[str, object]
    if favicon_result.get("ok"):
        icon_bytes = favicon_result.get("body_bytes", b"")
        if not isinstance(icon_bytes, bytes):
            icon_bytes = b""
        mmh3_hash = (
            mmh3.hash(base64.b64encode(icon_bytes), signed=False)
            if icon_bytes
            else None
        )
        favicon_payload = strip_nones(
            {
                "scanId": scan_id,
                "networkArtifactId": record_id,
                "url": favicon_result.get("final_url") or favicon_url,
                "status": favicon_result.get("status"),
                "contentType": favicon_result.get("content_type"),
                "contentLength": favicon_result.get("content_length"),
                "sha256": compute_sha256(icon_bytes) if icon_bytes else None,
                "mmh3": mmh3_hash,
                "storageTodo": True,
                "recordedAt": fetched_at,
            }
        )
    else:
        favicon_payload = strip_nones(
            {
                "scanId": scan_id,
                "networkArtifactId": record_id,
                "url": favicon_url,
                "errorType": favicon_result.get("error_type"),
                "errorDetail": favicon_result.get("error_detail"),
                "recordedAt": fetched_at,
            }
        )

    return {
        "body_bytes": body_bytes,
        "base_url": base_url,
        "html_ok": html_ok,
        "html_payload": strip_nones(html_payload),
        "assets_payload": assets_payload,
        "analytics_payload": analytics_payload,
        "favicon_payload": favicon_payload,
    }
