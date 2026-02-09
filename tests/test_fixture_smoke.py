import base64
import tempfile
from urllib.parse import urlparse

import mmh3

from fixture_server import (
    FIXTURE_CSS,
    FIXTURE_FAVICON,
    FIXTURE_HTML,
    FIXTURE_JS,
    FIXTURE_PNG,
    start_fixture_server,
)
from fingerprint_core import compute_sha256
from worker import build_config, run_worker
from worker_io import FileJobSource, MemoryResultSink


def _records_by_name(records):
    grouped = {}
    for record in records:
        grouped.setdefault(record["name"], []).append(record["payload"])
    return grouped


def test_fixture_smoke():
    server = start_fixture_server()
    try:
        base_url = server.base_url
        parsed = urlparse(base_url)
        host = parsed.netloc
        jobs = [
            {"host": host, "url": f"{base_url}/"},
        ]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as handle:
            handle.write("{\"jobs\": [")
            handle.write(
                ",".join(
                    [
                        f"{{\"host\": \"{job['host']}\", \"url\": \"{job['url']}\"}}"
                        for job in jobs
                    ]
                )
            )
            handle.write("]}")
            jobs_path = handle.name

        env = {
            "WORKER_MAX_LOOPS": "1",
            "WORKER_BATCH_SIZE": "1",
            "FINGERPRINT_DISABLE_TLS": "1",
            "FINGERPRINT_DISABLE_JARM": "1",
        }
        config = build_config(env)
        job_source = FileJobSource(jobs_path)
        sink = MemoryResultSink()

        run_worker(config, job_source, sink, install_signal_handlers=False)

        grouped = _records_by_name(sink.records)
        http_payload = grouped["fingerprints:upsertHttpFingerprint"][0]
        assert http_payload["status"] == 200
        assert any(
            header.get("key") == "X-Test-Header" and header.get("value") == "fixture"
            for header in http_payload.get("headers", [])
        )

        html_payload = grouped["fingerprints:upsertHtmlFingerprint"][0]
        assert html_payload["sha256"] == compute_sha256(FIXTURE_HTML.encode("utf-8"))

        assets_payload = grouped["fingerprints:upsertAssetsFingerprint"][0]
        assert assets_payload["localAssetCount"] == 3
        hashes = [asset.get("sha256") for asset in assets_payload["localAssets"]]
        assert compute_sha256(FIXTURE_JS) in hashes
        assert compute_sha256(FIXTURE_CSS) in hashes
        assert compute_sha256(FIXTURE_PNG) in hashes

        analytics_payload = grouped["fingerprints:upsertAnalyticsFingerprint"][0]
        assert analytics_payload["googleAnalyticsIds"] == ["UA-12345678-1"]
        assert analytics_payload["googleAnalytics4Ids"] == ["G-1A2B3C4D"]
        assert analytics_payload["gtmIds"] == ["GTM-ABCDE1"]
        assert analytics_payload["facebookPixelIds"] == ["1234567890"]

        favicon_payload = grouped["fingerprints:upsertFaviconFingerprint"][0]
        expected_mmh3 = mmh3.hash(base64.b64encode(FIXTURE_FAVICON), signed=False)
        assert favicon_payload["mmh3"] == expected_mmh3
    finally:
        server.close()
