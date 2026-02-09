import json
import os
import sys
from urllib.parse import urlparse

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from fixture_server import start_fixture_server
from worker import build_config, run_worker
from worker_io import FileJobSource, FileResultSink


def main():
    server = start_fixture_server()
    try:
        base_url = server.base_url
        parsed = urlparse(base_url)
        host = parsed.netloc
        jobs = [
            {"host": host, "url": f"{base_url}/"},
            {"host": host, "url": f"{base_url}/redirect"},
        ]

        jobs_path = os.path.join("tests", "fixtures", "jobs.generated.json")
        results_path = os.path.join("tests", "fixtures", "results.generated.json")
        os.makedirs(os.path.dirname(jobs_path), exist_ok=True)
        with open(jobs_path, "w", encoding="utf-8") as handle:
            json.dump({"jobs": jobs}, handle, indent=2)

        env = dict(os.environ)
        env.update(
            {
                "WORKER_MAX_LOOPS": "1",
                "WORKER_BATCH_SIZE": str(len(jobs)),
                "FINGERPRINT_DISABLE_TLS": "1",
                "FINGERPRINT_DISABLE_JARM": "1",
            }
        )
        config = build_config(env)
        job_source = FileJobSource(jobs_path)
        sink = FileResultSink(results_path)

        run_worker(config, job_source, sink, install_signal_handlers=False)
        print(f"[smoke] wrote results to {results_path}")
    finally:
        server.close()


if __name__ == "__main__":
    main()
