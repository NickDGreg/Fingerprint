import os
import sys

from fingerprint_worker.config.env import build_config
from fingerprint_worker.providers.convex_provider import build_convex_client
from fingerprint_worker.providers.logging_provider import LOGGER, configure_logging
from fingerprint_worker.repo.job_io import (
    ConvexJobSource,
    ConvexResultSink,
    FileJobSource,
    FileResultSink,
    MemoryResultSink,
)
from fingerprint_worker.runtime.worker import run_worker


def main() -> None:
    env = os.environ
    config = build_config(env)
    configure_logging(config)

    job_source_kind = (env.get("JOB_SOURCE") or "convex").lower()
    result_sink_kind = env.get("RESULT_SINK")
    job_file = env.get("JOB_FILE") or "tests/fixtures/jobs.json"
    results_file = env.get("RESULTS_FILE") or "tests/fixtures/results.json"

    needs_convex = job_source_kind == "convex"
    if result_sink_kind is None:
        result_sink_kind = "convex" if needs_convex else "file"
    result_sink_kind = result_sink_kind.lower()
    needs_convex = needs_convex or result_sink_kind == "convex"

    client = build_convex_client(env) if needs_convex else None
    if needs_convex and client is None:
        LOGGER.error("Missing CONVEX_URL; set it to your Convex deployment URL.")
        sys.exit(1)

    if job_source_kind == "convex":
        job_source = ConvexJobSource(client)
    elif job_source_kind == "file":
        job_source = FileJobSource(job_file)
    else:
        LOGGER.error("Unknown JOB_SOURCE=%s", job_source_kind)
        sys.exit(1)

    if result_sink_kind == "convex":
        sink = ConvexResultSink(client)
    elif result_sink_kind == "file":
        sink = FileResultSink(results_file)
    elif result_sink_kind == "memory":
        sink = MemoryResultSink()
    else:
        LOGGER.error("Unknown RESULT_SINK=%s", result_sink_kind)
        sys.exit(1)

    run_worker(config, job_source, sink, install_signal_handlers=True)


if __name__ == "__main__":
    main()
