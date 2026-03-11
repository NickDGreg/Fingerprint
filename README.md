# Scam Site Fingerprinting Worker

This repository contains a Python worker that fingerprints scam websites and writes structured results to Convex.

## Scope

This worker does:
- claim jobs from Convex or a local file source
- collect HTTP metadata, HTML hashes, favicon hashes, asset hashes, trackers, and TLS metadata
- record stage-level issues and final run outcomes
- run locally and in Docker without code changes

This worker does not:
- run a browser
- store raw HTML or large assets in Convex
- manage a distributed queue
- operate as a multi-service monorepo

## Repository Layout

- `src/fingerprint_worker/`: layered Python package for config, providers, repo adapters, services, and runtime
- `src/*.py`: compatibility wrappers for the historical flat import surface
- `docs/`: architecture, design, reliability, quality, and product-spec documents
- `scripts/`: smoke runner and repo-shape lint scripts
- `tests/`: unit and fixture smoke coverage

## Local Run

Python:

```bash
.venv/bin/uv run python src/worker.py
```

Local fixture smoke:

```bash
.venv/bin/uv run python scripts/run_fixture_smoke.py
```

Docker:

```bash
docker build -t tracehammer-fingerprint .
docker run --rm -e CONVEX_URL="https://<your-convex-deployment>" tracehammer-fingerprint
```

## Quality Gates

```bash
.venv/bin/uv run ruff check .
.venv/bin/uv run ruff format .
.venv/bin/uv run ty check .
.venv/bin/uv run pytest
.venv/bin/uv run python scripts/lint_architecture.py
.venv/bin/uv run python scripts/lint_file_size.py
.venv/bin/uv run python scripts/lint_no_print.py
.venv/bin/uv run python scripts/lint_diagram.py
.venv/bin/uv run python scripts/run_fixture_smoke.py
```

## Environment

Required:
- `CONVEX_URL` when using the Convex job source or result sink

Key optional variables:
- `WORKER_ENV`
- `WORKER_LOG_LEVEL`
- `WORKER_LOG_HTTP_DETAILS`
- `WORKER_BATCH_SIZE`
- `WORKER_POLL_INTERVAL_MS`
- `WORKER_MAX_LOOPS`
- `JOB_SOURCE`
- `RESULT_SINK`
- `FINGERPRINT_DISABLE_TLS`
- `FINGERPRINT_DISABLE_JARM`

See `docs/product-specs/fingerprint-worker-v1.md` for the worker contract and `ARCHITECTURE.md` for the runtime map.
