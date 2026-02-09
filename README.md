# Scam Site Fingerprinting Worker

This repository contains a Dockerised Python worker responsible for fingerprinting scam websites.

It is designed to run:
- locally during development
- on a single VM in production

The worker integrates with Convex, which acts as the system of record.

---

## What This Is

- A **pull-based fingerprinting worker**
- Processes domains sourced from scam reporting lists
- Produces structured, queryable fingerprints over time
- Built for correctness, resilience, and iteration

---

## What This Is Not

- A full crawler framework
- A scraping engine for bypassing heavy anti-bot systems
- A distributed job system
- A real-time detection engine

Those may come later. This is the foundation.

---

## High-Level Flow

1. Scam sources are ingested elsewhere (Convex cron)
2. Domains needing inspection are queued in Convex
3. This worker:
   - pulls due jobs
   - claims them via a lease
   - fingerprints the domain
   - writes results and run metadata back to Convex
4. Failed jobs are retried with backoff

Convex remains the single source of truth throughout.

---

## Key Properties

- **Idempotent**: jobs may run more than once safely
- **Fault-tolerant**: crashes and restarts are expected
- **Observable**: every run leaves a trace
- **Portable**: same Docker image everywhere

---

## Running Locally

The worker is implemented in Python and is intended to be run via Docker.

All configuration is provided through environment variables (e.g. Convex deployment keys).

A typical local workflow:
- point the worker at a dev Convex deployment
- enqueue a small set of test domains
- observe job transitions and fingerprint output

---

## Configuration

Required:
- `CONVEX_URL` — Convex deployment URL from `npx convex dev` (local) or the deployed environment.

Optional:
- `WORKER_ID` — explicit identifier for logs and lease ownership (default: random UUID).
- `WORKER_POLL_INTERVAL_MS` — idle wait before polling again (default: `5000`).
- `WORKER_BATCH_SIZE` — domains to claim per loop (default: `1`).
- `WORKER_LEASE_DURATION_MS` — lease duration for claimed work (default: `60000`).
- `WORKER_MAX_LOOPS` — maximum poll loops before exit (use `1` for a single run).
- `WORKER_ONCE` — set to `1` to run a single poll loop and exit.
- `JOB_SOURCE` — `convex` (default) or `file` for local fixtures.
- `JOB_FILE` — path to jobs JSON when `JOB_SOURCE=file` (default: `tests/fixtures/jobs.json`).
- `RESULT_SINK` — `convex` (default) or `file` for local output.
- `RESULTS_FILE` — path to results JSON when `RESULT_SINK=file` (default: `tests/fixtures/results.json`).
- `FINGERPRINT_TIMEOUT_MS` — per-request timeout for HTTP fingerprinting (default: `8000`).
- `FINGERPRINT_HTML_MAX_BYTES` — max HTML bytes to read for hashing (default: `512000`).
- `FINGERPRINT_SAMPLE_BYTES` — max bytes stored as the run sample (default: `2048`).
- `FINGERPRINT_MAX_HEADERS` — cap on stored response headers (default: `50`).
- `FINGERPRINT_HEADER_VALUE_MAX` — max header value length (default: `512`).
- `FINGERPRINT_MAX_SET_COOKIE` — cap on stored Set-Cookie entries (default: `5`).
- `FINGERPRINT_SET_COOKIE_MAX` — max Set-Cookie value length (default: `512`).
- `FINGERPRINT_ASSET_TIMEOUT_MS` — per-asset fetch timeout (default: `5000`).
- `FINGERPRINT_ASSET_MAX_BYTES` — max asset bytes to hash (default: `256000`).
- `FINGERPRINT_MAX_ASSETS` — max local assets to fetch (default: `10`).
- `FINGERPRINT_MAX_EXTERNAL_DOMAINS` — cap on stored external domains (default: `50`).
- `FINGERPRINT_FAVICON_TIMEOUT_MS` — favicon fetch timeout (default: `5000`).
- `FINGERPRINT_FAVICON_MAX_BYTES` — max favicon bytes to hash (default: `100000`).
- `FINGERPRINT_ASN_DB_PATH` — optional path to an IP→ASN database file for ASN lookup.
- `FINGERPRINT_JARM_TIMEOUT_MS` — timeout for JARM fingerprinting (default: `8000`).
- `FINGERPRINT_DISABLE_JARM` — set to `1` to skip JARM (otherwise required).
- `FINGERPRINT_DISABLE_TLS` — set to `1` to skip TLS/ASN/JARM lookups (fixture-friendly).
- `FINGERPRINT_USER_AGENT` — override the HTTP user agent string.
- `CONVEX_ADMIN_KEY` — optional admin key if your Convex deployment requires it and your SDK supports admin auth.
- `CONVEX_AUTH_TOKEN` — optional auth token if you gate mutations behind auth.

## Running locally (Docker)

### 1. Build the image (human)
```bash
docker build -t tracehammer-fingerprint .
```

### 2. Run the worker (human)
```bash
docker run --rm \
  -e CONVEX_URL="https://<your-convex-deployment>" \
  tracehammer-fingerprint
```

## Running locally (Python)

This repo uses the Convex Python SDK and is `uv`-ready for dependency management.

```bash
CONVEX_URL="https://<your-convex-deployment>" uv run python src/worker.py
```

If you need to (re)install dependencies locally:
```bash
uv sync
```

### Local fixture smoke (no Convex)

Run a deterministic local fixture server and process a small set of test jobs:

```bash
uv run python scripts/run_fixture_smoke.py
```

Docker installs the Convex SDK directly via `pip install convex` for simplicity.
If you want to change dependencies, use `uv add <package>` and re-run `uv sync`.

## Notes

- The worker is stateless; you can stop and restart it without losing progress.
- Each claim creates a `fingerprintRuns` record in Convex so run history is visible.
- Milestone 2 HTTP fingerprinting stores a small response sample plus status metadata to explain why a domain was classified as `http_content`, `http_error`, or `unreachable`.
- Milestone 3 adds exponential backoff for failures and marks stale runs as `abandoned` when a lease expires.
- The worker now stores per-scan outputs for HTTP, HTML hashes, favicon hash, local asset hashes, tracker IDs, and TLS metadata.
- Raw HTML/assets are not stored in Convex yet; those are marked with `storageTodo` for future object storage integration.
- Fuzzy hashing uses `ssdeep`; ensure the Docker image includes `libfuzzy-dev` (already in the Dockerfile).

---

## Deployment Model

- One VM
- One running worker process
- No special infrastructure requirements beyond Docker
- CI builds the image; deployment pulls and restarts it

The system is intentionally simple.

---

## CI/CD Deployment

On each push to `main`, GitHub Actions builds the Docker image, tags it with the commit SHA and `latest`, pushes to GHCR, then deploys to the VM over SSH by updating `/home/github/fingerprint/compose.yml` and running `docker compose pull` + `docker compose up -d`.

VM requirements:
- Docker installed and running.
- `github` user exists with SSH access.
- `/home/github/fingerprint/.env` is present with required worker environment variables.
- The VM is already logged into GHCR (`docker login ghcr.io`).

Rollback (from the VM):
```bash
cd /home/github/fingerprint
IMAGE_TAG=<previous-sha> docker compose pull
IMAGE_TAG=<previous-sha> docker compose up -d
```

## Design Principles

- Convex is the database and job queue
- The worker does network-heavy work
- State machines are explicit
- Failure paths are first-class
- Simplicity beats premature abstraction

---

## Status

Early-stage, evolving system.

Expect schemas, fingerprint depth, and heuristics to change rapidly.

---

## macOS install notes (`ssdeep` via `uv`)

On macOS (especially Apple Silicon), the Python `ssdeep` package is often built from source and may fail during `uv sync` with errors like:

- `ModuleNotFoundError: No module named 'pkg_resources'`
- `fatal error: 'fuzzy.h' file not found`
- autotools-related errors (`configure` missing, `libtoolize`/`automake` not found)

### 1) Install system dependencies

```sh
brew install ssdeep autoconf automake libtool
````

If the build complains about `libtoolize` not found, Homebrew provides `glibtoolize`. Create a shim:

```sh
mkdir -p ~/.local/bin
ln -sf "$(brew --prefix libtool)/bin/glibtoolize" ~/.local/bin/libtoolize
export PATH="$HOME/.local/bin:$PATH"
```

### 2) Pin build-time `setuptools` for `ssdeep` in `pyproject.toml`

Add:

```toml
[tool.uv.extra-build-dependencies]
ssdeep = ["setuptools<81"]
```

(Reason: `ssdeep`’s build still imports `pkg_resources`, which may be missing with newer `setuptools`.)

### 3) Sync (build bundled lib)

```sh
uv cache clean
BUILD_LIB=1 uv sync
```
