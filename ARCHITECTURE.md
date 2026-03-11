# Architecture

## Bird's-Eye Overview

This repository contains a single Python service: a pull-based fingerprinting worker.

The worker claims due jobs from Convex, performs bounded HTTP/HTML/asset/favicon/TLS fingerprinting for each target website, and writes structured stage results plus final run outcomes back to Convex. It can also run locally against fixture files using file-backed job and result adapters.

## Runtime Flow

1. The runtime entrypoint in `src/fingerprint_worker/main.py` loads environment configuration.
2. The worker chooses job and result adapters:
   - Convex-backed for normal operation
   - file/memory-backed for local tests and fixture smoke
3. The runtime loop in `src/fingerprint_worker/runtime/worker.py` claims a bounded batch of jobs.
4. For each job, the worker:
   - fetches the primary HTTP response
   - stores HTTP metadata
   - computes HTML hashes and similarity markers when HTML is present
   - fetches local assets and favicon
   - extracts external domains and tracking IDs
   - collects TLS/IP/ASN/JARM metadata unless disabled
   - reports the final run outcome and any per-stage issues
5. The worker sleeps between empty polls and exits cleanly on signal or configured loop limit.

## Layer Model

Dependency direction is enforced by `scripts/lint_architecture.py`.

- `types`: constants and shared payload aliases
- `config`: environment parsing and runtime config
- `providers`: external system wrappers such as logging, HTTP, TLS, Convex client creation
- `repo`: job source and result sink adapters
- `service`: fingerprinting logic and payload construction
- `runtime`: orchestration and run reporting

`testing` exists for deterministic fixture helpers and is excluded from the production layer chain.

## Codemap

Entrypoints:
- `src/worker.py`: compatibility wrapper entrypoint
- `src/fingerprint_worker/main.py`: package entrypoint and composition root

Config and shared types:
- `src/fingerprint_worker/config/env.py`: environment parsing into `WorkerConfig`
- `src/fingerprint_worker/types/runtime.py`: worker constants and shared JSON alias

Providers:
- `src/fingerprint_worker/providers/logging_provider.py`: application logger setup
- `src/fingerprint_worker/providers/convex_provider.py`: Convex client construction
- `src/fingerprint_worker/providers/http_provider.py`: bounded HTTP and binary fetches
- `src/fingerprint_worker/providers/tls_provider.py`: TLS certificate, ASN, and JARM helpers

Repositories:
- `src/fingerprint_worker/repo/job_io.py`: Convex/file job sources and result sinks

Services:
- `src/fingerprint_worker/service/fingerprint_core.py`: shared HTML/header/hash/domain helpers
- `src/fingerprint_worker/service/http_analysis.py`: HTTP/HTML/assets/analytics/favicon payload building
- `src/fingerprint_worker/service/tls_analysis.py`: TLS payload building
- `src/fingerprint_worker/service/runtime_helpers.py`: outcome/status helpers

Runtime orchestration:
- `src/fingerprint_worker/runtime/reporting.py`: run issue and final result reporting
- `src/fingerprint_worker/runtime/worker.py`: claim/process/finalize loop

Testing helpers:
- `src/fingerprint_worker/testing/fixture_server.py`: deterministic local fixture site
- `scripts/run_fixture_smoke.py`: end-to-end local smoke runner

## Non-Goals

- Distributed work scheduling
- Browser automation
- Object storage integration in this repo today
- Large artifact persistence in Convex
- Multi-service monorepo orchestration
