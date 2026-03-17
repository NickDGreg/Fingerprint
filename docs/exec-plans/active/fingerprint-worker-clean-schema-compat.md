# Fingerprint Worker Clean Schema Compatibility

## Purpose

Keep the fingerprint worker compatible with the final clean Convex schema in
`../tracehammer-app` by removing legacy artifact field usage and aligning local
fixtures, tests, and docs with the canonical claim-work contract.

## Repository Context

- This repo is a Python worker that claims fingerprint jobs from Convex and
  writes stage evidence plus final run outcomes back through `fingerprints:*`
  mutations.
- The adjacent app repo removed the temporary clean-schema compatibility layer.
- `convex/fingerprints/queue.ts` now returns work items with canonical artifact
  fields: `networkArtifactId`, `host`, `canonicalUrl`, and `runId`.
- This worker still reads legacy job keys `websiteHost` and `websiteUrl` in
  `src/fingerprint_worker/repo/job_io.py` and
  `src/fingerprint_worker/runtime/worker.py`.
- This repo does not currently call `crypto.reportResult`; the worker contract
  change here is the fingerprint claim-work payload shape.

## Implementation Path

1. Update local job normalization in
   `src/fingerprint_worker/repo/job_io.py` to canonicalize jobs around `host`
   and `canonicalUrl`, including local fixture backfills for file-backed runs.
2. Update runtime readers in `src/fingerprint_worker/runtime/worker.py` to use
   `host` and `canonicalUrl` when building logs, fetch URLs, and final reports.
3. Update local fixtures and tests under `tests/` and
   `scripts/run_fixture_smoke.py` so they generate and assert canonical field
   names only.
4. Update docs that still describe the old job shape.

## Acceptance Criteria

- File-backed jobs can omit generated IDs but must normalize to canonical
  `host` and `canonicalUrl` fields.
- The worker must process Convex `claimWork` payloads from the clean schema
  without depending on `websiteHost` or `websiteUrl`.
- Smoke and unit tests must pass using canonical field names only.
- Documentation in this repo must describe the canonical artifact job contract.

## Validation Commands

- `.venv/bin/uv run ruff check .`
- `.venv/bin/uv run ty check .`
- `.venv/bin/uv run pytest`
- `.venv/bin/uv run python scripts/lint_architecture.py`
- `.venv/bin/uv run python scripts/lint_file_size.py`
- `.venv/bin/uv run python scripts/lint_no_print.py`
- `.venv/bin/uv run python scripts/lint_diagram.py`

## Progress

- [completed] Inspect worker contract and adjacent Convex clean-schema files.
- [completed] Update worker job normalization and runtime readers.
- [completed] Update tests, fixtures, and docs.
- [completed] Run validation commands and capture outcomes.

## Surprises & Discoveries

- The user flagged crypto mutation payload changes, but this repository only
  calls `fingerprints:*` mutations today.
- The concrete breakage here is the fingerprint work-claim reader: the worker
  still expects `websiteHost` and `websiteUrl` while the clean schema now emits
  `host` and `canonicalUrl`.
- The fingerprint result mutation contract itself did not change in the adjacent
  repo, so only job readers, local fixtures, and docs needed code changes here.

## Decision Log

- Use canonical artifact field names throughout this repository rather than
  keeping local aliases, because the adjacent schema removed the compatibility
  layer entirely.
- Keep result payload field names unchanged where the Convex fingerprint
  mutation contract has not changed.

## Outcomes & Retrospective

- `src/fingerprint_worker/repo/job_io.py` now normalizes file/Convex jobs with
  canonical `host` and `canonicalUrl` fields only.
- `src/fingerprint_worker/runtime/worker.py` now reads canonical artifact fields
  when building requested URLs and logs.
- Fixture generators, tests, and product spec docs were updated to the clean
  schema contract.
- Validation passed:
  - `.venv/bin/uv run ruff check .`
  - `.venv/bin/uv run ty check .`
  - `.venv/bin/uv run pytest`
  - `.venv/bin/uv run python scripts/lint_architecture.py`
  - `.venv/bin/uv run python scripts/lint_file_size.py`
  - `.venv/bin/uv run python scripts/lint_no_print.py`
  - `.venv/bin/uv run python scripts/lint_diagram.py`
