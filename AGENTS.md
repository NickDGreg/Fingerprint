# AGENTS.md

This file is the navigation map for coding agents working in this repository.

## Mission

Build and operate a Python fingerprinting worker that claims website jobs from Convex, fingerprints scam sites deterministically, and writes structured, explainable results back to Convex with strong observability and idempotent retry behavior.

## Start Here (Order)

1. Read `ARCHITECTURE.md` for the layer model and codemap.
2. Read the generated diagrams in:
   - `docs/generated/high-level-architecture-diagram.txt`
   - `docs/generated/code-structure-diagram.txt`
3. Read `docs/product-specs/index.md` and `docs/product-specs/fingerprint-worker-v1.md`.
4. Read `docs/DESIGN.md` and `docs/RELIABILITY.md` for non-functional constraints.
5. For substantial work, create or update an ExecPlan under `docs/exec-plans/active/` and follow `docs/PLANS.md`.
6. Run quality gates before and after changes:
   - `.venv/bin/uv run ruff check .`
   - `.venv/bin/uv run ty check .`
   - `.venv/bin/uv run pytest`
   - `.venv/bin/uv run python scripts/lint_architecture.py`
   - `.venv/bin/uv run python scripts/lint_file_size.py`
   - `.venv/bin/uv run python scripts/lint_no_print.py`
   - `.venv/bin/uv run python scripts/lint_diagram.py`

## Docs Map

- `docs/design-docs/`
  - `index.md`: design doc index.
  - `core-beliefs.md`: beliefs for agent-readable Python services.
  - `layering-and-constraints.md`: import direction and repo-shape rules.
  - `parallel-execution.md`: worktree and merge-safe guidance for parallel agent work.
- `docs/product-specs/`
  - `index.md`: product spec index.
  - `fingerprint-worker-v1.md`: worker outcomes and acceptance criteria.
- `docs/exec-plans/`
  - `active/`: in-flight execution plans.
  - `completed/`: completed plans.
  - `tech-debt-tracker.md`: intentionally deferred cleanup.
- `docs/generated/`
  - `db-schema.md`: Convex contract and storage-shape notes.
  - `high-level-architecture-diagram.txt`: runtime behavior overview.
  - `code-structure-diagram.txt`: code map aligned to the Python package structure.
  - `diagram-hashes.json`: generated hash metadata for diagram linting.
- Top-level docs in `docs/`
  - `DESIGN.md`, `PLANS.md`, `QUALITY_SCORE.md`, `RELIABILITY.md`, `SECURITY.md`.

## Required Working Agreements

- Keep files small and semantically named.
- Preserve typed boundaries; parse unknown external data into typed or validated shapes before business logic.
- Use the logger provider in application code; do not add `print()` calls under `src/fingerprint_worker/`.
- Keep architecture diagrams updated whenever runtime flow or package structure changes, then run:
  - `.venv/bin/uv run python scripts/sync_diagram_hash.py`
  - `.venv/bin/uv run python scripts/lint_diagram.py`
- Respect the package layers:
  - `types`
  - `config`
  - `providers`
  - `repo`
  - `service`
  - `runtime`
- Record major implementation decisions and surprises in the active ExecPlan.
