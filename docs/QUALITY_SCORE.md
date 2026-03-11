# QUALITY_SCORE

## Current Baseline

- Layered Python package under `src/fingerprint_worker/`
- Explicit architecture and generated code-structure diagrams
- Typed config object and typed module boundaries
- Unit and fixture-smoke coverage
- Custom repo-shape linting for architecture, file size, no-print, and diagram freshness

## Quality Gates

Pass criteria before merge:

- `.venv/bin/uv run ruff check .`
- `.venv/bin/uv run ruff format .`
- `.venv/bin/uv run ty check .`
- `.venv/bin/uv run pytest`
- `.venv/bin/uv run python scripts/lint_architecture.py`
- `.venv/bin/uv run python scripts/lint_file_size.py`
- `.venv/bin/uv run python scripts/lint_no_print.py`
- `.venv/bin/uv run python scripts/lint_diagram.py`
- `.venv/bin/uv run python scripts/run_fixture_smoke.py`

## Target

- Keep runtime files below enforced size limits.
- Keep layer boundaries green at all times.
- Keep diagrams synchronized with code changes.
- Keep local smoke coverage as a required proof point for worker behavior.
