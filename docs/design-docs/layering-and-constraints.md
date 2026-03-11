# Layering And Constraints

## Layers

- `types`
- `config`
- `providers`
- `repo`
- `service`
- `runtime`

`testing` exists for deterministic fixture helpers and is excluded from the main production dependency chain.

## Dependency Direction

A layer may import from itself and any earlier layer in the list above.

Reverse imports are invalid and fail `scripts/lint_architecture.py`.

## Mechanical Rules

- No `print()` in `src/fingerprint_worker/`; use the logger provider.
- Keep package files below the enforced file-size limits.
- Keep generated diagrams synchronized with the real code structure.
- Parse unknown external data before business logic depends on it.
