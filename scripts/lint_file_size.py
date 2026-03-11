from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = ROOT / "src" / "fingerprint_worker"
DEFAULT_MAX_LINES = 260
LAYER_LIMITS = {
    "config": 220,
    "providers": 220,
    "runtime": 360,
}


def main() -> int:
    violations: list[str] = []
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        max_lines = limit_for(path)
        if line_count > max_lines:
            violations.append(
                f"{path.relative_to(ROOT)}: {line_count} lines (limit {max_lines})"
            )
    if violations:
        sys.stderr.write("lint_file_size failed. File size limits exceeded.\n")
        for violation in violations:
            sys.stderr.write(f" - {violation}\n")
        return 1
    return 0


def limit_for(path: Path) -> int:
    relative = path.relative_to(PACKAGE_ROOT)
    layer = relative.parts[0] if len(relative.parts) > 1 else ""
    return LAYER_LIMITS.get(layer, DEFAULT_MAX_LINES)


if __name__ == "__main__":
    raise SystemExit(main())
