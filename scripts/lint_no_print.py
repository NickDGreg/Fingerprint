from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = ROOT / "src" / "fingerprint_worker"


def main() -> int:
    violations: list[str] = []
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == "print":
                    violations.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    if violations:
        sys.stderr.write(
            "lint_no_print failed. Use logger providers instead of print().\n"
        )
        for violation in violations:
            sys.stderr.write(f" - {violation}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
