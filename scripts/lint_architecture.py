from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = ROOT / "src" / "fingerprint_worker"
ORDERED_LAYERS = ["types", "config", "providers", "repo", "service", "runtime"]
IGNORED_DIRS = {"__pycache__"}


def main() -> int:
    violations: list[str] = []
    for path in iter_python_files(PACKAGE_ROOT):
        current_layer = read_layer(path)
        if current_layer is None or current_layer == "testing":
            continue
        current_index = ORDERED_LAYERS.index(current_layer)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for import_name in read_internal_imports(tree):
            target_layer = read_imported_layer(import_name)
            if target_layer is None or target_layer == "testing":
                continue
            target_index = ORDERED_LAYERS.index(target_layer)
            if target_index > current_index:
                violations.append(
                    f"{path.relative_to(ROOT)} imports {import_name} "
                    f"({current_layer} -> {target_layer})"
                )
    if violations:
        sys.stderr.write("lint_architecture failed. Layering violations detected.\n")
        for violation in violations:
            sys.stderr.write(f" - {violation}\n")
        return 1
    return 0


def iter_python_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*.py"):
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        files.append(path)
    return sorted(files)


def read_layer(path: Path) -> str | None:
    relative = path.relative_to(PACKAGE_ROOT)
    if len(relative.parts) <= 1:
        return None
    return relative.parts[0]


def read_internal_imports(tree: ast.AST) -> list[str]:
    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("fingerprint_worker."):
                    imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.startswith("fingerprint_worker."):
                imports.append(node.module)
    return imports


def read_imported_layer(module_name: str) -> str | None:
    parts = module_name.split(".")
    if len(parts) < 2:
        return None
    layer = parts[1]
    return layer if layer in ORDERED_LAYERS or layer == "testing" else None


if __name__ == "__main__":
    raise SystemExit(main())
