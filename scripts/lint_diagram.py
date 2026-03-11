from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HASH_FILE = ROOT / "docs" / "generated" / "diagram-hashes.json"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    payload = json.loads(HASH_FILE.read_text(encoding="utf-8"))
    if payload.get("algorithm") != "sha256" or not isinstance(
        payload.get("files"), dict
    ):
        sys.stderr.write(
            "lint_diagram failed. diagram-hashes.json has invalid shape.\n"
        )
        return 1

    mismatches: list[str] = []
    for file_name, expected_hash in payload["files"].items():
        actual_hash = sha256_bytes((ROOT / file_name).read_bytes())
        if actual_hash != expected_hash:
            mismatches.append(file_name)
    if mismatches:
        sys.stderr.write(
            "lint_diagram failed. Diagram hashes are stale. Run the sync script.\n"
        )
        for mismatch in mismatches:
            sys.stderr.write(f" - {mismatch}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
