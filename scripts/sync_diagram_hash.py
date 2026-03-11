from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TRACKED_FILES = [
    "docs/generated/high-level-architecture-diagram.txt",
    "docs/generated/code-structure-diagram.txt",
]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


payload = {
    "generatedAt": datetime.now(timezone.utc).isoformat(),
    "algorithm": "sha256",
    "files": {},
}
for file_name in TRACKED_FILES:
    content = (ROOT / file_name).read_bytes()
    payload["files"][file_name] = sha256_bytes(content)

(ROOT / "docs" / "generated" / "diagram-hashes.json").write_text(
    f"{json.dumps(payload, indent=2)}\n",
    encoding="utf-8",
)
