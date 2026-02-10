import json
import os
import uuid
from dataclasses import dataclass
from urllib.parse import urlparse

from fingerprint_core import normalize_host


@dataclass
class JobClaim:
    work: list
    lease_expires_at: int | None


class ConvexJobSource:
    def __init__(self, client):
        self._client = client

    def claim(self, worker_id, limit, lease_duration_ms):
        result = self._client.mutation(
            "fingerprints:claimWork",
            {
                "workerId": worker_id,
                "limit": limit,
                "leaseDurationMs": lease_duration_ms,
            },
        )
        return JobClaim(result.get("work", []), result.get("leaseExpiresAt"))


class FileJobSource:
    def __init__(self, path):
        self._jobs = self._load_jobs(path)
        self._cursor = 0

    def _load_jobs(self, path):
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict):
            jobs = data.get("jobs", [])
        elif isinstance(data, list):
            jobs = data
        else:
            jobs = []
        return [job for job in jobs if isinstance(job, dict)]

    def _ensure_ids(self, job, index):
        updated = dict(job)
        url = updated.get("url")
        host = updated.get("host")
        if not host and url:
            parsed = urlparse(url)
            host = parsed.netloc or parsed.path.split("/", 1)[0]
            updated["host"] = host
        stable_host = normalize_host(host or "") or "unknown"
        if not updated.get("domainId"):
            updated["domainId"] = f"local-domain-{stable_host}"
        if not updated.get("runId"):
            updated["runId"] = f"local-run-{index + 1}"
        if not updated.get("url") and updated.get("host"):
            updated["url"] = f"http://{updated['host']}"
        if not updated.get("runId"):
            updated["runId"] = f"local-run-{uuid.uuid4()}"
        return updated

    def claim(self, worker_id, limit, lease_duration_ms):
        if self._cursor >= len(self._jobs):
            return JobClaim([], None)
        batch = self._jobs[self._cursor : self._cursor + limit]
        start_index = self._cursor
        self._cursor += len(batch)
        work = [
            self._ensure_ids(job, start_index + idx) for idx, job in enumerate(batch)
        ]
        return JobClaim(work, None)


class ConvexResultSink:
    def __init__(self, client):
        self._client = client

    def mutation(self, name, payload):
        return self._client.mutation(name, payload)

    def close(self):
        return None


class MemoryResultSink:
    def __init__(self):
        self.records = []

    def mutation(self, name, payload):
        self.records.append({"name": name, "payload": payload})
        return None

    def close(self):
        return None


class FileResultSink(MemoryResultSink):
    def __init__(self, path):
        super().__init__()
        self._path = path

    def close(self):
        directory = os.path.dirname(self._path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(self._path, "w", encoding="utf-8") as handle:
            json.dump({"records": self.records}, handle, indent=2)
        return None
