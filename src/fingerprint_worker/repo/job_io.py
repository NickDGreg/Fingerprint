import json
import os
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse


@dataclass(slots=True)
class JobClaim:
    work: list[dict[str, object]]
    lease_expires_at: int | None


def normalize_job_payload(
    job: dict[str, object],
    index: int | None = None,
) -> dict[str, object]:
    updated = dict(job)
    url = updated.get("websiteUrl")
    host = updated.get("websiteHost")
    if not host and isinstance(url, str):
        parsed = urlparse(url)
        host = parsed.netloc or parsed.path.split("/", 1)[0]
    if not updated.get("networkArtifactId"):
        generated_host = host or "unknown"
        updated["networkArtifactId"] = f"local-network-artifact-{generated_host}"
    if host:
        updated["websiteHost"] = host
    if not url and host:
        url = f"http://{host}"
    if url:
        updated["websiteUrl"] = url
    if not updated.get("runId"):
        updated["runId"] = (
            f"local-run-{index + 1}"
            if index is not None
            else f"local-run-{uuid.uuid4()}"
        )
    return updated


class ConvexJobSource:
    def __init__(self, client: Any):
        self._client = client

    def claim(self, worker_id: str, limit: int, lease_duration_ms: int) -> JobClaim:
        result = self._client.mutation(
            "fingerprints:claimWork",
            {
                "workerId": worker_id,
                "limit": limit,
                "leaseDurationMs": lease_duration_ms,
            },
        )
        work = [
            normalize_job_payload(job)
            for job in result.get("work", [])
            if isinstance(job, dict)
        ]
        return JobClaim(work, result.get("leaseExpiresAt"))


class FileJobSource:
    def __init__(self, path: str):
        self._jobs = self._load_jobs(path)
        self._cursor = 0

    def _load_jobs(self, path: str) -> list[dict[str, object]]:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict):
            jobs = data.get("jobs", [])
        elif isinstance(data, list):
            jobs = data
        else:
            jobs = []
        return [job for job in jobs if isinstance(job, dict)]

    def claim(self, worker_id: str, limit: int, lease_duration_ms: int) -> JobClaim:
        del worker_id, lease_duration_ms
        if self._cursor >= len(self._jobs):
            return JobClaim([], None)
        batch = self._jobs[self._cursor : self._cursor + limit]
        start_index = self._cursor
        self._cursor += len(batch)
        work = [
            normalize_job_payload(job, index=start_index + idx)
            for idx, job in enumerate(batch)
        ]
        return JobClaim(work, None)


class ConvexResultSink:
    def __init__(self, client: Any):
        self._client = client

    def mutation(self, name: str, payload: dict[str, object]) -> object:
        return self._client.mutation(name, payload)

    def close(self) -> None:
        return None


class MemoryResultSink:
    def __init__(self) -> None:
        self.records: list[dict[str, object]] = []

    def mutation(self, name: str, payload: dict[str, object]) -> None:
        self.records.append({"name": name, "payload": payload})
        return None

    def close(self) -> None:
        return None


class FileResultSink(MemoryResultSink):
    def __init__(self, path: str):
        super().__init__()
        self._path = path

    def close(self) -> None:
        directory = os.path.dirname(self._path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(self._path, "w", encoding="utf-8") as handle:
            json.dump({"records": self.records}, handle, indent=2)
