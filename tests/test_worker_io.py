from worker_io import FileJobSource, normalize_job_payload


def test_normalize_job_payload_accepts_network_artifact_shape():
    job = normalize_job_payload(
        {
            "networkArtifactId": "artifact-1",
            "host": "example.test",
            "canonicalUrl": "https://example.test/login",
        }
    )

    assert job["networkArtifactId"] == "artifact-1"
    assert job["host"] == "example.test"
    assert job["canonicalUrl"] == "https://example.test/login"
    assert str(job["runId"]).startswith("local-run-")


def test_file_job_source_backfills_canonical_artifact_fields(tmp_path):
    jobs_path = tmp_path / "jobs.json"
    jobs_path.write_text(
        """
        {
          "jobs": [
            {
              "networkArtifactId": "artifact-2",
              "host": "example.test",
              "canonicalUrl": "https://example.test/dashboard"
            }
          ]
        }
        """.strip(),
        encoding="utf-8",
    )

    claim = FileJobSource(str(jobs_path)).claim("worker-1", 1, 60000)

    assert len(claim.work) == 1
    job = claim.work[0]
    assert job["networkArtifactId"] == "artifact-2"
    assert job["host"] == "example.test"
    assert job["canonicalUrl"] == "https://example.test/dashboard"
