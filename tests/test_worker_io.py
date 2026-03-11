from worker_io import FileJobSource, normalize_job_payload


def test_normalize_job_payload_accepts_network_artifact_shape():
    job = normalize_job_payload(
        {
            "networkArtifactId": "artifact-1",
            "websiteHost": "example.test",
            "websiteUrl": "https://example.test/login",
        }
    )

    assert job["networkArtifactId"] == "artifact-1"
    assert job["websiteHost"] == "example.test"
    assert job["websiteUrl"] == "https://example.test/login"
    assert str(job["runId"]).startswith("local-run-")


def test_file_job_source_backfills_legacy_aliases_for_artifact_jobs(tmp_path):
    jobs_path = tmp_path / "jobs.json"
    jobs_path.write_text(
        """
        {
          "jobs": [
            {
              "networkArtifactId": "artifact-2",
              "websiteHost": "example.test",
              "websiteUrl": "https://example.test/dashboard"
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
    assert job["websiteHost"] == "example.test"
    assert job["websiteUrl"] == "https://example.test/dashboard"
