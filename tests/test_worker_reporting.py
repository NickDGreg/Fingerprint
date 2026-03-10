from worker import build_config, run_worker
from worker_io import JobClaim


class SingleBatchJobSource:
    def __init__(self, jobs):
        self._jobs = jobs
        self._claimed = False

    def claim(self, worker_id, limit, lease_duration_ms):
        del worker_id, limit, lease_duration_ms
        if self._claimed:
            return JobClaim([], None)
        self._claimed = True
        return JobClaim(self._jobs, None)


class ControlledSink:
    def __init__(
        self,
        fail_names=None,
        fail_once_names=None,
        report_result_response=None,
    ):
        self.records = []
        self._counts = {}
        self._fail_names = fail_names or set()
        self._fail_once_names = fail_once_names or set()
        self._report_result_response = report_result_response

    def mutation(self, name, payload):
        self.records.append({"name": name, "payload": payload})
        self._counts[name] = self._counts.get(name, 0) + 1
        if name in self._fail_names:
            raise Exception(f"forced failure: {name}")
        if name in self._fail_once_names and self._counts[name] == 1:
            raise Exception(f"forced first failure: {name}")
        if (
            name == "fingerprints:reportResult"
            and self._report_result_response is not None
        ):
            return self._report_result_response
        return None

    def close(self):
        return None


def _records_by_name(records):
    grouped = {}
    for record in records:
        grouped.setdefault(record["name"], []).append(record["payload"])
    return grouped


def _build_config(batch_size):
    env = {
        "WORKER_MAX_LOOPS": "1",
        "WORKER_BATCH_SIZE": str(batch_size),
        "FINGERPRINT_DISABLE_TLS": "1",
        "FINGERPRINT_DISABLE_JARM": "1",
    }
    return build_config(env)


def _job(run_id="run-1", domain_id="domain-1", host="example.test"):
    return {
        "runId": run_id,
        "domainId": domain_id,
        "host": host,
        "url": f"https://{host}",
    }


def _mock_http_ok(url, *args, **kwargs):
    del args, kwargs
    body = b"<html><head></head><body>ok</body></html>"
    return {
        "ok": True,
        "status": 200,
        "requested_url": url,
        "final_url": url,
        "headers": [],
        "headers_truncated": False,
        "redirect_chain": [],
        "content_type": "text/html",
        "content_length": len(body),
        "server": "test",
        "powered_by": None,
        "set_cookie": [],
        "duration_ms": 1,
        "body_bytes": body,
        "body_truncated": False,
        "encoding": "utf-8",
    }


def _mock_http_unreachable(url, *args, **kwargs):
    del args, kwargs
    return {
        "ok": False,
        "requested_url": url,
        "error_type": "connection_error",
        "error_detail": "connection refused",
        "duration_ms": 1,
    }


def _mock_binary_ok(url, *args, **kwargs):
    del args, kwargs
    return {
        "ok": True,
        "status": 200,
        "final_url": url,
        "content_type": "application/octet-stream",
        "content_length": 0,
        "body_bytes": b"",
        "body_truncated": False,
        "duration_ms": 1,
    }


def test_http_content_reports_success(monkeypatch):
    monkeypatch.setattr("worker.fetch_http", _mock_http_ok)
    monkeypatch.setattr("worker.fetch_binary", _mock_binary_ok)
    sink = ControlledSink()
    run_worker(
        _build_config(batch_size=1),
        SingleBatchJobSource([_job()]),
        sink,
        install_signal_handlers=False,
    )
    grouped = _records_by_name(sink.records)
    report_payload = grouped["fingerprints:reportResult"][0]
    assert report_payload["status"] == "success"
    assert report_payload["outcome"]["kind"] == "http_content"


def test_unreachable_reports_unreachable(monkeypatch):
    monkeypatch.setattr("worker.fetch_http", _mock_http_unreachable)
    monkeypatch.setattr("worker.fetch_binary", _mock_binary_ok)
    sink = ControlledSink()
    run_worker(
        _build_config(batch_size=1),
        SingleBatchJobSource([_job()]),
        sink,
        install_signal_handlers=False,
    )
    grouped = _records_by_name(sink.records)
    report_payload = grouped["fingerprints:reportResult"][0]
    assert report_payload["status"] == "unreachable"
    assert report_payload["outcome"]["kind"] == "unreachable"


def test_stage_failure_records_issue_and_marks_run_error(monkeypatch):
    monkeypatch.setattr("worker.fetch_http", _mock_http_ok)
    monkeypatch.setattr("worker.fetch_binary", _mock_binary_ok)
    sink = ControlledSink(fail_once_names={"fingerprints:upsertAssetsFingerprint"})
    run_worker(
        _build_config(batch_size=1),
        SingleBatchJobSource([_job()]),
        sink,
        install_signal_handlers=False,
    )
    grouped = _records_by_name(sink.records)
    report_payload = grouped["fingerprints:reportResult"][0]
    assert report_payload["status"] == "error"
    issue_payloads = grouped["fingerprints:recordRunIssue"]
    assert any(
        payload["stage"] == "upsert_assets" and payload["code"] == "mutation_exception"
        for payload in issue_payloads
    )


def test_report_result_exception_records_issue(monkeypatch):
    monkeypatch.setattr("worker.fetch_http", _mock_http_ok)
    monkeypatch.setattr("worker.fetch_binary", _mock_binary_ok)
    sink = ControlledSink(fail_names={"fingerprints:reportResult"})
    run_worker(
        _build_config(batch_size=1),
        SingleBatchJobSource([_job()]),
        sink,
        install_signal_handlers=False,
    )
    grouped = _records_by_name(sink.records)
    issue_payloads = grouped["fingerprints:recordRunIssue"]
    assert any(
        payload["stage"] == "report_result"
        and payload["code"] == "report_result_exception"
        for payload in issue_payloads
    )


def test_report_result_rejection_records_issue(monkeypatch):
    monkeypatch.setattr("worker.fetch_http", _mock_http_ok)
    monkeypatch.setattr("worker.fetch_binary", _mock_binary_ok)
    sink = ControlledSink(report_result_response={"ok": False, "reason": "stale_run"})
    run_worker(
        _build_config(batch_size=1),
        SingleBatchJobSource([_job()]),
        sink,
        install_signal_handlers=False,
    )
    grouped = _records_by_name(sink.records)
    issue_payloads = grouped["fingerprints:recordRunIssue"]
    assert any(
        payload["stage"] == "report_result"
        and payload["code"] == "report_result_rejected"
        and "stale_run" in payload.get("detail", "")
        for payload in issue_payloads
    )


def test_loop_continues_after_stage_failure(monkeypatch):
    monkeypatch.setattr("worker.fetch_http", _mock_http_ok)
    monkeypatch.setattr("worker.fetch_binary", _mock_binary_ok)
    jobs = [
        _job(run_id="run-1", domain_id="domain-1", host="one.example"),
        _job(run_id="run-2", domain_id="domain-2", host="two.example"),
    ]
    sink = ControlledSink(fail_once_names={"fingerprints:upsertHttpFingerprint"})
    run_worker(
        _build_config(batch_size=2),
        SingleBatchJobSource(jobs),
        sink,
        install_signal_handlers=False,
    )
    grouped = _records_by_name(sink.records)
    report_payloads = grouped["fingerprints:reportResult"]
    assert len(report_payloads) == 2
    status_by_run = {payload["runId"]: payload["status"] for payload in report_payloads}
    assert status_by_run["run-1"] == "error"
    assert status_by_run["run-2"] == "success"
