import fingerprint_tls


def test_jarm_runtime_error_includes_import_reason(monkeypatch):
    monkeypatch.setattr(fingerprint_tls, "jarm_scanner", None)
    monkeypatch.setattr(
        fingerprint_tls,
        "_JARM_IMPORT_ERROR",
        "ModuleNotFoundError: No module named 'jarm'",
    )
    error = fingerprint_tls.jarm_runtime_error()
    assert (
        error
        == "jarm_module_unavailable: ModuleNotFoundError: No module named 'jarm'"
    )


def test_compute_jarm_uses_scanner_scan(monkeypatch):
    class DummyScanner:
        @staticmethod
        def scan(**kwargs):
            assert kwargs["dest_host"] == "example.org"
            assert kwargs["dest_port"] == 443
            assert kwargs["timeout"] == 8
            assert kwargs["suppress"] is True
            return ("abc123", "example.org", 443)

    monkeypatch.setattr(fingerprint_tls, "jarm_scanner", DummyScanner())
    monkeypatch.setattr(fingerprint_tls, "_JARM_IMPORT_ERROR", None)
    value, error = fingerprint_tls.compute_jarm("example.org", 443, 8000)
    assert value == "abc123"
    assert error is None


def test_compute_jarm_reports_unsupported_scanner(monkeypatch):
    class DummyScanner:
        __name__ = "DummyScanner"

    monkeypatch.setattr(fingerprint_tls, "jarm_scanner", DummyScanner())
    monkeypatch.setattr(fingerprint_tls, "_JARM_IMPORT_ERROR", None)
    monkeypatch.setattr(fingerprint_tls, "_JARM_SCANNER_PATH", "/tmp/dummy_scanner.py")
    value, error = fingerprint_tls.compute_jarm("example.org", 443, 8000)
    assert value is None
    assert error == "jarm_api_unavailable: scanner=/tmp/dummy_scanner.py"


def test_compute_jarm_reports_scan_exception(monkeypatch):
    class DummyScanner:
        @staticmethod
        def scan(**kwargs):
            del kwargs
            raise TimeoutError("timed out")

    monkeypatch.setattr(fingerprint_tls, "jarm_scanner", DummyScanner())
    monkeypatch.setattr(fingerprint_tls, "_JARM_IMPORT_ERROR", None)
    value, error = fingerprint_tls.compute_jarm("example.org", 443, 8000)
    assert value is None
    assert error == "jarm_scan_error: TimeoutError: timed out"


def test_load_asn_db_requires_path():
    db, error = fingerprint_tls.load_asn_db(None)
    assert db is None
    assert error == "asn_db_path_missing"


def test_load_asn_db_reports_missing_file(monkeypatch, tmp_path):
    monkeypatch.setattr(fingerprint_tls, "pyasn", object())
    missing_path = str(tmp_path / "missing-asn.dat")
    db, error = fingerprint_tls.load_asn_db(missing_path)
    assert db is None
    assert error == f"asn_db_not_found: {missing_path}"


def test_load_asn_db_reports_import_error(monkeypatch):
    monkeypatch.setattr(fingerprint_tls, "pyasn", None)
    monkeypatch.setattr(
        fingerprint_tls,
        "_PYASN_IMPORT_ERROR",
        "ModuleNotFoundError: No module named 'pyasn'",
    )
    db, error = fingerprint_tls.load_asn_db("/tmp/asn.dat")
    assert db is None
    assert (
        error == "asn_module_unavailable: ModuleNotFoundError: No module named 'pyasn'"
    )
