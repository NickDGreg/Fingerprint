import fingerprint_tls


def test_jarm_runtime_error_includes_import_reason(monkeypatch):
    monkeypatch.setattr(fingerprint_tls, "jarm", None)
    monkeypatch.setattr(
        fingerprint_tls,
        "_JARM_IMPORT_ERROR",
        "ModuleNotFoundError: No module named 'colorama'",
    )
    error = fingerprint_tls.jarm_runtime_error()
    assert (
        error
        == "jarm_module_unavailable: ModuleNotFoundError: No module named 'colorama'"
    )


def test_compute_jarm_reports_unsupported_module(monkeypatch):
    class DummyJarmModule:
        __file__ = "/tmp/dummy_jarm.py"

    monkeypatch.setattr(fingerprint_tls, "jarm", DummyJarmModule())
    monkeypatch.setattr(fingerprint_tls, "_JARM_IMPORT_ERROR", None)
    value, error = fingerprint_tls.compute_jarm("example.org", 443, 8000)
    assert value is None
    assert error == "jarm_api_unavailable: module=/tmp/dummy_jarm.py"


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
