from worker import build_config


def test_build_config_defaults_to_production_logging():
    config = build_config({})

    assert config.worker_environment == "production"
    assert config.log_level == "INFO"
    assert config.log_http_details is False


def test_build_config_defaults_to_development_logging():
    config = build_config({"WORKER_ENV": "dev"})

    assert config.worker_environment == "development"
    assert config.log_level == "DEBUG"
    assert config.log_http_details is True


def test_build_config_invalid_log_level_falls_back_to_default():
    config = build_config({"WORKER_ENV": "production", "WORKER_LOG_LEVEL": "TRACE"})

    assert config.log_level == "INFO"
