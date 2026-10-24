from argusloom.config import Settings


def test_settings_loads_defaults() -> None:
    settings = Settings()

    assert settings.app_name == "argusloom"
    assert settings.argus_use_mock_llm is True
    assert settings.use_mock_nvd is True
    assert settings.nvd_cache_ttl_days == 7
    assert settings.nvd_api_key == ""
    assert settings.nvd_timeout_seconds == 10
    assert settings.log_level == "INFO"


def test_settings_reads_mock_nvd_environment_flag(monkeypatch) -> None:
    monkeypatch.setenv("ARGUS_USE_MOCK_NVD", "false")

    assert Settings().use_mock_nvd is False


def test_settings_accepts_legacy_mock_nvd_name() -> None:
    assert Settings(argus_use_mock_nvd=False).use_mock_nvd is False
