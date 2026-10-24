from argusloom.config import Settings


def test_settings_loads_defaults() -> None:
    settings = Settings()

    assert settings.app_name == "argusloom"
    assert settings.argus_use_mock_llm is True
    assert settings.argus_use_mock_nvd is True
    assert settings.log_level == "INFO"
