from argusloom.config import Settings
from argusloom.rag.llm import MockLLMProvider, get_llm_provider


def test_mock_llm_is_deterministic() -> None:
    provider = MockLLMProvider()

    first = provider.complete("network exposure")
    second = provider.complete("network exposure")

    assert first == second
    assert isinstance(first, str)


def test_mock_llm_responds_to_network_keyword() -> None:
    provider = MockLLMProvider()

    response = provider.complete("network attack surface")

    assert "network" in response.lower()


def test_get_llm_provider_returns_mock_when_enabled() -> None:
    settings = Settings(argus_use_mock_llm=True)

    provider = get_llm_provider(settings)

    assert isinstance(provider, MockLLMProvider)
