"""Abstract LLM provider interface and deterministic mock implementation."""

from __future__ import annotations

from abc import ABC, abstractmethod

from argusloom.config import Settings


class LLMProvider(ABC):
    @abstractmethod
    def complete(
        self,
        prompt: str,
        *,
        system: str | None = None,
        few_shot: list[tuple[str, str]] | None = None,
    ) -> str:
        raise NotImplementedError


class MockLLMProvider(LLMProvider):
    """Deterministic offline provider for tests and local demos."""

    def complete(
        self,
        prompt: str,
        *,
        system: str | None = None,
        few_shot: list[tuple[str, str]] | None = None,
    ) -> str:
        text = (prompt or "").lower()
        if "network" in text or "ingress" in text:
            return "Network exposure is the main risk: enforce ingress controls, TLS, and workload isolation."
        if "iam" in text or "privilege" in text:
            return "Privilege boundaries are too broad: reduce IAM scope and separate duties across identity roles."
        if "database" in text or "data" in text or "encryption" in text:
            return "Protect the data plane with encryption, least privilege, and controlled access paths."
        if system:
            return (
                f"{system}: prioritize exposure reduction and least-privilege controls."
            )
        return (
            "Prioritize exposure reduction, least privilege, and resilience controls."
        )


class OpenAIProvider(LLMProvider):
    """Optional real provider; kept intentionally unavailable unless the dependency is installed."""

    def complete(
        self,
        prompt: str,
        *,
        system: str | None = None,
        few_shot: list[tuple[str, str]] | None = None,
    ) -> str:
        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover - dependency is optional
            raise ImportError(
                "OpenAIProvider requires the optional dependency 'openai'. "
                "Install it explicitly to enable live LLM completions."
            ) from exc

        _ = OpenAI
        raise NotImplementedError(
            "OpenAIProvider is intentionally unavailable in this workspace configuration."
        )


def get_llm_provider(settings: Settings) -> LLMProvider:
    enabled = getattr(settings, "use_mock_llm", None)
    if enabled is None:
        enabled = getattr(settings, "argus_use_mock_llm", True)
    if bool(enabled):
        return MockLLMProvider()
    return OpenAIProvider()
