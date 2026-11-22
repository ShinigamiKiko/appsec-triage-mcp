"""Build the client for the single configured model endpoint."""

from __future__ import annotations

from ..config import ProviderConfig
from .base import LLMClient
from .openai_compatible import OpenAICompatibleClient


def build_client(cfg: ProviderConfig) -> LLMClient:
    return OpenAICompatibleClient(cfg)
