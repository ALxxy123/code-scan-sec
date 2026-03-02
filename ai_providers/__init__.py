"""AI Providers for Security Scanner."""

from .base_provider import BaseAIProvider
from .gemini_provider import GeminiProvider
from .openai_provider import OpenAIProvider
from .claude_provider import ClaudeProvider
from .huggingface_provider import HuggingFaceProvider, get_available_models

__all__ = [
    "BaseAIProvider",
    "GeminiProvider", 
    "OpenAIProvider",
    "ClaudeProvider",
    "HuggingFaceProvider",
    "get_available_models",
]

# Provider registry
PROVIDERS = {
    "gemini": GeminiProvider,
    "openai": OpenAIProvider,
    "claude": ClaudeProvider,
    "anthropic": ClaudeProvider,
    "huggingface": HuggingFaceProvider,
    "hf": HuggingFaceProvider,
}

def get_provider(name: str):
    """Get AI provider by name."""
    provider_class = PROVIDERS.get(name.lower())
    if provider_class:
        return provider_class()
    return None
