"""
Docstring for kai.clients
"""

from typing import Any

from dotenv import load_dotenv

from kai.clients.base_lm import BaseLM
from kai.core.types import ClientBackend

load_dotenv()


def get_client(
    backend: ClientBackend,
    backend_kwargs: dict[str, Any],
) -> BaseLM:
    """
    Routes a specific backend and the args (as a dict) to the appropriate client if supported.
    Currently supported backends: ['openai']
    """
    if backend == "openai":
        from kai.clients.openai import OpenAIClient

        return OpenAIClient(**backend_kwargs)
    elif backend == "vllm":
        from kai.clients.openai import OpenAIClient

        assert "base_url" in backend_kwargs, (
            "base_url is required to be set to local vLLM server address for vLLM"
        )
        return OpenAIClient(**backend_kwargs)
    elif backend == "portkey":
        from kai.clients.portkey import PortkeyClient

        return PortkeyClient(**backend_kwargs)
    elif backend == "openrouter":
        from kai.clients.openai import OpenAIClient

        backend_kwargs.setdefault("base_url", "https://openrouter.ai/api/v1")
        return OpenAIClient(**backend_kwargs)
    elif backend == "vercel":
        from kai.clients.openai import OpenAIClient

        backend_kwargs.setdefault("base_url", "https://ai-gateway.vercel.sh/v1")
        return OpenAIClient(**backend_kwargs)
    elif backend == "litellm":
        from kai.clients.litellm import LiteLLMClient

        return LiteLLMClient(**backend_kwargs)
    elif backend == "anthropic":
        from kai.clients.anthropic import AnthropicClient

        return AnthropicClient(**backend_kwargs)
    elif backend == "gemini":
        from kai.clients.gemini import GeminiClient

        return GeminiClient(**backend_kwargs)
    elif backend == "azure_openai":
        from kai.clients.azure_openai import AzureOpenAIClient

        return AzureOpenAIClient(**backend_kwargs)
    else:
        raise ValueError(
            f"Unknown backend: {backend}. Supported backends: ['openai', 'vllm', 'portkey', 'openrouter', 'litellm', 'anthropic', 'azure_openai', 'gemini', 'vercel']"
        )
