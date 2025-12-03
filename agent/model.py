from openai import AsyncOpenAI
from pydantic import BaseModel
import requests
from typing import Optional, Union, Dict, Tuple

from agent.settings import (
    OPENROUTER_API_KEY,
    OPENROUTER_BASE_URL,
    OPENROUTER_STRONG_MODEL,
    OPENAI_API_KEY,
)
from agent.schemas import ChatMessage, Role

# Cache for model pricing to avoid repeated API calls
_pricing_cache: Dict[str, Dict[str, float]] = {}


def create_openai_client(use_openai: bool = False) -> AsyncOpenAI:
    """Create a new async OpenAI client instance."""
    if use_openai:
        return AsyncOpenAI(
            api_key=OPENAI_API_KEY,
        )
    else:
        return AsyncOpenAI(
            api_key=OPENROUTER_API_KEY,
            base_url=OPENROUTER_BASE_URL,
        )


def create_vllm_client(host: str = "0.0.0.0", port: int = 8000) -> AsyncOpenAI:
    """Create a new async vLLM client instance (OpenAI-compatible)."""
    return AsyncOpenAI(
        base_url=f"http://{host}:{port}/v1",
        api_key="EMPTY",  # vLLM doesn't require a real API key
    )


def get_model_pricing(model_name: str, use_openai: bool = False) -> Dict[str, float]:
    """
    Get pricing for a model from OpenRouter or use defaults for OpenAI.

    Returns:
        Dict with 'prompt' and 'completion' keys (cost per token in dollars)
    """
    # Check cache first
    if model_name in _pricing_cache:
        return _pricing_cache[model_name]

    if use_openai:
        # Default OpenAI pricing (approximate, will be updated dynamically)
        default_pricing = {
            "prompt": 0.00003,  # $30/1M tokens
            "completion": 0.00006,  # $60/1M tokens
        }
        _pricing_cache[model_name] = default_pricing
        return default_pricing

    # Fetch from OpenRouter API
    try:
        response = requests.get(
            "https://openrouter.ai/api/v1/models",
            headers={"Authorization": f"Bearer {OPENROUTER_API_KEY}"},
            timeout=5,
        )
        if response.status_code == 200:
            models = response.json().get("data", [])
            for model in models:
                if model.get("id") == model_name:
                    pricing = model.get("pricing", {})
                    result = {
                        "prompt": float(pricing.get("prompt", 0)),
                        "completion": float(pricing.get("completion", 0)),
                    }
                    _pricing_cache[model_name] = result
                    return result
    except Exception:
        pass  # Fall through to default

    # Default fallback pricing
    default_pricing = {
        "prompt": 0.000003,  # $3/1M tokens (reasonable default)
        "completion": 0.000015,  # $15/1M tokens
    }
    _pricing_cache[model_name] = default_pricing
    return default_pricing


def _as_dict(msg: Union[ChatMessage, dict]) -> dict:
    """
    Accept either ChatMessage or raw dict and return the raw dict.

    Args:
        msg: A ChatMessage object or a raw dict.

    Returns:
        A raw dict.
    """
    return msg if isinstance(msg, dict) else msg.model_dump()


async def get_model_response(
    messages: Optional[list[ChatMessage]] = None,
    message: Optional[str] = None,
    system_prompt: Optional[str] = None,
    model: str = OPENROUTER_STRONG_MODEL,
    client: Optional[AsyncOpenAI] = None,
    use_vllm: bool = False,
    use_openai: bool = False,
) -> Tuple[str, Dict[str, int]]:
    """
    Get a response from a model using OpenRouter or vLLM (async).

    Args:
        messages: A list of ChatMessage objects (optional).
        message: A single message string (optional).
        system_prompt: A system prompt for the model (optional).
        model: The model to use.
        client: Optional AsyncOpenAI client to use. If None, creates a new one.
        use_vllm: Whether to use vLLM backend instead of OpenRouter.
        use_openai: Whether to use OpenAI API directly.

    Returns:
        Tuple of (response_text, usage_dict) where usage_dict contains:
        - prompt_tokens: int
        - completion_tokens: int
        - total_tokens: int
    """
    if messages is None and message is None:
        raise ValueError("Either 'messages' or 'message' must be provided.")

    # Use provided client or create a new one
    if client is None:
        if use_vllm:
            client = create_vllm_client()
        else:
            client = create_openai_client(use_openai=use_openai)

    # Build message history
    if messages is None:
        messages = []
        if system_prompt:
            messages.append(
                _as_dict(ChatMessage(role=Role.SYSTEM, content=system_prompt))
            )
        messages.append(_as_dict(ChatMessage(role=Role.USER, content=message)))
    else:
        messages = [_as_dict(m) for m in messages]

    try:
        completion = await client.chat.completions.create(
            model=model, messages=messages
        )

        response_text = completion.choices[0].message.content

        # Extract usage data
        usage = completion.usage
        usage_dict = {
            "prompt_tokens": usage.prompt_tokens if usage else 0,
            "completion_tokens": usage.completion_tokens if usage else 0,
            "total_tokens": usage.total_tokens if usage else 0,
        }

        return response_text, usage_dict

    except Exception as e:
        error_msg = str(e)

        # Check if this is a context length error
        if any(
            keyword in error_msg.lower()
            for keyword in ["context length", "maximum context", "tokens"]
        ):
            # Calculate approximate token count from messages
            total_chars = sum(len(str(m)) for m in messages)
            approx_tokens = total_chars // 4  # Rough approximation

            raise Exception(
                f"Context length exceeded: approximately {approx_tokens} tokens.\n"
                f"This usually means the conversation history is too long.\n"
                f"Original error: {error_msg}"
            )
        else:
            # Re-raise the original exception
            raise
