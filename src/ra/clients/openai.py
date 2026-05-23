import asyncio
import json
import logging
import os
import random
import time
from collections import defaultdict
from typing import Any

import httpx
import openai
from dotenv import load_dotenv
from openai.types.chat import ChatCompletion

from ra.clients.base_lm import BaseLM
from ra.core.types import ModelUsageSummary, UsageSummary

load_dotenv()

_log = logging.getLogger(__name__)

# Exceptions that warrant a retry. Network blips, malformed payloads from
# the proxy (we saw OpenRouter return a body that failed JSON parsing on
# cybergym R18 arvo:48736 — a single LLM call burned the task), rate
# limits, and 5xx errors are all transient. Hard 4xx errors (auth, bad
# request, model-not-found) are NOT retried.
_RETRYABLE_EXCEPTIONS: tuple[type[BaseException], ...] = (
    json.JSONDecodeError,
    openai.APIConnectionError,
    openai.APITimeoutError,
    openai.RateLimitError,
    openai.InternalServerError,
    httpx.RequestError,
    httpx.RemoteProtocolError,
    httpx.ReadError,
)

# Status codes (when an APIStatusError surfaces) that should be retried.
# 429 is rate-limit; 5xx are server-side blips.
_RETRYABLE_STATUS_CODES: frozenset[int] = frozenset({429, 500, 502, 503, 504})

_DEFAULT_MAX_RETRIES = int(os.environ.get("KAI_LLM_MAX_RETRIES", "4"))
_DEFAULT_BASE_BACKOFF_S = float(os.environ.get("KAI_LLM_BACKOFF_S", "1.5"))


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, _RETRYABLE_EXCEPTIONS):
        return True
    if isinstance(exc, openai.APIStatusError):
        status = getattr(exc, "status_code", None)
        if isinstance(status, int) and status in _RETRYABLE_STATUS_CODES:
            return True
    return False


def _sleep_for_retry(attempt: int) -> float:
    """Exponential backoff with jitter; attempt is 1-indexed."""
    base = _DEFAULT_BASE_BACKOFF_S * (2 ** (attempt - 1))
    jitter = random.uniform(0, base * 0.25)
    return base + jitter


def _call_with_retry(call_fn, *, model: str, log_prefix: str) -> Any:  # type: ignore[no-untyped-def]
    """Call ``call_fn`` synchronously with retry on transient errors."""
    attempt = 0
    last_exc: BaseException | None = None
    while attempt < _DEFAULT_MAX_RETRIES:
        attempt += 1
        try:
            return call_fn()
        except BaseException as exc:
            last_exc = exc
            if not _is_retryable(exc):
                raise
            if attempt >= _DEFAULT_MAX_RETRIES:
                break
            delay = _sleep_for_retry(attempt)
            _log.warning(
                "%s transient LLM failure (%s) on attempt %d/%d; "
                "retrying in %.1fs (model=%s)",
                log_prefix,
                type(exc).__name__,
                attempt,
                _DEFAULT_MAX_RETRIES,
                delay,
                model,
            )
            time.sleep(delay)
    assert last_exc is not None
    raise last_exc


async def _acall_with_retry(coro_factory, *, model: str, log_prefix: str) -> Any:  # type: ignore[no-untyped-def]
    """Async variant of ``_call_with_retry``."""
    attempt = 0
    last_exc: BaseException | None = None
    while attempt < _DEFAULT_MAX_RETRIES:
        attempt += 1
        try:
            return await coro_factory()
        except BaseException as exc:
            last_exc = exc
            if not _is_retryable(exc):
                raise
            if attempt >= _DEFAULT_MAX_RETRIES:
                break
            delay = _sleep_for_retry(attempt)
            _log.warning(
                "%s transient LLM failure (%s) on attempt %d/%d; "
                "retrying in %.1fs (model=%s)",
                log_prefix,
                type(exc).__name__,
                attempt,
                _DEFAULT_MAX_RETRIES,
                delay,
                model,
            )
            await asyncio.sleep(delay)
    assert last_exc is not None
    raise last_exc


def _extract_text(response: Any) -> str:
    """Pull the message text out of a chat-completions response, raising
    a retryable error when the payload is structurally bad."""
    try:
        choices = response.choices
    except AttributeError as exc:
        raise openai.APIError(
            "response has no .choices field", request=None, body=None
        ) from exc
    if not choices:
        raise openai.APIError("response.choices is empty", request=None, body=None)
    content = getattr(choices[0].message, "content", None)
    if content is None or content == "":
        raise openai.APIError(
            "response.choices[0].message.content is empty",
            request=None,
            body=None,
        )
    return content


# Load API keys from environment variables
DEFAULT_OPENAI_API_KEY = os.getenv("OPENAI_API_KEY") or os.getenv("OPEN_AI_API_KEY")
DEFAULT_OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
DEFAULT_VERCEL_API_KEY = os.getenv("AI_GATEWAY_API_KEY")
DEFAULT_PRIME_INTELLECT_BASE_URL = "https://api.pinference.ai/api/v1/"

OPENROUTER_APP_URL = os.getenv(
    "OPENROUTER_APP_URL",
    "https://kai.dria.co/",
)
OPENROUTER_APP_TITLE = os.getenv("OPENROUTER_APP_TITLE", "kai-security")
OPENROUTER_APP_CATEGORIES = os.getenv(
    "OPENROUTER_APP_CATEGORIES",
    "cli-agent,programming-app",
)
_OPENROUTER_HEADERS = {
    "HTTP-Referer": OPENROUTER_APP_URL,
    "X-OpenRouter-Title": OPENROUTER_APP_TITLE,
}
if OPENROUTER_APP_CATEGORIES:
    _OPENROUTER_HEADERS["X-OpenRouter-Categories"] = OPENROUTER_APP_CATEGORIES


class OpenAIClient(BaseLM):
    """
    LM Client for running models with the OpenAI API. Works with vLLM as well.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model_name: str | None = None,
        base_url: str | None = None,
        **kwargs,
    ):
        super().__init__(model_name=model_name, **kwargs)

        if api_key is None:
            if base_url == "https://api.openai.com/v1" or base_url is None:
                api_key = DEFAULT_OPENAI_API_KEY
            elif base_url == "https://openrouter.ai/api/v1":
                api_key = DEFAULT_OPENROUTER_API_KEY
            elif base_url == "https://ai-gateway.vercel.sh/v1":
                api_key = DEFAULT_VERCEL_API_KEY

        # For vLLM, set base_url to local vLLM server address.
        extra_headers = (
            _OPENROUTER_HEADERS if base_url == "https://openrouter.ai/api/v1" else None
        )
        self.client = openai.OpenAI(
            api_key=api_key,
            base_url=base_url,
            default_headers=extra_headers,
        )
        self._async_client_kwargs: dict[str, Any] = {
            "api_key": api_key,
            "base_url": base_url,
            "default_headers": extra_headers,
        }
        self.model_name = model_name

        # Per-model usage tracking
        self.model_call_counts: dict[str, int] = defaultdict(int)
        self.model_input_tokens: dict[str, int] = defaultdict(int)
        self.model_output_tokens: dict[str, int] = defaultdict(int)
        self.model_total_tokens: dict[str, int] = defaultdict(int)

    def completion(
        self,
        prompt: str | list[dict[str, Any]],
        model: str | None = None,
    ) -> str:
        if isinstance(prompt, str):
            messages = [{"role": "user", "content": prompt}]
        elif isinstance(prompt, list) and all(
            isinstance(item, dict) for item in prompt
        ):
            messages = prompt
        else:
            raise ValueError(f"Invalid prompt type: {type(prompt)}")

        model = model or self.model_name
        if not model:
            raise ValueError("Model name is required for OpenAI client.")

        extra_body = self._build_extra_body()

        def _do_call() -> ChatCompletion:
            return self.client.chat.completions.create(
                model=model,
                messages=messages,  # type: ignore[arg-type]
                extra_body=extra_body,
            )

        response = _call_with_retry(
            _do_call, model=model, log_prefix="sync completion:"
        )
        self._track_cost(response, model)
        return _extract_text(response)

    async def acompletion(
        self,
        prompt: str | list[dict[str, Any]],
        model: str | None = None,
    ) -> str:
        if isinstance(prompt, str):
            messages = [{"role": "user", "content": prompt}]
        elif isinstance(prompt, list) and all(
            isinstance(item, dict) for item in prompt
        ):
            messages = prompt
        else:
            raise ValueError(f"Invalid prompt type: {type(prompt)}")

        model = model or self.model_name
        if not model:
            raise ValueError("Model name is required for OpenAI client.")

        extra_body = self._build_extra_body()

        async with openai.AsyncOpenAI(
            **self._async_client_kwargs,
        ) as client:

            async def _do_call():  # type: ignore[no-untyped-def]
                return await client.chat.completions.create(
                    model=model,
                    messages=messages,  # type: ignore[arg-type]
                    extra_body=extra_body,
                )

            response = await _acall_with_retry(
                _do_call, model=model, log_prefix="async completion:"
            )
        self._track_cost(response, model)
        return _extract_text(response)

    def _build_extra_body(self) -> dict[str, Any]:
        """Per-call ``extra_body`` for chat completions.

        Disables OpenRouter's response cache so two cybergym tasks
        with similar analyzer/researcher prompts cannot receive the
        same cached completion (cross-task contamination has been
        observed where C-target tasks received Solidity content
        from a prior EVM-bench task).
        """
        extra_body: dict[str, Any] = {}
        base_url = str(self.client.base_url or "")
        if base_url == DEFAULT_PRIME_INTELLECT_BASE_URL:
            extra_body["usage"] = {"include": True}
        if "openrouter" in base_url.lower():
            extra_body["cache"] = False
        return extra_body

    def _track_cost(self, response: ChatCompletion, model: str):
        self.model_call_counts[model] += 1

        usage = getattr(response, "usage", None)
        if usage is None:
            raise ValueError("No usage data received. Tracking tokens not possible.")

        self.model_input_tokens[model] += usage.prompt_tokens
        self.model_output_tokens[model] += usage.completion_tokens
        self.model_total_tokens[model] += usage.total_tokens

        # Track last call for handler to read
        self.last_prompt_tokens = usage.prompt_tokens
        self.last_completion_tokens = usage.completion_tokens

    def get_usage_summary(self) -> UsageSummary:
        model_summaries = {}
        for model in self.model_call_counts:
            model_summaries[model] = ModelUsageSummary(
                total_calls=self.model_call_counts[model],
                total_input_tokens=self.model_input_tokens[model],
                total_output_tokens=self.model_output_tokens[model],
            )
        return UsageSummary(model_usage_summaries=model_summaries)

    def get_last_usage(self) -> ModelUsageSummary:
        return ModelUsageSummary(
            total_calls=1,
            total_input_tokens=self.last_prompt_tokens,
            total_output_tokens=self.last_completion_tokens,
        )
