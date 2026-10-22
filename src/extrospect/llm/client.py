"""LLM access for Engine mode: litellm behind a small interface.

* one place for retries (exponential backoff), refusals, prompt caching, usage/cost
  accounting and JSONL tracing;
* conversations are append-only (assistant messages are re-sent exactly as returned,
  including thinking blocks) so provider-side caching and thinking stay valid;
* the backend is pluggable: :class:`LiteLLMBackend` for real models, and
  :class:`extrospect.llm.fake.ScriptedBackend` for tests and dry runs (zero tokens).
"""

from __future__ import annotations

import copy
import json
import random
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from extrospect.config import LlmConfig, LlmModelConfig
from extrospect.models import LlmUsage
from extrospect.trace import Tracer


class LlmUnavailable(RuntimeError):
    """Engine mode cannot run: litellm missing, no API key, or authentication failed."""


class LlmCallError(RuntimeError):
    """A model call failed after retries."""


class BudgetExceeded(RuntimeError):
    """The cost budget for this analysis is exhausted."""


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]
    raw_arguments: str = ""
    parse_error: str | None = None


@dataclass
class LLMResponse:
    text: str
    tool_calls: list[ToolCall]
    finish_reason: str
    usage: LlmUsage
    model: str
    latency_ms: int
    message: dict[str, Any]  # assistant message to append to the conversation
    refused: bool = False


@dataclass
class RawResult:
    """What a backend returns before accounting/tracing."""

    text: str
    tool_calls: list[ToolCall]
    finish_reason: str
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    cost_usd: float | None = None
    message: dict[str, Any] = field(default_factory=dict)
    model: str = ""


class LlmBackend(Protocol):
    def complete(
        self,
        model_cfg: LlmModelConfig,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        timeout: float,
    ) -> RawResult: ...

    def check(self, model: str) -> None:
        """Raise LlmUnavailable when the model cannot be used (missing package/key)."""


# --------------------------------------------------------------------------- helpers


def is_anthropic_model(model: str) -> bool:
    lowered = model.lower()
    return "claude" in lowered and not lowered.startswith(("openrouter/", "ollama/"))


def parse_arguments(raw: Any) -> tuple[dict[str, Any], str | None]:
    if isinstance(raw, dict):
        return raw, None
    text = str(raw or "").strip()
    if not text:
        return {}, None
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        return {}, f"invalid JSON arguments: {exc}"
    return (value, None) if isinstance(value, dict) else ({}, "arguments must be a JSON object")


def with_cache_control(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Mark the system prompt and the first user message as cache breakpoints (copy)."""
    marked = copy.deepcopy(messages)
    breakpoints = 0
    for message in marked:
        if breakpoints >= 2:
            break
        if message.get("role") not in {"system", "user"}:
            continue
        content = message.get("content")
        if isinstance(content, str):
            message["content"] = [
                {"type": "text", "text": content, "cache_control": {"type": "ephemeral"}}
            ]
            breakpoints += 1
        elif isinstance(content, list) and content and isinstance(content[-1], dict):
            content[-1]["cache_control"] = {"type": "ephemeral"}
            breakpoints += 1
        if message.get("role") == "user":
            break
    return marked


def estimate_cost(usage: LlmUsage, model: str, cfg: LlmConfig) -> float:
    base = model.split("/", 1)[-1]
    price = cfg.pricing.get(base) or cfg.pricing.get(model)
    if price is None:
        return 0.0
    uncached = max(0, usage.input_tokens - usage.cache_read_tokens - usage.cache_write_tokens)
    cost = uncached * price.input + usage.output_tokens * price.output
    cost += usage.cache_read_tokens * (
        price.cache_read if price.cache_read is not None else price.input
    )
    cost += usage.cache_write_tokens * (
        price.cache_write if price.cache_write is not None else price.input
    )
    return cost / 1_000_000


# --------------------------------------------------------------------------- litellm backend


class LiteLLMBackend:
    def __init__(self) -> None:
        try:
            import litellm
        except ImportError as exc:  # pragma: no cover - depends on the environment
            raise LlmUnavailable("litellm is not installed: pip install 'extrospect[llm]'") from exc
        litellm.suppress_debug_info = True
        self.litellm = litellm

    def check(self, model: str) -> None:
        try:
            env = self.litellm.validate_environment(model=model)
        except Exception:
            return
        if isinstance(env, dict) and not env.get("keys_in_environment", True):
            missing = ", ".join(env.get("missing_keys") or []) or "API key"
            raise LlmUnavailable(f"{model}: missing {missing} (Engine mode is BYOK)")

    def complete(
        self,
        model_cfg: LlmModelConfig,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        timeout: float,
    ) -> RawResult:
        kwargs: dict[str, Any] = {
            "model": model_cfg.model,
            "messages": messages,
            "max_tokens": model_cfg.max_tokens,
            "timeout": timeout,
            "drop_params": True,
        }
        if model_cfg.temperature is not None:
            kwargs["temperature"] = model_cfg.temperature
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        kwargs.update(model_cfg.extra_params)
        response = self.litellm.completion(**kwargs)
        choice = response.choices[0]
        message = choice.message
        tool_calls: list[ToolCall] = []
        for call in getattr(message, "tool_calls", None) or []:
            function = call.function
            arguments, error = parse_arguments(function.arguments)
            tool_calls.append(
                ToolCall(
                    id=str(call.id or f"call_{len(tool_calls)}"),
                    name=str(function.name),
                    arguments=arguments,
                    raw_arguments=str(function.arguments or ""),
                    parse_error=error,
                )
            )
        usage = getattr(response, "usage", None)
        input_tokens = int(getattr(usage, "prompt_tokens", 0) or 0)
        output_tokens = int(getattr(usage, "completion_tokens", 0) or 0)
        cache_read = int(getattr(usage, "cache_read_input_tokens", 0) or 0)
        details = getattr(usage, "prompt_tokens_details", None)
        if not cache_read and details is not None:
            cache_read = int(getattr(details, "cached_tokens", 0) or 0)
        cache_write = int(getattr(usage, "cache_creation_input_tokens", 0) or 0)
        try:
            cost = float(self.litellm.completion_cost(completion_response=response))
        except Exception:
            cost = None
        dumped = (
            message.model_dump(exclude_none=True)
            if hasattr(message, "model_dump")
            else dict(message)
        )
        dumped.pop("provider_specific_fields", None)
        dumped["role"] = "assistant"
        dumped["content"] = message.content
        text = message.content if isinstance(message.content, str) else ""
        return RawResult(
            text=text or "",
            tool_calls=tool_calls,
            finish_reason=str(choice.finish_reason or "stop"),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read_tokens=cache_read,
            cache_write_tokens=cache_write,
            cost_usd=cost,
            message=dumped,
            model=str(getattr(response, "model", model_cfg.model) or model_cfg.model),
        )


def _is_retryable(exc: Exception) -> bool:
    name = type(exc).__name__
    if name in {
        "AuthenticationError",
        "BadRequestError",
        "NotFoundError",
        "PermissionDeniedError",
        "ContextWindowExceededError",
        "ContentPolicyViolationError",
        "UnsupportedParamsError",
    }:
        return False
    if name in {
        "RateLimitError",
        "APIConnectionError",
        "Timeout",
        "InternalServerError",
        "ServiceUnavailableError",
        "APIError",
        "TimeoutError",
        "ConnectionError",
    }:
        return True
    status = getattr(exc, "status_code", None)
    return isinstance(status, int) and (status == 429 or status >= 500)


def _is_auth_error(exc: Exception) -> bool:
    return type(exc).__name__ in {"AuthenticationError", "PermissionDeniedError"}


# --------------------------------------------------------------------------- client


class LLMClient:
    """Role-based access to the configured models with accounting and tracing."""

    def __init__(
        self,
        cfg: LlmConfig,
        tracer: Tracer | None = None,
        backend: LlmBackend | None = None,
        max_cost_usd: float | None = None,
    ) -> None:
        self.cfg = cfg
        self.tracer = tracer
        self.backend: LlmBackend = backend or LiteLLMBackend()
        self.usage = LlmUsage()
        self.max_cost_usd = max_cost_usd
        self._checked: set[str] = set()

    def model_for(self, role: str) -> LlmModelConfig:
        model_cfg = getattr(self.cfg, role, None)
        if not isinstance(model_cfg, LlmModelConfig):
            raise ValueError(f"unknown LLM role: {role}")
        return model_cfg

    def ensure_available(self, role: str) -> None:
        model = self.model_for(role).model
        if model not in self._checked:
            self.backend.check(model)
            self._checked.add(model)

    def remaining_budget(self) -> float | None:
        if self.max_cost_usd is None:
            return None
        return self.max_cost_usd - self.usage.cost_usd

    def complete(
        self,
        role: str,
        messages: list[dict[str, Any]],
        *,
        tools: list[dict[str, Any]] | None = None,
        span: str,
        prompt_version: str,
        model_override: str | None = None,
    ) -> LLMResponse:
        model_cfg = self.model_for(role)
        if model_override:
            model_cfg = model_cfg.model_copy(update={"model": model_override})
        remaining = self.remaining_budget()
        if remaining is not None and remaining <= 0:
            raise BudgetExceeded(f"cost budget ${self.max_cost_usd:.2f} exhausted")
        self.ensure_available(role) if not model_override else None
        request = (
            with_cache_control(messages)
            if self.cfg.prompt_caching and is_anthropic_model(model_cfg.model)
            else messages
        )

        attempt = 0
        started = time.perf_counter()
        while True:
            try:
                raw = self.backend.complete(model_cfg, request, tools, self.cfg.timeout_s)
                break
            except LlmUnavailable:
                raise
            except Exception as exc:
                if _is_auth_error(exc):
                    raise LlmUnavailable(
                        f"{model_cfg.model}: authentication failed ({type(exc).__name__})"
                    ) from exc
                if attempt >= self.cfg.max_retries or not _is_retryable(exc):
                    self._trace_error(span, model_cfg.model, prompt_version, request, exc, started)
                    raise LlmCallError(
                        f"{model_cfg.model}: {type(exc).__name__}: {str(exc)[:300]}"
                    ) from exc
                delay = min(30.0, 1.5 * (2**attempt)) * (0.75 + random.random() / 2)
                attempt += 1
                time.sleep(delay)
        latency = int((time.perf_counter() - started) * 1000)

        usage = LlmUsage(
            input_tokens=raw.input_tokens,
            output_tokens=raw.output_tokens,
            cache_read_tokens=raw.cache_read_tokens,
            cache_write_tokens=raw.cache_write_tokens,
            calls=1,
        )
        usage.cost_usd = (
            raw.cost_usd
            if raw.cost_usd is not None
            else estimate_cost(usage, model_cfg.model, self.cfg)
        )
        self.usage.add(usage)
        refused = raw.finish_reason in {"content_filter", "refusal"}
        if self.tracer is not None:
            self.tracer.llm_call(
                span=span,
                model=raw.model or model_cfg.model,
                prompt_version=prompt_version,
                messages=messages,
                response=raw.message or {"content": raw.text},
                usage=usage.model_dump(),
                latency_ms=latency,
                finish_reason=raw.finish_reason,
            )
        response = LLMResponse(
            text=raw.text,
            tool_calls=raw.tool_calls,
            finish_reason=raw.finish_reason,
            usage=usage,
            model=raw.model or model_cfg.model,
            latency_ms=latency,
            message=raw.message or {"role": "assistant", "content": raw.text},
            refused=refused,
        )
        if refused and self.cfg.refusal_fallback_model and not model_override:
            return self.complete(
                role,
                messages,
                tools=tools,
                span=f"{span}:fallback",
                prompt_version=prompt_version,
                model_override=self.cfg.refusal_fallback_model,
            )
        return response

    def _trace_error(
        self,
        span: str,
        model: str,
        prompt_version: str,
        messages: list[dict[str, Any]],
        exc: Exception,
        started: float,
    ) -> None:
        if self.tracer is None:
            return
        self.tracer.llm_call(
            span=span,
            model=model,
            prompt_version=prompt_version,
            messages=messages,
            response={},
            usage={},
            latency_ms=int((time.perf_counter() - started) * 1000),
            finish_reason="error",
            error=f"{type(exc).__name__}: {str(exc)[:300]}",
        )


__all__ = [
    "BudgetExceeded",
    "LLMClient",
    "LLMResponse",
    "LiteLLMBackend",
    "LlmBackend",
    "LlmCallError",
    "LlmUnavailable",
    "RawResult",
    "ToolCall",
    "estimate_cost",
    "is_anthropic_model",
    "parse_arguments",
    "with_cache_control",
]
