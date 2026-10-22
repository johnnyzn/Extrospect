"""Zero-token LLM backends for tests, demos and dry runs of the evaluation harness.

* :class:`ScriptedBackend` replays responses produced by a handler or a list.
* :class:`HeuristicBackend` imitates a cooperative model: it reads the prompts this
  package builds (slice ids, gutter-numbered code), triages slices with keyword rules,
  runs a short investigation (retrieve_listing -> submit_verdict with verbatim quotes)
  and answers consistency checks. It exercises every code path of Engine mode without
  any API key - it is *not* a detector and must never be used for real verdicts.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from extrospect.config import LlmModelConfig
from extrospect.llm.client import RawResult, ToolCall
from extrospect.util import estimate_tokens

ResponseSpec = dict[str, Any]
Handler = Callable[[str, list[dict[str, Any]], list[dict[str, Any]] | None], ResponseSpec]

_BLOCK_RE = re.compile(r'<untrusted_code id="([0-9a-f]{16})"[^>]*>\n(.*?)\n</untrusted_code>', re.S)
_GUTTER_RE = re.compile(r"^\s*(\d+) \| (.*)$")
_KEYWORDS: list[tuple[str, float, str]] = [
    (r"cookies\.getAll|document\.cookie", 0.85, "exfiltration"),
    (r"type=password|keydown|addEventListener\(\"submit\"", 0.8, "exfiltration"),
    (r"\beval\(|new Function|executeScript\(.*code", 0.8, "remote_control"),
    (r"updateDynamicRules|search_url|\.href\s*=", 0.65, "hijack"),
    (r"sendBeacon|fetch\(|XMLHttpRequest|\.open\(\"(GET|POST)", 0.35, "tracking"),
]


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(str(p.get("text", "")) for p in content if isinstance(p, dict))
    return ""


def _usage_for(messages: list[dict[str, Any]], output: str) -> tuple[int, int]:
    text = "\n".join(_content_text(m.get("content")) for m in messages)
    return estimate_tokens(text), max(1, estimate_tokens(output))


def _to_raw(spec: ResponseSpec, model: str, messages: list[dict[str, Any]]) -> RawResult:
    calls = []
    for index, call in enumerate(spec.get("tool_calls") or []):
        arguments = call.get("arguments") or {}
        calls.append(
            ToolCall(
                id=call.get("id") or f"call_{len(messages)}_{index}",
                name=call["name"],
                arguments=arguments,
                raw_arguments=json.dumps(arguments, ensure_ascii=False),
            )
        )
    text = spec.get("text") or ""
    message: dict[str, Any] = {"role": "assistant", "content": text or None}
    if calls:
        message["tool_calls"] = [
            {
                "id": c.id,
                "type": "function",
                "function": {"name": c.name, "arguments": c.raw_arguments},
            }
            for c in calls
        ]
    input_tokens, output_tokens = _usage_for(
        messages, text + "".join(c.raw_arguments for c in calls)
    )
    return RawResult(
        text=text,
        tool_calls=calls,
        finish_reason=spec.get("finish_reason") or ("tool_calls" if calls else "stop"),
        input_tokens=spec.get("input_tokens", input_tokens),
        output_tokens=spec.get("output_tokens", output_tokens),
        cost_usd=spec.get("cost_usd", 0.0),
        message=message,
        model=model,
    )


class ScriptedBackend:
    """Return pre-scripted responses. ``calls`` records (model, messages, tools)."""

    def __init__(
        self, handler: Handler | None = None, responses: list[ResponseSpec] | None = None
    ) -> None:
        self.handler = handler
        self.responses = list(responses or [])
        self.calls: list[tuple[str, list[dict[str, Any]], list[dict[str, Any]] | None]] = []

    def check(self, model: str) -> None:
        return None

    def complete(
        self,
        model_cfg: LlmModelConfig,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        timeout: float,
    ) -> RawResult:
        snapshot = json.loads(json.dumps(messages, default=str))
        self.calls.append((model_cfg.model, snapshot, tools))
        if self.handler is not None:
            spec = self.handler(model_cfg.model, snapshot, tools)
        elif self.responses:
            spec = self.responses.pop(0)
        else:
            spec = {"text": ""}
        if isinstance(spec, Exception):
            raise spec
        return _to_raw(spec, model_cfg.model, messages)


def _tool_names(tools: list[dict[str, Any]] | None) -> set[str]:
    return {t["function"]["name"] for t in tools or [] if "function" in t}


def _parse_blocks(text: str) -> dict[str, list[tuple[int, str]]]:
    blocks: dict[str, list[tuple[int, str]]] = {}
    for slice_id, body in _BLOCK_RE.findall(text):
        lines = []
        for raw in body.split("\n"):
            match = _GUTTER_RE.match(raw)
            if match:
                lines.append((int(match.group(1)), match.group(2)))
        blocks[slice_id] = lines
    return blocks


def _score(lines: list[tuple[int, str]]) -> tuple[float, str, list[int]]:
    best, category, evidence = 0.1, "benign", []
    for pattern, weight, cat in _KEYWORDS:
        hits = [n for n, code in lines if re.search(pattern, code)]
        if hits and weight > best:
            best, category, evidence = weight, cat, hits[:3]
    has_network = any(re.search(_KEYWORDS[-1][0], code) for _, code in lines)
    if category in {"exfiltration", "remote_control"} and not has_network:
        best, category = 0.45, "unclear"
    return best, category, evidence


class HeuristicBackend:
    """A deterministic stand-in for a real model (see module docstring)."""

    def __init__(self) -> None:
        self.calls = 0

    def check(self, model: str) -> None:
        return None

    def complete(
        self,
        model_cfg: LlmModelConfig,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        timeout: float,
    ) -> RawResult:
        self.calls += 1
        names = _tool_names(tools)
        first_user = next(
            (_content_text(m.get("content")) for m in messages if m.get("role") == "user"), ""
        )
        if "report_triage" in names:
            return _to_raw(self._triage(first_user), model_cfg.model, messages)
        if "report_consistency" in names:
            spec = {
                "tool_calls": [
                    {
                        "name": "report_consistency",
                        "arguments": {"consistent": True, "reason": "evidence supports the chain"},
                    }
                ]
            }
            return _to_raw(spec, model_cfg.model, messages)
        if "submit_verdict" in names:
            return _to_raw(self._investigate(first_user, messages), model_cfg.model, messages)
        if "report_listing" in names:
            spec = {
                "tool_calls": [
                    {
                        "name": "report_listing",
                        "arguments": {
                            "declared_purpose": "",
                            "data_collected": [],
                            "first_party_domains": [],
                        },
                    }
                ]
            }
            return _to_raw(spec, model_cfg.model, messages)
        return _to_raw({"text": "ok"}, model_cfg.model, messages)

    def _triage(self, text: str) -> ResponseSpec:
        results = []
        for slice_id, lines in _parse_blocks(text).items():
            suspicion, category, evidence = _score(lines)
            results.append(
                {
                    "slice_id": slice_id,
                    "behavior": f"heuristic: {category} pattern"
                    if evidence
                    else "heuristic: routine code",
                    "data_flow": "",
                    "suspicion": suspicion,
                    "evidence_lines": evidence,
                    "category": category,
                }
            )
        return {"tool_calls": [{"name": "report_triage", "arguments": {"results": results}}]}

    def _investigate(self, first_user: str, messages: list[dict[str, Any]]) -> ResponseSpec:
        called = {
            call["function"]["name"]
            for m in messages
            if m.get("role") == "assistant"
            for call in m.get("tool_calls") or []
        }
        if "retrieve_listing" not in called:
            return {"tool_calls": [{"name": "retrieve_listing", "arguments": {}}]}
        evidence = []
        best = 0.1
        file_re = re.compile(r'<untrusted_code id="([0-9a-f]{16})" file="([^"]+)"')
        files = dict(file_re.findall(first_user))
        for slice_id, lines in _parse_blocks(first_user).items():
            suspicion, category, hits = _score(lines)
            best = max(best, suspicion)
            by_line = dict(lines)
            for number in hits[:2]:
                code = by_line[number].strip()
                if code:
                    evidence.append(
                        {
                            "claim": f"{category} behaviour",
                            "file": files.get(slice_id, "?"),
                            "lines": [number, number],
                            "quote": code,
                        }
                    )
        label = "malicious" if best >= 0.75 else "suspicious" if best >= 0.4 else "benign"
        verdict = {
            "label": label,
            "malicious_prob": best,
            "purpose_consistent": label == "benign",
            "attack_chain": "heuristic chain: sensitive source flows to a network sink"
            if label != "benign"
            else "",
            "evidence": evidence[:6],
            "confidence": 0.5,
            "summary": f"Heuristic (fake) investigation result: {label}.",
            "exfil_targets": [],
        }
        return {"tool_calls": [{"name": "submit_verdict", "arguments": verdict}]}


__all__ = ["HeuristicBackend", "ScriptedBackend"]
