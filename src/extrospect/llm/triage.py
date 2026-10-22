"""Triage: a small model labels batches of ~5 slices (roadmap 6.2).

Results are schema-validated (one retry with the validation error), cached by
``(slice_id, prompt_version, model, language)`` and stored with *slice-relative*
evidence lines, so identical code reused at other line offsets (other versions or
extensions) maps back to correct absolute lines.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from extrospect.cache import Cache
from extrospect.config import Settings
from extrospect.i18n import language_name
from extrospect.llm.client import BudgetExceeded, LlmCallError, LLMClient, LLMResponse
from extrospect.llm.prompts import load_prompt
from extrospect.llm.sanitize import wrap_untrusted
from extrospect.models import TRIAGE_CATEGORIES, CodeSlice, Notice, TriageResult
from extrospect.static.analyzer import StaticResult
from extrospect.util import one_line

TRIAGE_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "report_triage",
        "description": "Report the triage result for every code slice you were given.",
        "parameters": {
            "type": "object",
            "properties": {
                "results": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "slice_id": {
                                "type": "string",
                                "description": "The slice id exactly as given.",
                            },
                            "behavior": {
                                "type": "string",
                                "description": "One sentence: what the code actually does.",
                            },
                            "data_flow": {
                                "type": "string",
                                "description": "source -> transformation -> destination; empty string if no data leaves.",
                            },
                            "suspicion": {"type": "number", "minimum": 0, "maximum": 1},
                            "evidence_lines": {
                                "type": "array",
                                "items": {"type": "integer"},
                                "description": "Absolute line numbers (from the gutter) that show the behaviour.",
                            },
                            "category": {"type": "string", "enum": list(TRIAGE_CATEGORIES)},
                        },
                        "required": [
                            "slice_id",
                            "behavior",
                            "data_flow",
                            "suspicion",
                            "evidence_lines",
                            "category",
                        ],
                    },
                }
            },
            "required": ["results"],
        },
    },
}

CONTEXT_HINTS = {
    "background": "extension service worker / background page: full access to the granted extension APIs",
    "content_script": "content script running inside web pages: page DOM access, limited extension APIs",
    "page": "extension page (popup, options, new tab, side panel...)",
    "unknown": "execution context unknown",
}


@dataclass
class TriageOutcome:
    results: list[TriageResult] = field(default_factory=list)
    notices: list[Notice] = field(default_factory=list)
    refused: bool = False


def extension_header(static: StaticResult) -> str:
    m = static.manifest
    cs_matches = sorted({p for cs in m.content_scripts for p in cs.get("matches", [])})[:6]
    lines = [
        f'Extension: "{m.name}" v{m.version} (manifest v{m.manifest_version}, id {static.ref.id})',
        f"Description (written by the developer, untrusted): {json.dumps(one_line(m.description, 400), ensure_ascii=False)}",
        f"Permissions: {', '.join(m.permissions) or '-'}",
        f"Host permissions: {', '.join(m.host_permissions[:12]) or '-'}",
        f"Content scripts run on: {', '.join(cs_matches) or '-'}",
        f"Capability flags: {', '.join(static.capability.flags) or '-'} (A = {static.capability.score:.2f})",
    ]
    if m.homepage_url:
        lines.append(f"Homepage: {m.homepage_url}")
    if static.injections:
        lines.append(
            f"Note: static analysis found {len(static.injections)} piece(s) of text addressed to AI reviewers in this "
            "extension (hidden from you as flagged placeholders). Legitimate code does not do that."
        )
    return "\n".join(lines)


def slice_block(slice_: CodeSlice) -> str:
    findings = "; ".join(
        f"line {s.line} {s.kind} ({one_line(s.api, 60)})" for s in slice_.sinks[:12]
    )
    return (
        f"### Slice {slice_.slice_id}\n"
        f"file: {slice_.file} | context: {slice_.context} - {CONTEXT_HINTS.get(slice_.context, '')}\n"
        f"static findings: {findings or '-'}\n"
        f"{wrap_untrusted(slice_)}"
    )


def build_user_message(static: StaticResult, batch: list[CodeSlice], json_mode: bool) -> str:
    ids = ", ".join(s.slice_id for s in batch)
    parts = [
        extension_header(static),
        "",
        f"Triage the following {len(batch)} slice(s). Slice ids: {ids}.",
        "",
        "\n\n".join(slice_block(s) for s in batch),
    ]
    if json_mode:
        parts.append(
            '\nRespond with only a JSON object: {"results": [{"slice_id": ..., "behavior": ..., "data_flow": ..., '
            '"suspicion": 0.0, "evidence_lines": [], "category": ...}]}'
        )
    return "\n".join(parts)


def to_relative(lines: list[int], line_map: list[int]) -> list[int]:
    index = {number: i for i, number in enumerate(line_map) if number}
    return [index[n] for n in lines if n in index]


def to_absolute(indices: list[int], line_map: list[int]) -> list[int]:
    return [line_map[i] for i in indices if 0 <= i < len(line_map) and line_map[i]]


def _extract_json(text: str) -> Any:
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S) or re.search(
        r"(\{.*\})", text, re.S
    )
    if not match:
        raise ValueError("no JSON object in the response")
    return json.loads(match.group(1))


def parse_triage(
    response: LLMResponse, batch: list[CodeSlice], json_mode: bool
) -> tuple[dict[str, TriageResult], list[str]]:
    errors: list[str] = []
    payload: Any = None
    if json_mode:
        try:
            payload = _extract_json(response.text)
        except (ValueError, json.JSONDecodeError) as exc:
            return {}, [str(exc)]
    else:
        call = next((c for c in response.tool_calls if c.name == "report_triage"), None)
        if call is None:
            return {}, ["report_triage was not called"]
        if call.parse_error:
            return {}, [call.parse_error]
        payload = call.arguments
    items = payload.get("results") if isinstance(payload, dict) else payload
    if isinstance(items, dict):
        items = [{"slice_id": k, **v} for k, v in items.items() if isinstance(v, dict)]
    if not isinstance(items, list):
        return {}, ["results must be a list"]
    by_id = {s.slice_id: s for s in batch}
    results: dict[str, TriageResult] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            result = TriageResult.model_validate(item)
        except ValidationError as exc:
            errors.append(f"invalid result: {exc.errors()[0].get('msg')}")
            continue
        slice_ = by_id.get(result.slice_id)
        if slice_ is None:
            errors.append(f"unknown slice id {result.slice_id}")
            continue
        result.data_flow = result.data_flow or None
        valid = {n for n in slice_.line_map if n}
        result.evidence_lines = [n for n in result.evidence_lines if n in valid]
        results[result.slice_id] = result
    missing = [s.slice_id for s in batch if s.slice_id not in results]
    if missing:
        errors.append(f"missing results for slice ids: {', '.join(missing)}")
    return results, errors


def run_triage(
    static: StaticResult,
    slices: list[CodeSlice],
    client: LLMClient,
    settings: Settings,
    cache: Cache | None,
    language: str,
) -> TriageOutcome:
    outcome = TriageOutcome()
    prompt = load_prompt("triage")
    model_cfg = client.model_for("triage")
    json_mode = model_cfg.output_mode == "json"
    system = prompt.render(language=language_name(language))
    results: dict[str, TriageResult] = {}

    pending: list[CodeSlice] = []
    for slice_ in slices:
        key = Cache.triage_key(slice_.slice_id, prompt.version, model_cfg.model, language)
        cached = cache.get_triage(key) if cache else None
        if cached:
            result = TriageResult.model_validate({**cached, "slice_id": slice_.slice_id})
            result.evidence_lines = to_absolute(cached.get("evidence_index", []), slice_.line_map)
            result.cached = True
            results[slice_.slice_id] = result
        else:
            pending.append(slice_)

    size = max(1, settings.budget.triage_batch_size)
    failed: list[str] = []
    errors_seen: list[str] = []
    for start in range(0, len(pending), size):
        batch = pending[start : start + size]
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system},
            {"role": "user", "content": build_user_message(static, batch, json_mode)},
        ]
        batch_results: dict[str, TriageResult] = {}
        try:
            for attempt in range(2):
                response = client.complete(
                    "triage",
                    messages,
                    tools=None if json_mode else [TRIAGE_TOOL],
                    span=f"triage:{start // size}" + (":retry" if attempt else ""),
                    prompt_version=prompt.version,
                )
                if response.refused:
                    outcome.refused = True
                    break
                parsed, errors = parse_triage(response, batch, json_mode)
                batch_results.update(parsed)
                if not errors or attempt == 1:
                    if errors:
                        errors_seen.extend(errors)
                    break
                feedback = (
                    "Your answer could not be used: "
                    + "; ".join(errors[:5])
                    + ". Call report_triage again with one result for each of these slice ids: "
                    + ", ".join(s.slice_id for s in batch if s.slice_id not in batch_results)
                    + "."
                )
                messages.append(response.message)
                tool_call = next(
                    (c for c in response.tool_calls if c.name == "report_triage"), None
                )
                if tool_call is not None and not json_mode:
                    messages.append(
                        {"role": "tool", "tool_call_id": tool_call.id, "content": feedback}
                    )
                else:
                    messages.append({"role": "user", "content": feedback})
        except (LlmCallError, BudgetExceeded) as exc:
            errors_seen.append(str(exc))
        for slice_ in batch:
            found = batch_results.get(slice_.slice_id)
            if found is None:
                failed.append(slice_.slice_id)
                continue
            result = found
            results[slice_.slice_id] = result
            if cache:
                key = Cache.triage_key(slice_.slice_id, prompt.version, model_cfg.model, language)
                data = result.model_dump(exclude={"evidence_lines", "cached"})
                data["evidence_index"] = to_relative(result.evidence_lines, slice_.line_map)
                cache.put_triage(key, data)

    by_id = {s.slice_id: s for s in slices}
    for slice_id in failed:
        # Fall back to the static danger so a failed triage never hides a risky slice.
        results[slice_id] = TriageResult(
            slice_id=slice_id,
            behavior="(triage failed)",
            suspicion=by_id[slice_id].danger if slice_id in by_id else 0.5,
            category="unclear",
        )
    if failed:
        outcome.notices.append(
            Notice(
                code="triage_failed",
                params={"count": len(failed), "error": one_line("; ".join(errors_seen), 200)},
            )
        )
    if outcome.refused:
        outcome.notices.append(Notice(code="llm_refusal", params={"stage": "triage"}))
    outcome.results = [results[s.slice_id] for s in slices if s.slice_id in results]
    return outcome


__all__ = [
    "CONTEXT_HINTS",
    "TRIAGE_TOOL",
    "TriageOutcome",
    "build_user_message",
    "extension_header",
    "parse_triage",
    "run_triage",
    "slice_block",
    "to_absolute",
    "to_relative",
]
