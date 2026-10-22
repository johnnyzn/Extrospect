"""Investigator agent (roadmap 6.2): a larger model in a tool loop that ends with
``submit_verdict``.

Budget: ``investigator_max_steps`` model calls, ``investigator_max_input_tokens`` input
tokens and ``investigator_max_cost_usd``. When a limit is hit the model gets one last
turn in which only ``submit_verdict`` is accepted. The conversation is append-only.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from extrospect.config import Settings
from extrospect.i18n import language_name
from extrospect.llm.client import LLMClient
from extrospect.llm.prompts import load_prompt
from extrospect.llm.sanitize import wrap_untrusted
from extrospect.llm.tools import TOOL_SPECS, ToolBox
from extrospect.llm.triage import CONTEXT_HINTS, extension_header
from extrospect.models import Reachability, TriageResult, Verdict, VulnFinding
from extrospect.static.analyzer import StaticResult
from extrospect.util import one_line

FORCE_MESSAGE = (
    "Budget exhausted ({reason}). Call submit_verdict now with the evidence you already have. "
    "No other tool calls will be executed."
)
CONTINUE_MESSAGE = "Continue the investigation with the tools, or call submit_verdict to finish."


@dataclass
class InvestigationResult:
    verdict: Verdict | None = None
    reachability: dict[str, tuple[Reachability, str | None]] = field(default_factory=dict)
    steps: int = 0
    stopped_reason: str | None = None
    refused: bool = False
    messages: list[dict[str, Any]] = field(default_factory=list)


def build_investigation_message(
    static: StaticResult,
    focus: list[TriageResult],
    reach_tasks: list[VulnFinding],
    rules_signals: list[tuple[str, float]] | None = None,
    max_slices: int = 8,
) -> str:
    parts = [extension_header(static), ""]
    explanation = static.capability.explanation[:10]
    if explanation:
        parts.append(f"Capability (A = {static.capability.score:.2f}):")
        parts.extend(f"- {line}" for line in explanation)
        parts.append("")
    if rules_signals:
        parts.append(
            "Static rule signals: "
            + ", ".join(f"{name} ({value:.2f})" for name, value in rules_signals)
        )
    hosts: dict[str, str] = {}
    for endpoint in static.endpoints:
        hosts.setdefault(endpoint.host, f"{endpoint.file}:{endpoint.line}")
    if hosts:
        parts.append(
            "Remote hosts referenced in code: "
            + ", ".join(f"{h} ({loc})" for h, loc in list(hosts.items())[:20])
        )
    if reach_tasks:
        parts.append("")
        parts.append(
            "Vulnerable libraries - decide reachability (fill `reachability` in submit_verdict):"
        )
        for finding in reach_tasks[:10]:
            parts.append(
                f"- {finding.library} {finding.version} in {finding.file}: {finding.cve}"
                + (f" - {one_line(finding.summary, 160)}" if finding.summary else "")
            )
    parts.append("")
    if focus:
        parts.append("Triage results (most suspicious first):")
        for result in focus[:15]:
            slice_ = static.slice_by_id(result.slice_id)
            location = (
                f"{slice_.file}:{slice_.start_line}-{slice_.end_line}, {slice_.context}"
                if slice_
                else "?"
            )
            parts.append(
                f"- slice {result.slice_id} ({location}) - {result.category}, suspicion {result.suspicion:.2f}: "
                f"{one_line(result.behavior, 220)}"
                + (f" | data flow: {one_line(result.data_flow, 160)}" if result.data_flow else "")
            )
        parts.append("")
    slices = [s for r in focus if (s := static.slice_by_id(r.slice_id)) is not None][:max_slices]
    if not slices:
        slices = static.slices[:max_slices]
    parts.append("Suspicious code:")
    for slice_ in slices:
        parts.append(
            f"### Slice {slice_.slice_id} - {slice_.file} ({CONTEXT_HINTS.get(slice_.context, '')})"
        )
        parts.append(wrap_untrusted(slice_))
    other_files = sorted(f for f, v in static.workspace.files.items() if v.analyze)
    parts.append("")
    parts.append("Analysed files: " + ", ".join(other_files[:60]))
    parts.append("")
    parts.append("Investigate following the procedure and finish with submit_verdict.")
    return "\n".join(parts)


def parse_verdict(
    arguments: dict[str, Any],
) -> tuple[Verdict, dict[str, tuple[Reachability, str | None]]]:
    data = dict(arguments)
    reach_items = data.pop("reachability", None) or []
    data.setdefault("source", "engine")
    data["source"] = "engine"
    if isinstance(data.get("attack_chain"), str) and not data["attack_chain"].strip():
        data["attack_chain"] = None
    verdict = Verdict.model_validate(data)
    reachability: dict[str, tuple[Reachability, str | None]] = {}
    for item in reach_items if isinstance(reach_items, list) else []:
        if not isinstance(item, dict) or not item.get("cve"):
            continue
        value = str(item.get("reachable", "unknown")).lower()
        reach: Reachability = value if value in {"yes", "no", "unknown"} else "unknown"  # type: ignore[assignment]
        reachability[str(item["cve"])] = (reach, item.get("evidence"))
    return verdict, reachability


def investigate(
    static: StaticResult,
    focus: list[TriageResult],
    reach_tasks: list[VulnFinding],
    toolbox: ToolBox,
    client: LLMClient,
    settings: Settings,
    language: str,
    rules_signals: list[tuple[str, float]] | None = None,
) -> InvestigationResult:
    prompt = load_prompt("investigator")
    budget = settings.budget
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": prompt.render(language=language_name(language))},
        {
            "role": "user",
            "content": build_investigation_message(static, focus, reach_tasks, rules_signals),
        },
    ]
    result = InvestigationResult(messages=messages)
    input_tokens = 0
    cost = 0.0
    forced = False
    listing_nudged = False

    while True:
        result.steps += 1
        response = client.complete(
            "investigator",
            messages,
            tools=TOOL_SPECS,
            span=f"investigator:{result.steps}",
            prompt_version=prompt.version,
        )
        input_tokens += response.usage.input_tokens
        cost += response.usage.cost_usd
        if response.refused:
            result.refused = True
            result.stopped_reason = "refusal"
            return result
        messages.append(response.message)

        if not response.tool_calls:
            if forced:
                result.stopped_reason = result.stopped_reason or "no_verdict"
                return result
            messages.append({"role": "user", "content": CONTINUE_MESSAGE})
        else:
            tool_messages: list[dict[str, Any]] = []
            for call in response.tool_calls:
                content: str
                if call.name == "submit_verdict":
                    if call.parse_error:
                        content = (
                            f"Invalid arguments ({call.parse_error}). Call submit_verdict again."
                        )
                    elif not toolbox.listing_consulted and not listing_nudged and not forced:
                        listing_nudged = True
                        content = "Rejected: call retrieve_listing first (procedure step 1), then submit_verdict again."
                    else:
                        try:
                            verdict, reachability = parse_verdict(call.arguments)
                        except ValidationError as exc:
                            content = f"Invalid verdict: {one_line(str(exc), 400)}. Fix it and call submit_verdict again."
                        else:
                            result.verdict = verdict
                            result.reachability = reachability
                            content = "Verdict received."
                elif forced:
                    content = json.dumps(
                        {"error": "budget exhausted - only submit_verdict is accepted now"}
                    )
                else:
                    content = toolbox.execute(
                        call.name, call.arguments, span=f"investigator:{result.steps}"
                    )
                tool_messages.append({"role": "tool", "tool_call_id": call.id, "content": content})
            messages.extend(tool_messages)
            if result.verdict is not None:
                return result

        reason = None
        if result.steps >= budget.investigator_max_steps:
            reason = f"{result.steps} steps"
        elif input_tokens >= budget.investigator_max_input_tokens:
            reason = f"{input_tokens} input tokens"
        elif cost >= budget.investigator_max_cost_usd:
            reason = f"${cost:.3f}"
        if reason is not None:
            if forced:
                result.stopped_reason = result.stopped_reason or reason
                return result
            forced = True
            result.stopped_reason = reason
            messages.append({"role": "user", "content": FORCE_MESSAGE.format(reason=reason)})


__all__ = ["InvestigationResult", "build_investigation_message", "investigate", "parse_verdict"]
