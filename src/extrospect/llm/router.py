"""The two routers of the layered pipeline (roadmap 6.2). Rules only, no model calls.

Router #1 (before triage) decides whether to call an LLM at all and which slices fit the
token budget. Router #2 (after triage) decides whether the expensive investigator agent
runs, and which CVEs need a reachability check.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from extrospect.config import Settings
from extrospect.models import CodeSlice, TriageResult, VulnFinding
from extrospect.static.analyzer import StaticResult
from extrospect.static.slicer import select_slices

ESCALATING_CATEGORIES = {"exfiltration", "remote_control", "injection", "hijack"}

# Library functions commonly named in advisories, used for a cheap "possibly reachable" test.
AFFECTED_FUNCTION_HINTS: dict[str, list[str]] = {
    "jquery": [
        r"\.html\(",
        r"\.append\(",
        r"\.prepend\(",
        r"\.after\(",
        r"\.before\(",
        r"\.replaceWith\(",
        r"\$\(\s*[a-zA-Z_$]",
        r"\.load\(",
        r"\$\.ajax\(",
        r"\$\.get\(",
        r"\$\.extend\(\s*true",
        r"jQuery\.extend\(\s*true",
        r"parseHTML\(",
    ],
    "jquery-ui": [r"\.datepicker\(", r"\.position\(", r"\.dialog\(", r"\.tooltip\("],
    "lodash": [
        r"\.template\(",
        r"defaultsDeep\(",
        r"zipObjectDeep\(",
        r"\.merge\(",
        r"\.mergeWith\(",
        r"\.set\(",
    ],
    "underscore": [r"\.template\("],
    "handlebars": [r"\.compile\(", r"Handlebars\.template"],
    "bootstrap": [
        r"data-template",
        r"data-content",
        r"data-target",
        r"data-parent",
        r"\.tooltip\(",
        r"\.popover\(",
    ],
    "dompurify": [r"\.sanitize\("],
    "moment.js": [r"moment\(\s*[a-zA-Z_$]", r"\.locale\("],
    "moment": [r"moment\(\s*[a-zA-Z_$]", r"\.locale\("],
    "angularjs": [r"ng-bind-html", r"\$sce", r"\$compile"],
}


@dataclass
class BeforeTriage:
    run_llm: bool
    slices: list[CodeSlice]
    truncated: bool
    reason: str


@dataclass
class AfterTriage:
    escalate: bool
    reasons: list[str] = field(default_factory=list)
    focus: list[TriageResult] = field(default_factory=list)
    reachability_tasks: list[VulnFinding] = field(default_factory=list)


def route_before_triage(static: StaticResult, settings: Settings) -> BeforeTriage:
    cfg = settings.router
    relevant = [s for s in static.sinks if s.weight >= 0.2]
    if (
        static.capability.score < cfg.skip_llm_capability_below
        and not relevant
        and not static.injections
    ):
        return BeforeTriage(
            run_llm=False, slices=[], truncated=False, reason="low_capability_no_sinks"
        )
    if not static.slices:
        return BeforeTriage(run_llm=False, slices=[], truncated=False, reason="no_slices")
    picked, truncated = select_slices(
        static.slices, settings.budget.max_slice_tokens_total, settings.budget.max_slices
    )
    return BeforeTriage(run_llm=True, slices=picked, truncated=truncated, reason="triage")


def possibly_reachable(
    static: StaticResult, slices: list[CodeSlice] | None = None
) -> list[VulnFinding]:
    """CVEs whose library functions appear in the analysed (non-library) code."""
    code = "\n".join(s.code for s in (slices if slices is not None else static.slices))
    if not code:
        code = "\n".join(b.sanitized.text for b in static.bundles.values())
    tasks: list[VulnFinding] = []
    for finding in static.vulns:
        patterns = list(AFFECTED_FUNCTION_HINTS.get(finding.library.lower(), []))
        patterns += [re.escape(fn) for fn in finding.affected_functions if fn]
        if any(re.search(p, code) for p in patterns):
            tasks.append(finding)
    return tasks


def route_after_triage(
    static: StaticResult,
    triage: list[TriageResult],
    settings: Settings,
    rules_prob: float = 0.0,
) -> AfterTriage:
    cfg = settings.router
    decision = AfterTriage(escalate=False)
    max_suspicion = max((r.suspicion for r in triage), default=0.0)
    categories = {r.category for r in triage}
    decision.focus = sorted(
        [
            r
            for r in triage
            if r.suspicion >= cfg.benign_suspicion_below
            or r.category in ESCALATING_CATEGORIES | {"unclear"}
        ],
        key=lambda r: -r.suspicion,
    )

    if max_suspicion >= cfg.escalate_suspicion_at:
        decision.reasons.append("high_suspicion")
    if static.capability.score >= cfg.escalate_capability_unclear_at and "unclear" in categories:
        decision.reasons.append("high_capability_unclear")
    tasks = possibly_reachable(static)
    if tasks:
        decision.reachability_tasks = tasks
        decision.reasons.append("cve_possibly_reachable")
    if static.injections:
        decision.reasons.append("prompt_injection_attempt")
    if rules_prob >= 0.6:
        decision.reasons.append("high_static_prior")
    if any(
        r.category in ESCALATING_CATEGORIES and r.suspicion >= cfg.benign_suspicion_below
        for r in triage
    ):
        decision.reasons.append("suspicious_category")

    all_low = max_suspicion < cfg.benign_suspicion_below and not categories & {
        "exfiltration",
        "remote_control",
    }
    decision.escalate = bool(decision.reasons) and not (
        all_low and decision.reasons == ["suspicious_category"]
    )
    return decision


__all__ = [
    "AFFECTED_FUNCTION_HINTS",
    "ESCALATING_CATEGORIES",
    "AfterTriage",
    "BeforeTriage",
    "possibly_reachable",
    "route_after_triage",
    "route_before_triage",
]
