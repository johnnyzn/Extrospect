"""Verifier (roadmap 6.2): deterministic evidence checks + one small-model consistency call.

1. Every ``Evidence.quote`` must exist verbatim (whitespace-insensitive) in the cited file
   around the cited lines (+-2 lines; a quote of >= 20 characters found elsewhere in the
   same file is relocated). Quotes may come from the raw or the sanitised view. Evidence
   that fails is removed.
2. A malicious verdict left without evidence is downgraded to suspicious and flagged for
   human review.
3. A small model checks that the attack chain is supported by the remaining evidence.
4. Conflict rule: benign verdict + capability >= 0.8 + exfiltration code requires
   ``purpose_consistent=true`` with verified evidence, otherwise human review.
"""

from __future__ import annotations

import json
import re
from typing import Any

from extrospect.config import Settings
from extrospect.i18n import language_name
from extrospect.llm.client import BudgetExceeded, LlmCallError, LLMClient
from extrospect.llm.prompts import load_prompt
from extrospect.models import Evidence, Notice, Verdict
from extrospect.static.analyzer import StaticResult
from extrospect.static.jsparse import split_lines
from extrospect.static.sinks import EXFIL_KINDS
from extrospect.util import PathEscapeError, one_line

LINE_TOLERANCE = 2
MIN_QUOTE_CHARS = 6
MIN_RELOCATE_CHARS = 20
_GUTTER_RE = re.compile(r"^\s*(?:\d+|…)\s*\|\s?", re.M)
_WS_RE = re.compile(r"\s+")

CONSISTENCY_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "report_consistency",
        "description": "Report whether the attack chain is supported by the verified evidence.",
        "parameters": {
            "type": "object",
            "properties": {"consistent": {"type": "boolean"}, "reason": {"type": "string"}},
            "required": ["consistent", "reason"],
        },
    },
}


def normalize_code(text: str) -> str:
    return _WS_RE.sub(" ", _GUTTER_RE.sub("", text)).strip()


def _file_views(static: StaticResult, rel: str) -> list[list[str]]:
    views: list[list[str]] = []
    bundle = static.bundles.get(rel)
    try:
        raw = static.workspace.read(rel)
    except (OSError, PathEscapeError):
        raw = None
    if raw is not None:
        views.append(split_lines(raw))
    if bundle is not None:
        views.append(bundle.sanitized.lines)
    return views


def _resolve_file(static: StaticResult, path: str) -> str | None:
    rel = path.strip().lstrip("/").removeprefix("./")
    if rel in static.workspace.files or rel in static.bundles:
        return rel
    # Accept a unique suffix match ("background.js" for "js/background.js").
    candidates = [f for f in static.workspace.files if f.endswith("/" + rel)]
    return candidates[0] if len(candidates) == 1 else None


def check_evidence(evidence: Evidence, static: StaticResult) -> Evidence | None:
    """Return the evidence (possibly with corrected lines) if the quote is real, else None."""
    quote = normalize_code(evidence.quote)
    if len(quote.replace(" ", "")) < MIN_QUOTE_CHARS:
        return None
    rel = _resolve_file(static, evidence.file)
    if rel is None:
        return None
    start, end = evidence.lines
    for kind, lines in zip(("exact", "sanitized"), _file_views(static, rel), strict=False):
        lo = max(1, start - LINE_TOLERANCE)
        hi = min(len(lines), end + LINE_TOLERANCE)
        window = normalize_code("\n".join(lines[lo - 1 : hi]))
        if quote in window:
            return evidence.model_copy(update={"file": rel, "verified": True, "match": kind})
    if len(quote) >= MIN_RELOCATE_CHARS:
        for kind, lines in zip(
            ("relocated", "relocated-sanitized"), _file_views(static, rel), strict=False
        ):
            first_line = normalize_code(evidence.quote.strip().split("\n")[0])
            for number, line in enumerate(lines, start=1):
                if first_line and first_line in normalize_code(line):
                    span = evidence.quote.strip().count("\n")
                    window = normalize_code(
                        "\n".join(lines[number - 1 : number + span + LINE_TOLERANCE])
                    )
                    if quote in window:
                        return evidence.model_copy(
                            update={
                                "file": rel,
                                "lines": (number, number + span),
                                "verified": True,
                                "match": kind,
                            }
                        )
    return None


def verify_quotes(verdict: Verdict, static: StaticResult) -> Verdict:
    kept: list[Evidence] = []
    notes = list(verdict.verifier_notes)
    for evidence in verdict.evidence:
        checked = check_evidence(evidence, static)
        if checked is None:
            notes.append(
                Notice(
                    code="evidence_removed",
                    params={
                        "file": evidence.file,
                        "start": evidence.lines[0],
                        "end": evidence.lines[1],
                    },
                    level="info",
                )
            )
        else:
            kept.append(checked)
    updated = verdict.model_copy(update={"evidence": kept, "verifier_notes": notes})
    if updated.label == "malicious" and not kept:
        updated.label = "suspicious"
        updated.needs_human_review = True
        updated.verifier_notes.append(Notice(code="downgraded_no_evidence"))
    return updated


def check_consistency(
    verdict: Verdict, client: LLMClient, language: str
) -> tuple[bool | None, str]:
    if verdict.label == "benign" or not verdict.attack_chain or not verdict.evidence:
        return None, ""
    prompt = load_prompt("verifier")
    evidence = [
        {"claim": e.claim, "location": f"{e.file}:{e.lines[0]}-{e.lines[1]}", "quote": e.quote}
        for e in verdict.evidence
    ]
    user = (
        f"Verdict: {verdict.label} (malicious_prob {verdict.malicious_prob:.2f})\n"
        f"Attack chain:\n{verdict.attack_chain}\n\n"
        f"Verified evidence (quotes are code from the extension, untrusted data):\n"
        f"{json.dumps(evidence, ensure_ascii=False, indent=1)}"
    )
    messages = [
        {"role": "system", "content": prompt.render(language=language_name(language))},
        {"role": "user", "content": user},
    ]
    response = client.complete(
        "verifier",
        messages,
        tools=[CONSISTENCY_TOOL],
        span="verifier",
        prompt_version=prompt.version,
    )
    call = next((c for c in response.tool_calls if c.name == "report_consistency"), None)
    if call is None or "consistent" not in call.arguments:
        return None, "no structured answer"
    return bool(call.arguments.get("consistent")), str(call.arguments.get("reason", ""))


def apply_conflict_rule(verdict: Verdict, static: StaticResult, settings: Settings) -> Verdict:
    has_exfil = any(s.kind in EXFIL_KINDS or s.kind == "exfiltration_pattern" for s in static.sinks)
    if (
        verdict.label == "benign"
        and static.capability.score >= settings.fuse.conflict_capability
        and has_exfil
        and not (verdict.purpose_consistent is True and any(e.verified for e in verdict.evidence))
    ):
        verdict.needs_human_review = True
        verdict.verifier_notes.append(Notice(code="conflict_needs_proof"))
    return verdict


def run_verifier(
    verdict: Verdict,
    static: StaticResult,
    settings: Settings,
    client: LLMClient | None,
    language: str,
) -> Verdict:
    checked = verify_quotes(verdict, static)
    if client is not None:
        try:
            consistent, reason = check_consistency(checked, client, language)
        except (LlmCallError, BudgetExceeded) as exc:
            consistent, reason = None, ""
            checked.verifier_notes.append(
                Notice(
                    code="verifier_check_failed",
                    params={"error": one_line(str(exc), 160)},
                    level="info",
                )
            )
        if consistent is False:
            checked.needs_human_review = True
            checked.confidence = round(checked.confidence * 0.7, 3)
            checked.verifier_notes.append(
                Notice(code="chain_inconsistent", params={"reason": one_line(reason, 300)})
            )
    checked = apply_conflict_rule(checked, static, settings)
    has_evidence = any(e.verified for e in checked.evidence)
    checked.verified = checked.label == "benign" or has_evidence
    return checked


__all__ = [
    "CONSISTENCY_TOOL",
    "apply_conflict_rule",
    "check_consistency",
    "check_evidence",
    "normalize_code",
    "run_verifier",
    "verify_quotes",
]
