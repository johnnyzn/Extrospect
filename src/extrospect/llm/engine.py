"""Engine mode orchestration: Router #1 -> Triage -> Router #2 -> Investigator -> Verifier.

Every stage is logged to the trace. Failures degrade instead of aborting: a failed
investigation falls back to a triage-based ("lightweight") verdict flagged for human
review, and the static scores always remain available.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from extrospect.baseline.rules import rule_score
from extrospect.knowledge.listing import store_listing_possible
from extrospect.llm.client import BudgetExceeded, LlmBackend, LlmCallError, LLMClient
from extrospect.llm.investigator import investigate
from extrospect.llm.router import (
    AfterTriage,
    possibly_reachable,
    route_after_triage,
    route_before_triage,
)
from extrospect.llm.tools import ToolBox
from extrospect.llm.triage import TriageOutcome, run_triage
from extrospect.llm.verifier import apply_conflict_rule, run_verifier
from extrospect.models import (
    ListingInfo,
    LlmUsage,
    Notice,
    Reachability,
    TriageResult,
    Verdict,
    VerdictLabel,
)
from extrospect.static.analyzer import StaticResult
from extrospect.trace import Tracer
from extrospect.util import one_line

if TYPE_CHECKING:
    from extrospect.pipeline import Context


@dataclass
class EngineOutcome:
    verdict: Verdict | None = None
    triage: list[TriageResult] = field(default_factory=list)
    usage: LlmUsage = field(default_factory=LlmUsage)
    listing: ListingInfo | None = None
    gbm_prob: float | None = None
    trace_id: str = ""
    notices: list[Notice] = field(default_factory=list)
    reachability: dict[str, tuple[Reachability, str | None]] = field(default_factory=dict)
    route: dict[str, Any] = field(default_factory=dict)


def lightweight_verdict(triage: list[TriageResult], needs_review: bool = False) -> Verdict:
    """Verdict from triage alone (no investigator): label by the highest suspicion."""
    top = sorted(triage, key=lambda r: -r.suspicion)
    max_suspicion = top[0].suspicion if top else 0.0
    label: VerdictLabel = (
        "benign" if max_suspicion < 0.3 else "suspicious" if max_suspicion < 0.6 else "malicious"
    )
    summary = " ".join(one_line(r.behavior, 200) for r in top[:3] if r.behavior) or None
    return Verdict(
        label=label,
        malicious_prob=max_suspicion,
        confidence=0.4 if needs_review else 0.6,
        needs_human_review=needs_review or label == "malicious",
        summary=summary,
        source="lightweight",
    )


def run_engine(
    static: StaticResult, ctx: Context, llm: LLMClient | LlmBackend | None = None
) -> EngineOutcome:
    settings = ctx.settings
    trace_id = uuid.uuid4().hex[:16]
    tracer = Tracer(
        trace_id,
        settings.paths.traces_dir,
        settings.llm.trace_full_content,
        label=f"{static.manifest.name} {static.ref.id} v{static.ref.version or static.manifest.version}",
    )
    if isinstance(llm, LLMClient):
        client = llm
        client.tracer = client.tracer or tracer
    else:
        client = LLMClient(
            settings.llm, tracer, backend=llm, max_cost_usd=settings.budget.analysis_max_cost_usd
        )
    outcome = EngineOutcome(trace_id=trace_id)
    language = ctx.language

    rules = rule_score(
        static.sinks, static.capability, static.injections, static.stats.obfuscation_score
    )
    outcome.gbm_prob = _gbm_probability(static, ctx, outcome.notices)

    first = route_before_triage(static, settings)
    outcome.route["before_triage"] = {
        "run_llm": first.run_llm,
        "reason": first.reason,
        "slices": len(first.slices),
    }
    tracer.log({"type": "stage", "stage": "router1", "data": outcome.route["before_triage"]})
    if not first.run_llm:
        outcome.notices.append(Notice(code="llm_skipped_low_risk", level="info"))
        return outcome
    client.ensure_available("investigator" if settings.router.flat else "triage")
    if first.truncated:
        outcome.notices.append(
            Notice(
                code="slices_truncated",
                params={"count": len(first.slices), "total": len(static.slices)},
                level="info",
            )
        )

    if settings.router.flat:
        # Ablation control group: no small-model triage, the investigator gets every slice.
        triage = TriageOutcome(
            results=[
                TriageResult(
                    slice_id=s.slice_id,
                    behavior="(not triaged)",
                    suspicion=s.danger,
                    category="unclear",
                )
                for s in first.slices
            ]
        )
    else:
        try:
            triage = run_triage(static, first.slices, client, settings, ctx.cache, language)
        except BudgetExceeded:
            outcome.notices.append(
                Notice(code="analysis_budget", params={"cost": f"{client.usage.cost_usd:.3f}"})
            )
            outcome.usage = client.usage
            return outcome
        outcome.triage = triage.results
    outcome.notices.extend(triage.notices)
    tracer.log(
        {"type": "stage", "stage": "triage", "data": [r.model_dump() for r in triage.results]}
    )

    if settings.router.flat:
        second = AfterTriage(
            escalate=True,
            reasons=["flat_control_group"],
            focus=triage.results,
            reachability_tasks=possibly_reachable(static),
        )
    else:
        second = route_after_triage(static, triage.results, settings, rules.probability)
    outcome.route["after_triage"] = {"escalate": second.escalate, "reasons": second.reasons}
    tracer.log({"type": "stage", "stage": "router2", "data": outcome.route["after_triage"]})

    verdict: Verdict | None
    if not second.escalate:
        verdict = apply_conflict_rule(lightweight_verdict(triage.results), static, settings)
    else:
        toolbox = ToolBox(static, ctx, tracer)
        try:
            client.ensure_available("investigator")
            result = investigate(
                static,
                second.focus or triage.results,
                second.reachability_tasks,
                toolbox,
                client,
                settings,
                language,
                rules.signals,
            )
        except BudgetExceeded:
            outcome.notices.append(
                Notice(code="analysis_budget", params={"cost": f"{client.usage.cost_usd:.3f}"})
            )
            result = None
        except LlmCallError as exc:
            outcome.notices.append(
                Notice(code="investigator_failed", params={"error": one_line(str(exc), 200)})
            )
            result = None
        outcome.listing = toolbox.listing
        if result is not None and result.refused:
            outcome.notices.append(Notice(code="llm_refusal", params={"stage": "investigator"}))
        if result is not None and result.verdict is not None:
            if not toolbox.listing_consulted and store_listing_possible(static.ref):
                result.verdict.verifier_notes.append(
                    Notice(code="listing_not_consulted", level="info")
                )
            if settings.llm.verifier_enabled:
                verdict = run_verifier(result.verdict, static, settings, client, language)
            else:
                verdict = result.verdict  # ablation: unverified verdict
            outcome.reachability = result.reachability
        else:
            if result is not None and result.stopped_reason and not result.refused:
                outcome.notices.append(
                    Notice(code="investigator_budget", params={"reason": result.stopped_reason})
                )
            verdict = apply_conflict_rule(
                lightweight_verdict(triage.results, needs_review=True), static, settings
            )
    outcome.verdict = verdict
    outcome.usage = client.usage
    tracer.log(
        {
            "type": "stage",
            "stage": "verdict",
            "data": verdict.model_dump(mode="json") if verdict else None,
        }
    )
    tracer.log({"type": "stage", "stage": "usage", "data": client.usage.model_dump()})
    return outcome


def _gbm_probability(static: StaticResult, ctx: Context, notices: list[Notice]) -> float | None:
    try:
        from extrospect.baseline.gbm import predict_static
    except ImportError:
        return None
    try:
        return predict_static(static, ctx)
    except Exception:
        return None


__all__ = ["EngineOutcome", "lightweight_verdict", "run_engine"]
