"""Score fusion (roadmap section 8). The LLM never sets the score directly.

::

    A    = capability score (0-1)
    Ev   = max over CVEs (epss_percentile x reach_w)      reach_w: yes 1.0 / unknown 0.4 / no 0.1
    Em   = verified LLM malicious_prob; GBM prob without LLM; 0.7 LLM + 0.3 GBM with both;
           the rule baseline when neither ran
    E    = 1 - (1 - Ev)(1 - Em)                            noisy-OR
    Risk = 100 x A^0.5 x E^0.7 + hard rules
           * Verifier-confirmed malicious with evidence -> floor 80
           * purpose_consistent and all exfiltration targets first-party -> Em x 0.5
    One-way rule: an LLM may lower a high static prior only with a verified,
    purpose-consistent verdict that carries evidence.
"""

from __future__ import annotations

from dataclasses import dataclass

from extrospect.config import FuseConfig
from extrospect.models import CapabilityProfile, RiskLevel, ScoreBreakdown, Verdict, VulnFinding

ONE_WAY_THRESHOLD = 0.4


@dataclass
class FuseInputs:
    capability: CapabilityProfile
    vulns: list[VulnFinding]
    verdict: Verdict | None = None
    gbm_prob: float | None = None
    rules_prob: float | None = None
    exfil_all_first_party: bool = False


def vuln_evidence(vulns: list[VulnFinding], cfg: FuseConfig) -> float:
    best = 0.0
    for finding in vulns:
        reach = cfg.reach_weights.get(finding.reachable, cfg.reach_weights.get("unknown", 0.4))
        if cfg.epss_field == "percentile" and finding.epss_percentile is not None:
            base = finding.epss_percentile
        elif cfg.epss_field == "probability" and finding.epss is not None:
            base = finding.epss
        else:
            base = cfg.severity_fallback.get((finding.severity or "medium").lower(), 0.25)
        best = max(best, base * reach)
    return min(1.0, best)


def level_for(score: float, cfg: FuseConfig) -> RiskLevel:
    thresholds = cfg.level_thresholds
    if score <= thresholds.get("benign", 15):
        return "benign"
    if score <= thresholds.get("low", 35):
        return "low"
    if score <= thresholds.get("medium", 60):
        return "medium"
    if score <= thresholds.get("high", 80):
        return "high"
    return "critical"


def _verdict_can_lower(verdict: Verdict) -> bool:
    return (
        verdict.verified
        and verdict.purpose_consistent is True
        and any(e.verified for e in verdict.evidence)
        and verdict.source in {"engine", "host"}
    )


def fuse(inputs: FuseInputs, cfg: FuseConfig) -> tuple[int, RiskLevel, ScoreBreakdown]:
    breakdown = ScoreBreakdown()
    A = max(0.0, min(1.0, inputs.capability.score))
    Ev = vuln_evidence(inputs.vulns, cfg)
    verdict = inputs.verdict
    llm_prob = (
        verdict.malicious_prob if verdict is not None and verdict.source != "static" else None
    )
    gbm = inputs.gbm_prob
    rules = inputs.rules_prob

    if llm_prob is not None and gbm is not None:
        Em = cfg.llm_weight * llm_prob + cfg.gbm_weight * gbm
        source = "llm+gbm"
    elif llm_prob is not None:
        Em, source = llm_prob, "llm"
    elif gbm is not None:
        Em, source = gbm, "gbm"
    elif rules is not None:
        Em, source = rules, "rules"
    else:
        Em, source = 0.0, "none"

    # One-way adjustment rule (roadmap 6.1 #4).
    prior = gbm if gbm is not None else rules
    lowering = (
        llm_prob is not None and prior is not None and prior >= ONE_WAY_THRESHOLD and Em < prior
    )
    if lowering and (verdict is None or not _verdict_can_lower(verdict)):
        assert prior is not None
        Em = prior
        breakdown.one_way_kept_static = True

    if verdict is not None and verdict.purpose_consistent and inputs.exfil_all_first_party:
        Em *= cfg.first_party_multiplier
        breakdown.first_party_discount = True

    E = 1.0 - (1.0 - Ev) * (1.0 - Em)
    raw = (
        100.0 * (A**cfg.capability_exponent) * (E**cfg.evidence_exponent)
        if A > 0 and E > 0
        else 0.0
    )
    score = raw
    if (
        verdict is not None
        and verdict.label == "malicious"
        and verdict.verified
        and any(e.verified for e in verdict.evidence)
    ):
        if score < cfg.malicious_floor:
            breakdown.hard_rules.append("verified_malicious_floor")
        score = max(score, float(cfg.malicious_floor))

    final = max(0, min(100, round(score)))
    breakdown.A = round(A, 4)
    breakdown.Ev = round(Ev, 4)
    breakdown.Em = round(Em, 4)
    breakdown.E = round(E, 4)
    breakdown.raw = round(raw, 2)
    breakdown.em_source = source
    breakdown.llm_prob = llm_prob
    breakdown.gbm_prob = gbm
    breakdown.rules_prob = rules
    return final, level_for(final, cfg), breakdown


__all__ = ["ONE_WAY_THRESHOLD", "FuseInputs", "fuse", "level_for", "vuln_evidence"]
