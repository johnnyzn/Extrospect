"""Deterministic rule baseline: a static "malicious prior" from sink patterns.

Used (a) as the ``Em`` term when neither the LLM nor the GBM ran, (b) as the static
prior in the one-way adjustment rule (an LLM may only lower a high static prior with
verified purpose-consistency evidence), and (c) as the "rules" row of the ablation table.
Signals are combined with a noisy-OR so independent indicators reinforce each other.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from extrospect.models import CapabilityProfile, InjectionAttempt, Sink

STRONG_SOURCES = {
    "cookie_read",
    "header_read",
    "password_field_read",
    "payment_field_read",
    "credential_intercept",
    "keystroke_capture",
    "form_capture",
    "history_read",
    "screen_capture",
    "identity_read",
}


@dataclass
class RuleScore:
    probability: float
    signals: list[tuple[str, float]] = field(default_factory=list)


def _noisy_or(values: Iterable[float]) -> float:
    remaining = 1.0
    for value in values:
        remaining *= 1.0 - max(0.0, min(1.0, value))
    return 1.0 - remaining


def rule_score(
    sinks: list[Sink],
    capability: CapabilityProfile,
    injections: list[InjectionAttempt] | None = None,
    obfuscation: float = 0.0,
) -> RuleScore:
    kinds = {s.kind for s in sinks}
    signals: list[tuple[str, float]] = []

    for sink in sinks:
        if sink.kind == "exfiltration_pattern":
            strong = any(src in (sink.detail or "") for src in STRONG_SOURCES)
            signals.append(("exfiltration_pattern", 0.65 if strong else 0.45))
            break
    if "remote_control_pattern" in kinds:
        signals.append(("remote_control_pattern", 0.6))
    if injections:
        strongest = max((s.weight for s in sinks if s.kind == "prompt_injection"), default=0.6)
        signals.append(("prompt_injection", 0.7 if strongest >= 0.9 else 0.5))
    if kinds & {"proxy_hijack", "debugger_control"}:
        signals.append(("browser_control", 0.45))
    if "extension_tamper" in kinds:
        signals.append(("extension_tamper", 0.45))
    if "request_rewrite" in kinds and {"OVERRIDE_SEARCH", "COMBO_DNR_STRIP_SECURITY"} & set(
        capability.flags
    ):
        signals.append(("search_or_header_hijack", 0.5))
    elif "request_rewrite" in kinds:
        signals.append(("request_rewrite", 0.2))
    if "OVERRIDE_SEARCH" in capability.flags:
        signals.append(("search_override", 0.25))
    if "COMBO_DNR_STRIP_SECURITY" in capability.flags:
        signals.append(("strips_security_headers", 0.35))
    if "remote_code" in kinds:
        signals.append(("remote_code", 0.5))
    if "cookie_tamper" in kinds and "link_rewrite" in kinds:
        signals.append(("affiliate_fraud", 0.2))
    elif "link_rewrite" in kinds:
        signals.append(("link_rewrite", 0.1))
    if obfuscation >= 0.6 and kinds & {"network_exfil", "dynamic_code"}:
        signals.append(("obfuscated_network_code", 0.4))
    elif obfuscation >= 0.35:
        signals.append(("obfuscation", 0.15))
    if signals and "time_bomb" in kinds:
        signals.append(("time_bomb", 0.15))
    if signals and "evasion_check" in kinds:
        signals.append(("evasion_check", 0.15))
    if {"CSP_UNSAFE_EVAL", "CSP_REMOTE_SCRIPT"} & set(capability.flags) and "dynamic_code" in kinds:
        signals.append(("eval_with_relaxed_csp", 0.3))
    if "COMBO_OFFSTORE_UPDATE" in capability.flags:
        signals.append(("offstore_updates", 0.15))

    if not signals:
        top = sorted((s.weight for s in sinks), reverse=True)[:3]
        base = 0.02 + 0.08 * (sum(top) / 3 if top else 0.0)
        return RuleScore(probability=round(base, 4), signals=[])
    probability = min(0.95, _noisy_or(v for _, v in signals))
    return RuleScore(probability=round(probability, 4), signals=signals)


__all__ = ["STRONG_SOURCES", "RuleScore", "rule_score"]
