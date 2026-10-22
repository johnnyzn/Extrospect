"""Engine mode with scripted / heuristic fake models - zero tokens, no API keys."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from extrospect.config import LlmConfig
from extrospect.llm.client import LlmCallError, LLMClient, with_cache_control
from extrospect.llm.engine import lightweight_verdict, run_engine
from extrospect.llm.fake import HeuristicBackend, ScriptedBackend
from extrospect.llm.investigator import build_investigation_message, investigate, parse_verdict
from extrospect.llm.router import possibly_reachable, route_after_triage, route_before_triage
from extrospect.llm.tools import TOOL_NAMES, ToolBox
from extrospect.llm.triage import parse_triage, run_triage, to_absolute, to_relative
from extrospect.llm.verifier import check_evidence, run_verifier, verify_quotes
from extrospect.models import Evidence, TriageResult, Verdict
from extrospect.pipeline import analyze, static_for
from extrospect.trace import Tracer, load_trace, render_trace


def client_with(backend: Any, **kwargs: Any) -> LLMClient:
    return LLMClient(LlmConfig(max_retries=1), backend=backend, **kwargs)


def text_of(message: dict) -> str:
    content = message.get("content")
    if isinstance(content, list):  # cache_control blocks
        return "\n".join(part.get("text", "") for part in content)
    return content or ""


# --------------------------------------------------------------------------- client


def test_client_accounting_and_cache_control() -> None:
    backend = ScriptedBackend(
        responses=[{"text": "hello", "input_tokens": 1000, "output_tokens": 20}]
    )
    client = client_with(backend)
    response = client.complete(
        "triage",
        [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}],
        span="t",
        prompt_version="v",
    )
    assert response.text == "hello"
    assert client.usage.calls == 1 and client.usage.input_tokens == 1000
    # Anthropic models get cache breakpoints on the system prompt and the first user message.
    sent = backend.calls[0][1]
    assert sent[0]["content"][0]["cache_control"] == {"type": "ephemeral"}
    assert sent[1]["content"][0]["cache_control"] == {"type": "ephemeral"}
    marked = with_cache_control(
        [
            {"role": "system", "content": "a"},
            {"role": "user", "content": "b"},
            {"role": "user", "content": "c"},
        ]
    )
    assert isinstance(marked[2]["content"], str)  # only two breakpoints


def test_client_retries_then_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("extrospect.llm.client.time.sleep", lambda _s: None)

    class RateLimitError(Exception):
        pass

    backend = ScriptedBackend(responses=[RateLimitError("slow down"), {"text": "ok"}])  # type: ignore[list-item]
    client = client_with(backend)
    assert (
        client.complete(
            "triage", [{"role": "user", "content": "x"}], span="t", prompt_version="v"
        ).text
        == "ok"
    )

    class BadRequestError(Exception):
        pass

    client = client_with(ScriptedBackend(responses=[BadRequestError("nope")]))  # type: ignore[list-item]
    with pytest.raises(LlmCallError):
        client.complete("triage", [{"role": "user", "content": "x"}], span="t", prompt_version="v")


def test_refusal_falls_back_to_other_model() -> None:
    backend = ScriptedBackend(
        responses=[{"text": "", "finish_reason": "content_filter"}, {"text": "fallback answer"}]
    )
    cfg = LlmConfig(refusal_fallback_model="anthropic/claude-opus-5-5")
    client = LLMClient(cfg, backend=backend)
    response = client.complete(
        "investigator", [{"role": "user", "content": "x"}], span="i", prompt_version="v"
    )
    assert response.text == "fallback answer"
    assert backend.calls[1][0] == "anthropic/claude-opus-5-5"


# --------------------------------------------------------------------------- triage


def test_relative_evidence_lines_round_trip() -> None:
    line_map = [10, 11, 0, 40, 41]
    assert to_relative([11, 41, 99], line_map) == [1, 4]
    assert to_absolute([1, 4, 7], line_map) == [11, 41]


def test_triage_parses_validates_and_caches(ctx, fixtures_dir: Path) -> None:
    static = static_for(fixtures_dir / "mal_cookie_exfil", ctx)
    slice_ = static.slices[0]

    def handler(model: str, messages: list, tools: list | None) -> dict:
        assert tools and tools[0]["function"]["name"] == "report_triage"
        assert slice_.slice_id in text_of(messages[1])
        assert "<untrusted_code" in text_of(messages[1])
        return {
            "tool_calls": [
                {
                    "name": "report_triage",
                    "arguments": {
                        "results": [
                            {
                                "slice_id": slice_.slice_id,
                                "behavior": "posts all cookies to a remote server",
                                "data_flow": "cookies -> base64 -> fetch",
                                "suspicion": 0.92,
                                "evidence_lines": [8, 10, 999],
                                "category": "exfiltration",
                            }
                        ]
                    },
                }
            ]
        }

    backend = ScriptedBackend(handler)
    outcome = run_triage(static, [slice_], client_with(backend), ctx.settings, ctx.cache, "en")
    result = outcome.results[0]
    assert result.suspicion == pytest.approx(0.92) and result.category == "exfiltration"
    assert result.evidence_lines == [8, 10]  # line 999 is not part of the slice
    again = run_triage(static, [slice_], client_with(backend), ctx.settings, ctx.cache, "en")
    assert again.results[0].cached and len(backend.calls) == 1


def test_triage_retries_on_invalid_output(ctx, fixtures_dir: Path) -> None:
    static = static_for(fixtures_dir / "mal_remote_config", ctx)
    slice_ = static.slices[0]
    responses = [
        {"text": "I think it is fine."},
        {
            "tool_calls": [
                {
                    "name": "report_triage",
                    "arguments": {
                        "results": [
                            {
                                "slice_id": slice_.slice_id,
                                "behavior": "evals remote config",
                                "data_flow": "",
                                "suspicion": "95",
                                "evidence_lines": [18],
                                "category": "Remote-Control",
                            }
                        ]
                    },
                }
            ]
        },
    ]
    backend = ScriptedBackend(responses=responses)
    outcome = run_triage(static, [slice_], client_with(backend), ctx.settings, None, "en")
    result = outcome.results[0]
    assert result.suspicion == pytest.approx(0.95)  # "95" read as a percentage
    assert result.category == "remote_control"
    assert result.data_flow is None
    retry_messages = backend.calls[1][1]
    assert retry_messages[-1]["role"] == "user" and "report_triage" in text_of(retry_messages[-1])


def test_triage_failure_falls_back_to_static_danger(ctx, fixtures_dir: Path) -> None:
    static = static_for(fixtures_dir / "mal_cookie_exfil", ctx)
    backend = ScriptedBackend(responses=[{"text": "?"}, {"text": "?"}])
    outcome = run_triage(static, static.slices, client_with(backend), ctx.settings, None, "en")
    assert outcome.results[0].category == "unclear"
    assert outcome.results[0].suspicion == pytest.approx(static.slices[0].danger)
    assert outcome.notices[0].code == "triage_failed"


def test_parse_triage_json_mode(ctx, fixtures_dir: Path) -> None:
    from extrospect.llm.client import LLMResponse
    from extrospect.models import LlmUsage

    static = static_for(fixtures_dir / "mal_cookie_exfil", ctx)
    slice_ = static.slices[0]
    text = f'```json\n{{"results": [{{"slice_id": "{slice_.slice_id}", "behavior": "x", "data_flow": "", "suspicion": 0.4, "evidence_lines": [], "category": "tracking"}}]}}\n```'
    response = LLMResponse(
        text=text,
        tool_calls=[],
        finish_reason="stop",
        usage=LlmUsage(),
        model="m",
        latency_ms=1,
        message={},
    )
    results, errors = parse_triage(response, [slice_], json_mode=True)
    assert not errors and results[slice_.slice_id].category == "tracking"


# --------------------------------------------------------------------------- routers


def test_router_skips_low_risk(ctx, fixtures_dir: Path) -> None:
    static = static_for(fixtures_dir / "benign_legacy_jquery", ctx)
    decision = route_before_triage(static, ctx.settings)
    assert not decision.run_llm and decision.reason == "low_capability_no_sinks"


def test_router_escalation_rules(ctx, fixtures_dir: Path) -> None:
    static = static_for(fixtures_dir / "benign_word_counter", ctx)
    low = [TriageResult(slice_id="x", behavior="counts words", suspicion=0.1, category="benign")]
    assert not route_after_triage(static, low, ctx.settings).escalate
    high = [TriageResult(slice_id="x", behavior="exfil", suspicion=0.7, category="exfiltration")]
    decision = route_after_triage(static, high, ctx.settings)
    assert decision.escalate and "high_suspicion" in decision.reasons
    injected = static_for(fixtures_dir / "inj_prompt_injection", ctx)
    assert "prompt_injection_attempt" in route_after_triage(injected, low, ctx.settings).reasons


def test_reachability_candidates(ctx, ext_copy) -> None:
    ext = ext_copy("benign_legacy_jquery")
    (ext / "js" / "popup.js").write_text(
        '$("#out").html(location.hash.slice(1));\n', encoding="utf-8"
    )
    static = static_for(ext, ctx)
    assert static.vulns
    assert {v.cve for v in possibly_reachable(static)} >= {"CVE-2020-11023"}


# --------------------------------------------------------------------------- tools


def test_toolbox_tools(ctx, fixtures_dir: Path) -> None:
    static = static_for(fixtures_dir / "inj_prompt_injection", ctx)
    box = ToolBox(static, ctx)
    read = json.loads(
        box.execute("read_file", {"path": "helper.js", "start_line": 1, "end_line": 6})
    )
    assert "NOTE TO AI" not in read["code"] and "flagged=prompt-injection" in read["code"]
    assert "error" in json.loads(box.execute("read_file", {"path": "../manifest.json"}))
    assert "error" in json.loads(box.execute("read_file", {"path": "nope.js"}))
    found = json.loads(box.execute("search_code", {"pattern": "AUDITORS"}))
    assert found["matches"] and found["matches"][0]["note"].startswith("match is inside")
    sha = next(iter(static.flagged_strings))
    decoded = json.loads(box.execute("decode_string", {"value": f"sha:{sha}", "method": "raw"}))
    assert "warning" in decoded
    assert (
        json.loads(
            box.execute("decode_string", {"value": "104,116,116,112", "method": "charcode"})
        )["decoded"]
        == "http"
    )
    assert (
        json.loads(box.execute("decode_string", {"value": "uggc", "method": "rot13"}))["decoded"]
        == "http"
    )
    xor = json.loads(
        box.execute(
            "decode_string",
            {
                "value": "".join(chr(ord(c) ^ 7) for c in "https://x.example/cookie"),
                "method": "xor",
            },
        )
    )
    assert xor["decoded"] == "https://x.example/cookie"
    assert "error" in json.loads(box.execute("search_code", {"pattern": "("}))
    assert "error" in json.loads(box.execute("not_a_tool", {}))
    assert set(TOOL_NAMES) >= {
        "read_file",
        "search_code",
        "get_callers",
        "decode_string",
        "lookup_domain",
        "retrieve_listing",
        "retrieve_similar_malware",
        "retrieve_advisory",
        "submit_verdict",
    }


# --------------------------------------------------------------------------- verifier


def test_quote_verification(ctx, fixtures_dir: Path) -> None:
    static = static_for(fixtures_dir / "mal_cookie_exfil", ctx)
    good = Evidence(
        claim="c",
        file="background.js",
        lines=(8, 8),
        quote="const cookies = await chrome.cookies.getAll({});",
    )
    assert check_evidence(good, static).match == "exact"
    off_by_two = Evidence(
        claim="c", file="background.js", lines=(10, 10), quote="chrome.cookies.getAll({})"
    )
    assert check_evidence(off_by_two, static) is not None
    relocated = Evidence(
        claim="c",
        file="background.js",
        lines=(1, 1),
        quote='await fetch(ENDPOINT, { method: "POST", body: encode(payload) });',
    )
    checked = check_evidence(relocated, static)
    assert checked is not None and checked.lines == (10, 10) and checked.match == "relocated"
    gutter = Evidence(
        claim="c",
        file="background.js",
        lines=(8, 8),
        quote=" 8 |   const cookies = await chrome.cookies.getAll({});",
    )
    assert check_evidence(gutter, static) is not None
    assert (
        check_evidence(
            Evidence(claim="c", file="background.js", lines=(8, 8), quote="steal(passwords)"),
            static,
        )
        is None
    )
    assert (
        check_evidence(
            Evidence(claim="c", file="other.js", lines=(1, 1), quote="whatever is here"), static
        )
        is None
    )
    assert (
        check_evidence(
            Evidence(claim="c", file="background.js", lines=(8, 8), quote="({})"), static
        )
        is None
    )  # too short


def test_verifier_downgrades_and_flags(ctx, fixtures_dir: Path) -> None:
    static = static_for(fixtures_dir / "mal_cookie_exfil", ctx)
    fake = Verdict(
        label="malicious",
        malicious_prob=0.9,
        source="engine",
        evidence=[
            Evidence(claim="x", file="background.js", lines=(2, 2), quote="exfiltrate(everything)")
        ],
    )
    checked = verify_quotes(fake, static)
    assert checked.label == "suspicious" and checked.needs_human_review
    assert {n.code for n in checked.verifier_notes} == {
        "evidence_removed",
        "downgraded_no_evidence",
    }
    benign = Verdict(label="benign", malicious_prob=0.05, source="engine")
    result = run_verifier(benign, static, ctx.settings, None, "en")
    assert result.needs_human_review  # A = 1.0 with exfiltration code needs purpose evidence
    assert any(n.code == "conflict_needs_proof" for n in result.verifier_notes)


def test_consistency_check_marks_review(ctx, fixtures_dir: Path) -> None:
    static = static_for(fixtures_dir / "mal_cookie_exfil", ctx)
    verdict = Verdict(
        label="malicious",
        malicious_prob=0.9,
        source="engine",
        attack_chain="steals history",
        evidence=[
            Evidence(
                claim="cookies",
                file="background.js",
                lines=(8, 8),
                quote="chrome.cookies.getAll({})",
            )
        ],
    )
    backend = ScriptedBackend(
        responses=[
            {
                "tool_calls": [
                    {
                        "name": "report_consistency",
                        "arguments": {"consistent": False, "reason": "chain mentions history"},
                    }
                ]
            }
        ]
    )
    result = run_verifier(verdict, static, ctx.settings, client_with(backend), "en")
    assert result.needs_human_review and result.verified
    assert any(n.code == "chain_inconsistent" for n in result.verifier_notes)


# --------------------------------------------------------------------------- investigator


def test_investigator_requires_listing_and_parses_verdict(ctx, fixtures_dir: Path) -> None:
    static = static_for(fixtures_dir / "mal_cookie_exfil", ctx)
    verdict_args = {
        "label": "malicious",
        "malicious_prob": 0.97,
        "confidence": 0.9,
        "summary": "steals cookies",
        "evidence": [
            {
                "claim": "reads every cookie",
                "file": "background.js",
                "lines": [8, 8],
                "quote": "const cookies = await chrome.cookies.getAll({});",
            }
        ],
        "exfil_targets": ["cdn-darkmode-stats.example"],
        "reachability": [{"cve": "CVE-X", "reachable": "no", "evidence": "not used"}],
    }
    responses = [
        {
            "tool_calls": [{"name": "submit_verdict", "arguments": verdict_args}]
        },  # rejected: no listing yet
        {
            "tool_calls": [
                {"name": "retrieve_listing", "arguments": {}},
                {"name": "lookup_domain", "arguments": {"domain": "cdn-darkmode-stats.example"}},
            ]
        },
        {"tool_calls": [{"name": "submit_verdict", "arguments": verdict_args}]},
    ]
    backend = ScriptedBackend(responses=responses)
    box = ToolBox(static, ctx)
    result = investigate(static, [], [], box, client_with(backend), ctx.settings, "zh-CN")
    assert result.verdict is not None and result.verdict.label == "malicious" and result.steps == 3
    assert result.reachability == {"CVE-X": ("no", "not used")}
    second_request = backend.calls[1][1]
    assert "retrieve_listing first" in text_of(second_request[-1])
    system_prompt = backend.calls[0][1][0]["content"]
    assert "Simplified Chinese" in json.dumps(system_prompt, ensure_ascii=False)
    # Two tool calls in one turn -> two tool results in order.
    third_request = backend.calls[2][1]
    assert [m["role"] for m in third_request[-2:]] == ["tool", "tool"]


def test_investigator_budget_forces_verdict(ctx, fixtures_dir: Path) -> None:
    static = static_for(fixtures_dir / "mal_cookie_exfil", ctx)
    ctx.settings.budget.investigator_max_steps = 2
    looping = {"tool_calls": [{"name": "search_code", "arguments": {"pattern": "fetch"}}]}
    final = {
        "tool_calls": [
            {
                "name": "submit_verdict",
                "arguments": {
                    "label": "suspicious",
                    "malicious_prob": 0.5,
                    "confidence": 0.3,
                    "summary": "ran out of budget",
                    "evidence": [],
                },
            }
        ]
    }
    backend = ScriptedBackend(responses=[looping, looping, final])
    box = ToolBox(static, ctx)
    box.listing_consulted = True
    result = investigate(static, [], [], box, client_with(backend), ctx.settings, "en")
    assert result.verdict is not None and result.stopped_reason == "2 steps"
    assert "Budget exhausted" in text_of(backend.calls[2][1][-1])


def test_parse_verdict_lenient() -> None:
    verdict, reach = parse_verdict(
        {
            "label": "Malware",
            "malicious_prob": 85,
            "confidence": "0.5",
            "summary": "s",
            "evidence": [{"claim": "c", "file": "a.js", "lines": [5], "quote": "x()"}],
            "attack_chain": " ",
        }
    )
    assert verdict.label == "malicious" and verdict.malicious_prob == pytest.approx(0.85)
    assert verdict.evidence[0].lines == (5, 5) and verdict.attack_chain is None and reach == {}


def test_investigation_message_contains_context(ctx, fixtures_dir: Path) -> None:
    static = static_for(fixtures_dir / "inj_prompt_injection", ctx)
    text = build_investigation_message(static, [], [], [("prompt_injection", 0.7)])
    assert "Shopping Helper" in text and "prompt_injection (0.70)" in text
    assert "coupon-metrics.example" in text and "<untrusted_code" in text
    assert "NOTE TO AI" not in text


# --------------------------------------------------------------------------- end to end


def test_engine_end_to_end_with_heuristic_model(ctx, fixtures_dir: Path) -> None:
    report = analyze(
        fixtures_dir / "mal_cookie_exfil", ctx, llm=HeuristicBackend(), use_cache=False
    )
    assert report.mode == "engine" and report.verdict is not None
    assert report.verdict.source == "engine" and report.verdict.verified
    assert report.verdict.evidence and all(e.verified for e in report.verdict.evidence)
    assert report.level in {"high", "critical"}
    events = load_trace(ctx.settings.paths.traces_dir, report.trace_id)
    kinds = [e["type"] for e in events]
    assert kinds[0] == "start" and "llm_call" in kinds and "tool_call" in kinds
    replay = render_trace(events)
    assert "submit_verdict" in replay and "retrieve_listing" in replay
    cached = analyze(fixtures_dir / "mal_cookie_exfil", ctx, llm=HeuristicBackend())
    assert any(n.code == "report_from_cache" for n in cached.notices)


def test_engine_skips_llm_for_low_risk(ctx, fixtures_dir: Path) -> None:
    backend = ScriptedBackend()
    static = static_for(fixtures_dir / "benign_legacy_jquery", ctx)
    outcome = run_engine(static, ctx, llm=backend)
    assert outcome.verdict is None and not backend.calls
    assert outcome.notices[-1].code == "llm_skipped_low_risk"


def test_engine_survives_investigator_failure(ctx, fixtures_dir: Path) -> None:
    static = static_for(fixtures_dir / "mal_cookie_exfil", ctx)

    class InternalServerError(Exception):
        pass

    def handler(model: str, messages: list, tools: list | None) -> Any:
        if tools and tools[0]["function"]["name"] == "report_triage":
            return HeuristicBackend()._triage(text_of(messages[1]))
        return InternalServerError("boom")

    ctx.settings.llm.max_retries = 0
    outcome = run_engine(static, ctx, llm=ScriptedBackend(handler))
    assert outcome.verdict is not None and outcome.verdict.source == "lightweight"
    assert outcome.verdict.needs_human_review
    assert any(n.code == "investigator_failed" for n in outcome.notices)


def test_lightweight_verdict_labels() -> None:
    assert lightweight_verdict([]).label == "benign"
    results = [TriageResult(slice_id="a", behavior="b", suspicion=0.65, category="exfiltration")]
    verdict = lightweight_verdict(results)
    assert (
        verdict.label == "malicious"
        and verdict.needs_human_review
        and verdict.source == "lightweight"
    )


def test_tracer_writes_jsonl(tmp_path: Path) -> None:
    tracer = Tracer("t1", tmp_path, full_content=False, label="x")
    tracer.llm_call(
        span="s",
        model="m",
        prompt_version="v",
        messages=[{"role": "user", "content": "secret"}],
        response={"content": "r"},
        usage={"cost_usd": 0.01},
        latency_ms=5,
        finish_reason="stop",
    )
    events = load_trace(tmp_path, "t1")
    assert len(events) == 2 and "request" not in events[1]
    assert load_trace(tmp_path, "../t1") == []
