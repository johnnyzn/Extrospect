"""Report rendering: Markdown, JSON, self-contained HTML and the rich console view.

Static texts come from the i18n catalogs; LLM-written fields (summary, claims, attack
chain) are already in the requested language; code, quotes, API names and domains are
never translated.
"""

from __future__ import annotations

import html
import json
from collections.abc import Iterable
from typing import Any

from extrospect.i18n import t
from extrospect.models import Notice, Report, Sink, Verdict
from extrospect.static.permissions import explain_factor
from extrospect.util import one_line

LEVEL_COLORS = {
    "benign": "green",
    "low": "cyan",
    "medium": "yellow",
    "high": "red",
    "critical": "bold red",
}
LEVEL_HEX = {
    "benign": "#1a7f37",
    "low": "#0969da",
    "medium": "#9a6700",
    "high": "#cf222e",
    "critical": "#82071e",
}


def level_label(level: str, lang: str | None = None) -> str:
    return t(f"level.{level}", lang)


def label_label(label: str, lang: str | None = None) -> str:
    return t(f"label.{label}", lang)


def sink_label(kind: str, lang: str | None = None) -> str:
    key = f"sink.{kind}"
    text = t(key, lang)
    return kind if text == key else text


def notice_text(notice: Notice, lang: str | None = None) -> str:
    key = f"notice.{notice.code}"
    text = t(key, lang, **notice.params)
    return notice.code if text == key else text


def capability_lines(report: Report, lang: str | None = None) -> list[str]:
    if report.capability.factors:
        return [explain_factor(f, lang) for f in report.capability.factors if f.weight >= 0.1]
    return list(report.capability.explanation)


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _fmt_prob(value: float | None) -> str:
    return "-" if value is None else f"{value:.2f}"


def _epss(finding_epss: float | None, percentile: float | None) -> str:
    if finding_epss is None and percentile is None:
        return "-"
    parts = []
    if finding_epss is not None:
        parts.append(f"{finding_epss * 100:.2f}%")
    if percentile is not None:
        parts.append(f"p{percentile * 100:.0f}")
    return " / ".join(parts)


def _fence(code: str) -> str:
    fence = "```"
    while fence in code:
        fence += "`"
    return f"{fence}js\n{code}\n{fence}"


# --------------------------------------------------------------------------- markdown


def render_markdown(
    report: Report, lang: str | None = None, redact_injections: bool = False
) -> str:
    """Markdown report. ``redact_injections`` hides text aimed at AI reviewers (for MCP clients)."""
    L = lang or report.language
    m = report.manifest
    out: list[str] = []
    level = level_label(report.level, L)
    out.append(f"# {m.name} — {level} ({report.score}/100)")
    out.append("")
    out.append(
        "> "
        + " · ".join(
            [
                f"`{report.ref.id}`",
                f"v{report.ref.version or m.version or '?'}",
                t(f"mode.{report.mode}", L),
                report.created_at.strftime("%Y-%m-%d %H:%M UTC"),
            ]
        )
    )
    if m.description:
        out.append(f"> {one_line(m.description, 300)}")
    out.append("")

    # ---- summary
    out.append(f"## {t('report.summary', L)}")
    out.append("")
    out.append(f"- {t('report.risk_score', L)}: **{report.score}/100** ({level})")
    verdict = report.verdict
    if verdict is not None:
        out.append(
            f"- {t('report.verdict', L)}: **{label_label(verdict.label, L)}** — "
            f"{t('report.malicious_prob', L)} {verdict.malicious_prob:.2f}, "
            f"{t('report.confidence', L)} {verdict.confidence:.2f}"
            + (f" · ⚠️ {t('report.needs_review', L)}" if verdict.needs_human_review else "")
        )
        if verdict.summary:
            out.append(f"- {verdict.summary}")
    else:
        out.append(f"- {t('report.static_only_note', L)}")
    out.append(f"- {t('report.capability', L)}: A = {report.breakdown.A:.2f}")
    if report.injection_attempts:
        out.append(f"- ⚠️ {t('report.injection_detected', L, count=len(report.injection_attempts))}")
    out.append("")

    # ---- breakdown
    b = report.breakdown
    out.append(f"## {t('report.why_score', L)}")
    out.append("")
    out.append(f"| {t('report.term', L)} | {t('report.value', L)} | {t('report.meaning', L)} |")
    out.append("|---|---|---|")
    out.append(f"| A | {b.A:.2f} | {t('report.term_A', L)} |")
    out.append(f"| Ev | {b.Ev:.2f} | {t('report.term_Ev', L)} |")
    out.append(
        f"| Em | {b.Em:.2f} | {t('report.term_Em', L, source=t('em_source.' + b.em_source, L))} |"
    )
    out.append(f"| E | {b.E:.2f} | {t('report.term_E', L)} |")
    out.append(f"| Risk | {report.score} | {t('report.term_risk', L, raw=f'{b.raw:.1f}')} |")
    out.append("")
    extras = []
    if b.hard_rules:
        extras.append(
            t("report.hard_rules", L, rules=", ".join(t(f"rule.{r}", L) for r in b.hard_rules))
        )
    if b.first_party_discount:
        extras.append(t("report.first_party_discount", L))
    if b.one_way_kept_static:
        extras.append(t("report.one_way_kept", L))
    probs = []
    for name, value in (
        ("LLM", b.llm_prob),
        ("GBM", b.gbm_prob),
        (t("report.rules", L), b.rules_prob),
    ):
        if value is not None:
            probs.append(f"{name} {value:.2f}")
    if probs:
        extras.append(t("report.component_probs", L, probs=", ".join(probs)))
    out.extend(f"- {e}" for e in extras)
    if extras:
        out.append("")

    # ---- verdict evidence
    if verdict is not None and (verdict.evidence or verdict.attack_chain):
        out.append(f"## {t('report.evidence', L)}")
        out.append("")
        if verdict.attack_chain:
            out.append(f"**{t('report.attack_chain', L)}:** {verdict.attack_chain}")
            out.append("")
        for idx, ev in enumerate(verdict.evidence, start=1):
            status = "✅" if ev.verified else ("❌" if ev.verified is False else "•")
            out.append(f"{idx}. {status} {ev.claim} — `{ev.file}:{ev.lines[0]}-{ev.lines[1]}`")
            out.append("")
            out.append(_indent(_fence(ev.quote), "   "))
            out.append("")
        if verdict.verifier_notes:
            out.append(f"_{t('report.verifier_notes', L)}:_")
            for note in verdict.verifier_notes:
                out.append(f"- {notice_text(note, L)}")
            out.append("")

    # ---- capabilities
    out.append(f"## {t('report.capabilities', L)}")
    out.append("")
    lines = capability_lines(report, L)
    if lines:
        out.extend(f"- {line}" for line in lines)
    else:
        out.append(f"- {t('report.no_capabilities', L)}")
    out.append("")

    # ---- sinks
    out.append(f"## {t('report.code_findings', L)}")
    out.append("")
    if report.top_sinks:
        out.append(
            f"| {t('report.weight', L)} | {t('report.behavior', L)} | {t('report.location', L)} | API | {t('report.snippet', L)} |"
        )
        out.append("|---|---|---|---|---|")
        for sink in report.top_sinks[:25]:
            snippet = (
                "[redacted]"
                if redact_injections and sink.kind == "prompt_injection"
                else one_line(sink.snippet, 90)
            )
            out.append(
                f"| {sink.weight:.2f} | {_md_escape(sink_label(sink.kind, L))} | `{sink.file}:{sink.line}` | "
                f"`{_md_escape(one_line(sink.api, 60))}` | `{_md_escape(snippet)}` |"
            )
        if len(report.top_sinks) > 25:
            out.append("")
            out.append(t("report.more_findings", L, count=len(report.top_sinks) - 25))
    else:
        out.append(t("report.no_findings", L))
    out.append("")

    # ---- triage
    if report.triage:
        out.append(f"## {t('report.triage', L)}")
        out.append("")
        out.append(
            f"| slice | {t('report.category', L)} | {t('report.suspicion', L)} | {t('report.behavior', L)} |"
        )
        out.append("|---|---|---|---|")
        for tr in sorted(report.triage, key=lambda x: -x.suspicion)[:20]:
            out.append(
                f"| `{tr.slice_id[:8]}` | {t('category.' + tr.category, L)} | {tr.suspicion:.2f} | "
                f"{_md_escape(one_line(tr.behavior, 140))} |"
            )
        out.append("")

    # ---- vulnerabilities
    out.append(f"## {t('report.vulnerabilities', L)}")
    out.append("")
    if report.vulns:
        out.append(
            f"| {t('report.library', L)} | {t('report.version', L)} | ID | {t('report.severity', L)} | EPSS | {t('report.reachable', L)} |"
        )
        out.append("|---|---|---|---|---|---|")
        for v in report.vulns:
            out.append(
                f"| {v.library} | {v.version} | {_md_escape(v.cve)} | {v.severity or '-'} | "
                f"{_epss(v.epss, v.epss_percentile)} | {t('reach.' + v.reachable, L)} |"
            )
    else:
        out.append(t("report.no_vulns", L))
    out.append("")

    # ---- endpoints
    if report.endpoints:
        out.append(f"## {t('report.endpoints', L)}")
        out.append("")
        out.append(
            f"| {t('report.host', L)} | {t('report.first_party', L)} | {t('report.category', L)} | {t('report.location', L)} |"
        )
        out.append("|---|---|---|---|")
        seen: set[str] = set()
        for e in report.endpoints:
            if e.host in seen:
                continue
            seen.add(e.host)
            fp = "-" if e.first_party is None else ("✅" if e.first_party else "❌")
            out.append(f"| `{e.host}` | {fp} | {e.category or '-'} | `{e.file}:{e.line}` |")
            if len(seen) >= 30:
                break
        out.append("")

    # ---- injection attempts
    if report.injection_attempts:
        out.append(f"## {t('report.injection_attempts', L)}")
        out.append("")
        for attempt in report.injection_attempts:
            text = (
                f"[redacted: {len(attempt.text)} chars]"
                if redact_injections
                else f"“{one_line(attempt.text, 160)}”"
            )
            out.append(f"- `{attempt.file}:{attempt.line}` ({attempt.pattern}): {text}")
        out.append("")

    # ---- libraries
    if report.libraries:
        out.append(f"## {t('report.libraries', L)}")
        out.append("")
        for lib in report.libraries:
            state = t("report.stripped", L) if lib.stripped else t("report.kept", L)
            lib_note = f" — {lib.note}" if lib.note else ""
            out.append(
                f"- `{lib.file}`: {lib.name} {lib.version or ''} ({lib.method}, {state}){lib_note}"
            )
        out.append("")

    # ---- stats & notes
    s = report.stats
    out.append(f"## {t('report.analysis', L)}")
    out.append("")
    out.append(
        "- "
        + t(
            "report.stats_line",
            L,
            js=s.js_files,
            lines=s.total_lines,
            analyzed=s.analyzed_lines,
            stripped=s.stripped_files,
            formatted=s.formatted_files,
            deobfuscated=s.deobfuscated_files,
        )
    )
    if report.mode != "static":
        out.append(
            "- "
            + t(
                "report.cost_line",
                L,
                cost=f"{report.cost_usd:.4f}",
                input=report.tokens.get("input", 0),
                output=report.tokens.get("output", 0),
                calls=report.tokens.get("calls", 0),
            )
        )
    out.append(
        f"- {t('report.trace_line', L, trace=report.trace_id, version=report.pipeline_version, seconds=f'{report.duration_s:.1f}')}"
    )
    for notice in report.notices:
        out.append(f"- {notice_text(notice, L)}")
    out.append("")
    out.append(f"_{t('report.line_numbers_note', L)}_")
    return "\n".join(out).rstrip() + "\n"


def _indent(text: str, prefix: str) -> str:
    return "\n".join(prefix + line if line else line for line in text.split("\n"))


# --------------------------------------------------------------------------- json


def render_json(report: Report) -> str:
    return report.model_dump_json(indent=2)


def report_summary(report: Report, lang: str | None = None) -> dict[str, Any]:
    """Compact dict for MCP tool results and batch tables."""
    L = lang or report.language
    return {
        "id": report.ref.id,
        "name": report.manifest.name,
        "version": report.ref.version,
        "score": report.score,
        "level": report.level,
        "level_label": level_label(report.level, L),
        "verdict": report.verdict.label if report.verdict else None,
        "breakdown": report.breakdown.model_dump(),
        "capability_flags": report.capability.flags,
        "sink_counts": report.sink_counts,
        "vulns": len(report.vulns),
        "injection_attempts": len(report.injection_attempts),
        "mode": report.mode,
    }


# --------------------------------------------------------------------------- html

_HTML_TEMPLATE = """<!doctype html>
<html lang="{lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{ --bg:#ffffff; --fg:#1f2328; --muted:#59636e; --border:#d1d9e0; --code:#f6f8fa; --accent:{accent}; }}
@media (prefers-color-scheme: dark) {{
  :root {{ --bg:#0d1117; --fg:#e6edf3; --muted:#9198a1; --border:#3d444d; --code:#161b22; }}
}}
* {{ box-sizing: border-box; }}
body {{ margin:0; background:var(--bg); color:var(--fg); font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI","Noto Sans","PingFang SC","Microsoft YaHei",sans-serif; }}
main {{ max-width: 980px; margin: 0 auto; padding: 24px 16px 64px; }}
h1 {{ font-size: 1.6rem; margin: 0 0 4px; }}
h2 {{ font-size: 1.15rem; margin: 28px 0 8px; padding-bottom: 4px; border-bottom: 1px solid var(--border); }}
.meta {{ color: var(--muted); font-size: .9rem; }}
.badge {{ display:inline-block; padding: 2px 10px; border-radius: 999px; color:#fff; background: var(--accent); font-weight:600; }}
.score {{ font-size: 2.4rem; font-weight: 700; color: var(--accent); }}
table {{ width:100%; border-collapse: collapse; font-size: .9rem; display:block; overflow-x:auto; }}
th, td {{ text-align:left; padding: 6px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }}
code, pre {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .85rem; }}
pre {{ background: var(--code); padding: 10px; border-radius: 6px; overflow-x: auto; }}
code {{ background: var(--code); padding: 1px 4px; border-radius: 4px; word-break: break-all; }}
ul {{ padding-left: 20px; }}
.ok {{ color:#1a7f37; }} .bad {{ color:#cf222e; }}
</style>
</head>
<body><main>
{body}
</main></body></html>
"""


def _h(text: Any) -> str:
    return html.escape(str(text), quote=True)


def _table(headers: Iterable[str], rows: Iterable[Iterable[str]]) -> str:
    head = "".join(f"<th>{h}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def render_html(report: Report, lang: str | None = None) -> str:
    L = lang or report.language
    m = report.manifest
    level = level_label(report.level, L)
    parts: list[str] = []
    parts.append(f"<h1>{_h(m.name)}</h1>")
    parts.append(
        f'<div class="meta"><code>{_h(report.ref.id)}</code> · v{_h(report.ref.version or m.version)} · '
        f"{_h(t('mode.' + report.mode, L))} · {_h(report.created_at.strftime('%Y-%m-%d %H:%M UTC'))}</div>"
    )
    parts.append(
        f'<p><span class="score">{report.score}</span>/100 &nbsp; <span class="badge">{_h(level)}</span></p>'
    )
    if m.description:
        parts.append(f"<p class=meta>{_h(one_line(m.description, 300))}</p>")
    verdict: Verdict | None = report.verdict
    parts.append(f"<h2>{_h(t('report.summary', L))}</h2><ul>")
    if verdict is not None:
        parts.append(
            f"<li>{_h(t('report.verdict', L))}: <b>{_h(label_label(verdict.label, L))}</b> — "
            f"{_h(t('report.malicious_prob', L))} {verdict.malicious_prob:.2f}, {_h(t('report.confidence', L))} {verdict.confidence:.2f}"
            + (f" · ⚠️ {_h(t('report.needs_review', L))}" if verdict.needs_human_review else "")
            + "</li>"
        )
        if verdict.summary:
            parts.append(f"<li>{_h(verdict.summary)}</li>")
    else:
        parts.append(f"<li>{_h(t('report.static_only_note', L))}</li>")
    if report.injection_attempts:
        parts.append(
            f"<li>⚠️ {_h(t('report.injection_detected', L, count=len(report.injection_attempts)))}</li>"
        )
    parts.append("</ul>")

    b = report.breakdown
    parts.append(f"<h2>{_h(t('report.why_score', L))}</h2>")
    parts.append(
        _table(
            [_h(t("report.term", L)), _h(t("report.value", L)), _h(t("report.meaning", L))],
            [
                ["A", f"{b.A:.2f}", _h(t("report.term_A", L))],
                ["Ev", f"{b.Ev:.2f}", _h(t("report.term_Ev", L))],
                [
                    "Em",
                    f"{b.Em:.2f}",
                    _h(t("report.term_Em", L, source=t("em_source." + b.em_source, L))),
                ],
                ["E", f"{b.E:.2f}", _h(t("report.term_E", L))],
                ["Risk", str(report.score), _h(t("report.term_risk", L, raw=f"{b.raw:.1f}"))],
            ],
        )
    )

    if verdict is not None and (verdict.evidence or verdict.attack_chain):
        parts.append(f"<h2>{_h(t('report.evidence', L))}</h2>")
        if verdict.attack_chain:
            parts.append(
                f"<p><b>{_h(t('report.attack_chain', L))}:</b> {_h(verdict.attack_chain)}</p>"
            )
        parts.append("<ol>")
        for ev in verdict.evidence:
            mark = (
                '<span class="ok">✔</span>'
                if ev.verified
                else ('<span class="bad">✘</span>' if ev.verified is False else "•")
            )
            parts.append(
                f"<li>{mark} {_h(ev.claim)} — <code>{_h(ev.file)}:{ev.lines[0]}-{ev.lines[1]}</code>"
                f"<pre>{_h(ev.quote)}</pre></li>"
            )
        parts.append("</ol>")

    parts.append(f"<h2>{_h(t('report.capabilities', L))}</h2><ul>")
    for line in capability_lines(report, L) or [t("report.no_capabilities", L)]:
        parts.append(f"<li>{_h(line)}</li>")
    parts.append("</ul>")

    parts.append(f"<h2>{_h(t('report.code_findings', L))}</h2>")
    if report.top_sinks:
        parts.append(
            _table(
                [
                    _h(t("report.weight", L)),
                    _h(t("report.behavior", L)),
                    _h(t("report.location", L)),
                    "API",
                ],
                [
                    [
                        f"{s.weight:.2f}",
                        _h(sink_label(s.kind, L)),
                        f"<code>{_h(s.file)}:{s.line}</code>",
                        f"<code>{_h(one_line(s.api, 70))}</code>",
                    ]
                    for s in report.top_sinks[:40]
                ],
            )
        )
    else:
        parts.append(f"<p>{_h(t('report.no_findings', L))}</p>")

    parts.append(f"<h2>{_h(t('report.vulnerabilities', L))}</h2>")
    if report.vulns:
        parts.append(
            _table(
                [
                    _h(t("report.library", L)),
                    _h(t("report.version", L)),
                    "ID",
                    _h(t("report.severity", L)),
                    "EPSS",
                    _h(t("report.reachable", L)),
                ],
                [
                    [
                        _h(v.library),
                        _h(v.version),
                        _h(v.cve),
                        _h(v.severity or "-"),
                        _h(_epss(v.epss, v.epss_percentile)),
                        _h(t("reach." + v.reachable, L)),
                    ]
                    for v in report.vulns
                ],
            )
        )
    else:
        parts.append(f"<p>{_h(t('report.no_vulns', L))}</p>")

    if report.endpoints:
        parts.append(f"<h2>{_h(t('report.endpoints', L))}</h2>")
        seen: set[str] = set()
        rows = []
        for e in report.endpoints:
            if e.host in seen:
                continue
            seen.add(e.host)
            fp = "-" if e.first_party is None else ("✔" if e.first_party else "✘")
            rows.append(
                [
                    f"<code>{_h(e.host)}</code>",
                    fp,
                    _h(e.category or "-"),
                    f"<code>{_h(e.file)}:{e.line}</code>",
                ]
            )
        parts.append(
            _table(
                [
                    _h(t("report.host", L)),
                    _h(t("report.first_party", L)),
                    _h(t("report.category", L)),
                    _h(t("report.location", L)),
                ],
                rows[:40],
            )
        )

    if report.injection_attempts:
        parts.append(f"<h2>{_h(t('report.injection_attempts', L))}</h2><ul>")
        for attempt in report.injection_attempts:
            parts.append(
                f"<li><code>{_h(attempt.file)}:{attempt.line}</code> ({_h(attempt.pattern)}): “{_h(one_line(attempt.text, 160))}”</li>"
            )
        parts.append("</ul>")

    parts.append(f"<h2>{_h(t('report.analysis', L))}</h2><ul>")
    s = report.stats
    parts.append(
        "<li>"
        + _h(
            t(
                "report.stats_line",
                L,
                js=s.js_files,
                lines=s.total_lines,
                analyzed=s.analyzed_lines,
                stripped=s.stripped_files,
                formatted=s.formatted_files,
                deobfuscated=s.deobfuscated_files,
            )
        )
        + "</li>"
    )
    if report.mode != "static":
        parts.append(
            "<li>"
            + _h(
                t(
                    "report.cost_line",
                    L,
                    cost=f"{report.cost_usd:.4f}",
                    input=report.tokens.get("input", 0),
                    output=report.tokens.get("output", 0),
                    calls=report.tokens.get("calls", 0),
                )
            )
            + "</li>"
        )
    parts.append(
        "<li>"
        + _h(
            t(
                "report.trace_line",
                L,
                trace=report.trace_id,
                version=report.pipeline_version,
                seconds=f"{report.duration_s:.1f}",
            )
        )
        + "</li>"
    )
    for notice in report.notices:
        parts.append(f"<li>{_h(notice_text(notice, L))}</li>")
    parts.append("</ul>")
    parts.append(f"<p class=meta>{_h(t('report.line_numbers_note', L))}</p>")
    return _HTML_TEMPLATE.format(
        lang=_h(L),
        title=_h(f"{m.name} — {level}"),
        accent=LEVEL_HEX.get(report.level, "#59636e"),
        body="\n".join(parts),
    )


def render(report: Report, fmt: str, lang: str | None = None) -> str:
    if fmt == "json":
        return render_json(report)
    if fmt == "html":
        return render_html(report, lang)
    return render_markdown(report, lang)


def sinks_table_rows(
    sinks: list[Sink], lang: str | None = None, limit: int = 15
) -> list[list[str]]:
    return [
        [f"{s.weight:.2f}", sink_label(s.kind, lang), f"{s.file}:{s.line}", one_line(s.api, 50)]
        for s in sorted(sinks, key=lambda x: -x.weight)[:limit]
    ]


def dumps(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2, default=str)


__all__ = [
    "LEVEL_COLORS",
    "capability_lines",
    "dumps",
    "label_label",
    "level_label",
    "notice_text",
    "render",
    "render_html",
    "render_json",
    "render_markdown",
    "report_summary",
    "sink_label",
    "sinks_table_rows",
]
