"""Command line interface (typer + rich).

Command names and flags are English; messages and reports follow ``--lang`` /
``EXTROSPECT_LANG`` / the OS locale (en, zh-CN, ... see ``extrospect languages``).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from extrospect import __version__
from extrospect.config import (
    PIPELINE_VERSION,
    Settings,
    default_config_path,
    default_config_toml,
    load_settings,
)
from extrospect.i18n import (
    LANGUAGE_NAMES,
    available_languages,
    get_language,
    resolve_language,
    set_language,
    t,
)


def _early_language() -> str:
    """Language for --help texts, decided before typer parses argv."""
    argv = sys.argv[1:]
    for i, arg in enumerate(argv):
        if arg == "--lang" and i + 1 < len(argv):
            return resolve_language(argv[i + 1])
        if arg.startswith("--lang="):
            return resolve_language(arg.split("=", 1)[1])
    return resolve_language()


set_language(_early_language())

console = Console()
err_console = Console(stderr=True)

app = typer.Typer(
    name="extrospect",
    help=t("cli.app_help"),
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
)
config_app = typer.Typer(help=t("cli.config_help"), no_args_is_help=True)
trace_app = typer.Typer(help=t("cli.trace_help"), no_args_is_help=True)
cache_app = typer.Typer(help=t("cli.cache_help"), no_args_is_help=True)
knowledge_app = typer.Typer(help=t("cli.knowledge_help"), no_args_is_help=True)
app.add_typer(config_app, name="config")
app.add_typer(trace_app, name="trace")
app.add_typer(cache_app, name="cache")
app.add_typer(knowledge_app, name="knowledge")


class _State:
    lang: str | None = None
    config: Path | None = None
    offline: bool = False
    verbose: bool = False


STATE = _State()


def _settings(overrides: dict[str, Any] | None = None) -> Settings:
    data: dict[str, Any] = dict(overrides or {})
    if STATE.offline:
        data.setdefault("network", {})["offline"] = True
    settings = load_settings(STATE.config, data)
    lang = resolve_language(STATE.lang, None if settings.language == "auto" else settings.language)
    set_language(lang)
    return settings


def _context(overrides: dict[str, Any] | None = None) -> Any:
    from extrospect.pipeline import Context

    settings = _settings(overrides)
    return Context.create(settings=settings, language=get_language())


def _fail(message: str, code: int = 1) -> None:
    err_console.print(f"[bold red]✗[/] {message}")
    raise typer.Exit(code)


def _level_text(level: str) -> Text:
    from extrospect.report import LEVEL_COLORS, level_label

    return Text(level_label(level), style=LEVEL_COLORS.get(level, ""))


@app.callback()
def main_callback(
    lang: Annotated[str | None, typer.Option("--lang", help=t("cli.opt_lang"))] = None,
    config: Annotated[Path | None, typer.Option("--config", help=t("cli.opt_config"))] = None,
    offline: Annotated[bool, typer.Option("--offline", help=t("cli.opt_offline"))] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help=t("cli.opt_verbose"))] = False,
) -> None:
    STATE.lang = lang
    STATE.config = config
    STATE.offline = offline
    STATE.verbose = verbose
    if lang:
        set_language(resolve_language(lang))


# --------------------------------------------------------------------------- version / languages


@app.command("version", help=t("cli.version_help"))
def version_cmd() -> None:
    console.print(f"extrospect {__version__} (pipeline {PIPELINE_VERSION})")


@app.command("languages", help=t("cli.languages_help"))
def languages_cmd() -> None:
    _settings()
    table = Table(title=t("cli.languages_title"))
    table.add_column(t("cli.col_code"))
    table.add_column(t("cli.col_language"))
    table.add_column(t("cli.col_ui_catalog"))
    shipped = set(available_languages())
    for code, name in LANGUAGE_NAMES.items():
        table.add_row(code, name, "✔" if code in shipped else "LLM only")
    console.print(table)
    console.print(t("cli.languages_note", current=get_language()))


# --------------------------------------------------------------------------- list


@app.command("list", help=t("cli.list_help"))
def list_cmd(
    include_components: Annotated[
        bool, typer.Option("--all", help=t("cli.opt_all_components"))
    ] = False,
    as_json: Annotated[bool, typer.Option("--json", help=t("cli.opt_json"))] = False,
) -> None:
    from extrospect.acquire.local_profile import discover_extensions

    _settings()
    extensions = discover_extensions(
        include_components=include_components, ui_language=get_language()
    )
    if as_json:
        console.print_json(
            json.dumps([e.model_dump(mode="json") for e in extensions], ensure_ascii=False)
        )
        return
    if not extensions:
        console.print(t("cli.no_extensions_found"))
        return
    table = Table(title=t("cli.list_title", count=len(extensions)))
    for col in (
        "col_browser",
        "col_profile",
        "col_name",
        "col_id",
        "col_version",
        "col_enabled",
        "col_source",
    ):
        table.add_column(t(f"cli.{col}"))
    for ext in extensions:
        enabled = "-" if ext.enabled is None else ("✔" if ext.enabled else "✘")
        table.add_row(
            ext.ref.browser or "-",
            ext.profile_name or ext.ref.profile or "-",
            ext.name,
            ext.ref.id,
            ext.ref.version or "-",
            enabled,
            ext.install_location or "-",
        )
    console.print(table)


# --------------------------------------------------------------------------- scan


def _write_or_print(text: str, output: Path | None) -> None:
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        err_console.print(t("cli.written_to", path=str(output)))
    else:
        console.print(text, markup=False, highlight=False, soft_wrap=True)


def _print_report(report: Any, fmt: str, output: Path | None) -> None:
    from extrospect.report import render

    if fmt in {"md", "markdown", "json", "html"}:
        _write_or_print(render(report, "md" if fmt == "markdown" else fmt, get_language()), output)
        return
    _print_report_console(report)
    if output:
        suffix = output.suffix.lower().lstrip(".")
        _write_or_print(
            render(report, suffix if suffix in {"json", "html"} else "md", get_language()), output
        )


def _print_report_console(report: Any) -> None:
    from extrospect.report import capability_lines, label_label, notice_text, sink_label
    from extrospect.util import one_line

    header = Text()
    header.append(f"{report.manifest.name}  ", style="bold")
    header.append(
        f"{report.ref.id}  v{report.ref.version or report.manifest.version}\n", style="dim"
    )
    header.append(t("cli.score_line", score=report.score) + "  ")
    header.append_text(_level_text(report.level))
    b = report.breakdown
    header.append(
        f"\nA={b.A:.2f}  Ev={b.Ev:.2f}  Em={b.Em:.2f} ({t('em_source.' + b.em_source)})  E={b.E:.2f}",
        style="dim",
    )
    if report.verdict is not None:
        v = report.verdict
        header.append(
            f"\n{t('report.verdict')}: {label_label(v.label)}  p={v.malicious_prob:.2f}  conf={v.confidence:.2f}"
        )
        if v.needs_human_review:
            header.append(f"  ⚠ {t('report.needs_review')}", style="yellow")
        if v.summary:
            header.append(f"\n{v.summary}")
    console.print(Panel(header, title=t(f"mode.{report.mode}"), expand=False))

    caps = capability_lines(report)
    if caps:
        console.print(f"[bold]{t('report.capabilities')}[/]")
        for line in caps[:12]:
            console.print(f"  • {line}", highlight=False)
    if report.verdict is not None and report.verdict.evidence:
        console.print(f"[bold]{t('report.evidence')}[/]")
        for ev in report.verdict.evidence[:8]:
            mark = "[green]✔[/]" if ev.verified else "[red]✘[/]" if ev.verified is False else "•"
            console.print(
                f"  {mark} {ev.claim} [dim]{ev.file}:{ev.lines[0]}-{ev.lines[1]}[/]",
                highlight=False,
            )
    if report.top_sinks:
        table = Table(title=t("report.code_findings"), show_lines=False)
        for col in ("report.weight", "report.behavior", "report.location", "report.snippet"):
            table.add_column(t(col))
        for sink in report.top_sinks[:12]:
            table.add_row(
                f"{sink.weight:.2f}",
                sink_label(sink.kind),
                f"{sink.file}:{sink.line}",
                one_line(sink.snippet, 70),
            )
        console.print(table)
    if report.vulns:
        table = Table(title=t("report.vulnerabilities"))
        for col in ("report.library", "report.version", "ID", "report.severity", "EPSS"):
            table.add_column(t(col) if "." in col else col)
        for v in report.vulns[:15]:
            epss = "-" if v.epss_percentile is None else f"p{v.epss_percentile * 100:.0f}"
            table.add_row(v.library, v.version, v.cve, v.severity or "-", epss)
        console.print(table)
    if report.injection_attempts:
        console.print(
            f"[bold red]⚠ {t('report.injection_detected', count=len(report.injection_attempts))}[/]"
        )
    for notice in report.notices:
        style = "yellow" if notice.level == "warning" else "dim"
        console.print(f"[{style}]• {notice_text(notice)}[/]", highlight=False)
    if report.mode != "static":
        console.print(
            "[dim]"
            + t(
                "report.cost_line",
                cost=f"{report.cost_usd:.4f}",
                input=report.tokens.get("input", 0),
                output=report.tokens.get("output", 0),
                calls=report.tokens.get("calls", 0),
            )
            + "[/]"
        )


def _scan_local(ctx: Any, fmt: str, output: Path | None, include_disabled: bool) -> None:
    from extrospect.acquire.local_profile import discover_extensions
    from extrospect.pipeline import build_report, save_report
    from extrospect.static.analyzer import run_static

    extensions = discover_extensions(ui_language=ctx.language)
    if not include_disabled:
        extensions = [e for e in extensions if e.enabled is not False]
    if not extensions:
        console.print(t("cli.no_extensions_found"))
        return
    rows = []
    with console.status(t("cli.scanning_local", count=len(extensions))):
        for ext in extensions:
            assert ext.ref.path is not None
            try:
                static = run_static(
                    ext.ref.path,
                    ext.ref,
                    ctx.settings,
                    tools=ctx.tools,
                    cache=ctx.cache,
                    http=ctx.http,
                    language=ctx.language,
                )
            except Exception as exc:  # keep scanning the others
                err_console.print(f"[red]✗[/] {ext.name} ({ext.ref.id}): {exc}")
                continue
            report = build_report(static, ctx)
            save_report(report, ctx)
            rows.append((ext, report))
    rows.sort(key=lambda r: -r[1].score)
    if fmt == "json":
        payload = [
            {"browser": e.ref.browser, "profile": e.ref.profile, **_summary(r)} for e, r in rows
        ]
        _write_or_print(json.dumps(payload, ensure_ascii=False, indent=2), output)
        return
    table = Table(title=t("cli.local_scan_title", count=len(rows)))
    for col in (
        "col_score",
        "col_level",
        "col_name",
        "col_id",
        "col_version",
        "col_browser",
        "col_capability",
        "col_cves",
        "col_sinks",
    ):
        table.add_column(t(f"cli.{col}"))
    for ext, report in rows:
        top_kinds = ", ".join(list(report.sink_counts)[:3]) or "-"
        table.add_row(
            str(report.score),
            _level_text(report.level),
            ext.name,
            ext.ref.id,
            ext.ref.version or "-",
            f"{ext.ref.browser}/{ext.profile_name or ext.ref.profile}",
            f"{report.capability.score:.2f}",
            str(len(report.vulns)),
            f"{sum(report.sink_counts.values())} ({top_kinds})",
        )
    console.print(table)
    console.print(t("cli.local_scan_hint"))


def _summary(report: Any) -> dict[str, Any]:
    from extrospect.report import report_summary

    return report_summary(report, get_language())


@app.command("scan", help=t("cli.scan_help"))
def scan_cmd(
    targets: Annotated[list[str] | None, typer.Argument(help=t("cli.arg_targets"))] = None,
    local: Annotated[bool, typer.Option("--local", help=t("cli.opt_local"))] = False,
    ext_id: Annotated[list[str] | None, typer.Option("--id", help=t("cli.opt_id"))] = None,
    fmt: Annotated[str, typer.Option("--format", "-f", help=t("cli.opt_format"))] = "console",
    output: Annotated[Path | None, typer.Option("--output", "-o", help=t("cli.opt_output"))] = None,
    no_download: Annotated[
        bool, typer.Option("--no-download", help=t("cli.opt_no_download"))
    ] = False,
    include_disabled: Annotated[
        bool, typer.Option("--include-disabled", help=t("cli.opt_include_disabled"))
    ] = True,
) -> None:
    from extrospect.pipeline import TargetError, quick_scan

    ctx = _context()
    try:
        if local:
            _scan_local(ctx, fmt, output, include_disabled)
            return
        all_targets = list(targets or []) + list(ext_id or [])
        if not all_targets:
            _fail(t("cli.no_target"))
        reports = []
        for target in all_targets:
            try:
                with console.status(t("cli.scanning", target=target)):
                    report, _ = quick_scan(
                        target,
                        ctx,
                        prefer_local=not ext_id or target not in (ext_id or []),
                        allow_download=not no_download,
                    )
            except (TargetError, FileNotFoundError, ValueError, RuntimeError) as exc:
                err_console.print(f"[red]✗[/] {target}: {exc}")
                continue
            reports.append(report)
            if len(all_targets) == 1:
                _print_report(report, fmt, output)
        if len(all_targets) > 1:
            if fmt == "json":
                _write_or_print(
                    json.dumps([_summary(r) for r in reports], ensure_ascii=False, indent=2), output
                )
            else:
                table = Table()
                for col in (
                    "col_score",
                    "col_level",
                    "col_name",
                    "col_id",
                    "col_capability",
                    "col_cves",
                    "col_sinks",
                ):
                    table.add_column(t(f"cli.{col}"))
                for r in sorted(reports, key=lambda x: -x.score):
                    table.add_row(
                        str(r.score),
                        _level_text(r.level),
                        r.manifest.name,
                        r.ref.id,
                        f"{r.capability.score:.2f}",
                        str(len(r.vulns)),
                        str(sum(r.sink_counts.values())),
                    )
                console.print(table)
        if not reports:
            raise typer.Exit(1)
    finally:
        ctx.close()


# --------------------------------------------------------------------------- analyze (Engine mode)


@app.command("analyze", help=t("cli.analyze_help"))
def analyze_cmd(
    target: Annotated[str, typer.Argument(help=t("cli.arg_target"))],
    fmt: Annotated[str, typer.Option("--format", "-f", help=t("cli.opt_format"))] = "console",
    output: Annotated[Path | None, typer.Option("--output", "-o", help=t("cli.opt_output"))] = None,
    no_cache: Annotated[bool, typer.Option("--no-cache", help=t("cli.opt_no_cache"))] = False,
    no_download: Annotated[
        bool, typer.Option("--no-download", help=t("cli.opt_no_download"))
    ] = False,
    triage_model: Annotated[
        str | None, typer.Option("--triage-model", help=t("cli.opt_triage_model"))
    ] = None,
    investigator_model: Annotated[
        str | None, typer.Option("--investigator-model", help=t("cli.opt_investigator_model"))
    ] = None,
    max_cost: Annotated[
        float | None, typer.Option("--max-cost", help=t("cli.opt_max_cost"))
    ] = None,
) -> None:
    from extrospect.llm.client import LlmUnavailable
    from extrospect.pipeline import TargetError, analyze

    overrides: dict[str, Any] = {}
    if triage_model:
        overrides.setdefault("llm", {}).setdefault("triage", {})["model"] = triage_model
        overrides["llm"].setdefault("verifier", {})["model"] = triage_model
    if investigator_model:
        overrides.setdefault("llm", {}).setdefault("investigator", {})["model"] = investigator_model
    if max_cost is not None:
        overrides.setdefault("budget", {})["analysis_max_cost_usd"] = max_cost
    ctx = _context(overrides)
    try:
        with console.status(t("cli.analyzing", target=target)):
            report = analyze(target, ctx, allow_download=not no_download, use_cache=not no_cache)
    except LlmUnavailable as exc:
        _fail(t("cli.llm_unavailable", error=str(exc)))
    except (TargetError, FileNotFoundError, ValueError) as exc:
        _fail(f"{target}: {exc}")
    else:
        _print_report(report, fmt, output)
    finally:
        ctx.close()


# --------------------------------------------------------------------------- report / download


@app.command("report", help=t("cli.report_help"))
def report_cmd(
    ext_id: Annotated[str, typer.Argument(help=t("cli.arg_ext_id"))],
    mode: Annotated[str | None, typer.Option("--mode", help=t("cli.opt_mode"))] = None,
    fmt: Annotated[str, typer.Option("--format", "-f", help=t("cli.opt_format"))] = "md",
    output: Annotated[Path | None, typer.Option("--output", "-o", help=t("cli.opt_output"))] = None,
) -> None:
    from extrospect.models import Report

    ctx = _context()
    try:
        data = ctx.cache.latest_report(ext_id, mode)
        if data is None:
            _fail(t("cli.no_report", ext_id=ext_id))
        _print_report(Report.model_validate(data), fmt, output)
    finally:
        ctx.close()


@app.command("history", help=t("cli.history_help"))
def history_cmd(
    limit: Annotated[int, typer.Option("--limit", help=t("cli.opt_limit"))] = 30,
    mode: Annotated[str | None, typer.Option("--mode", help=t("cli.opt_mode"))] = None,
    as_json: Annotated[bool, typer.Option("--json", help=t("cli.opt_json"))] = False,
) -> None:
    from extrospect.models import Report

    ctx = _context()
    try:
        seen: set[tuple[str, str]] = set()
        reports: list[Report] = []
        for ext_id, _version, report_mode, _created in ctx.cache.list_reports(limit * 5):
            if (mode and report_mode != mode) or (ext_id, report_mode) in seen:
                continue
            seen.add((ext_id, report_mode))
            data = ctx.cache.latest_report(ext_id, report_mode)
            if data:
                reports.append(Report.model_validate(data))
            if len(reports) >= limit:
                break
    finally:
        ctx.close()
    if as_json:
        rows = []
        for r in reports:
            v = r.verdict
            rows.append(
                {
                    "created": r.created_at.isoformat(),
                    "mode": r.mode,
                    "id": r.ref.id,
                    "name": r.manifest.name,
                    "score": r.score,
                    "level": r.level,
                    "verdict": v.label if v else None,
                    "evidence_verified": sum(1 for e in v.evidence if e.verified) if v else 0,
                    "needs_human_review": v.needs_human_review if v else None,
                    "breakdown": r.breakdown.model_dump(exclude_none=True),
                }
            )
        console.print_json(json.dumps(rows, ensure_ascii=False))
        return
    if not reports:
        console.print(t("cli.no_history"))
        return
    table = Table(title=t("cli.history_title", count=len(reports)))
    for col in (
        "col_time",
        "col_mode",
        "col_name",
        "col_id",
        "col_score",
        "col_level",
        "col_verdict",
        "col_evidence",
    ):
        table.add_column(t(f"cli.{col}"))
    for r in reports:
        v = r.verdict
        evidence = f"{sum(1 for e in v.evidence if e.verified)}/{len(v.evidence)}" if v else "-"
        verdict = "-" if v is None else v.label + (" ⚠" if v.needs_human_review else "")
        table.add_row(
            r.created_at.astimezone().strftime("%m-%d %H:%M"),
            r.mode,
            r.manifest.name,
            r.ref.id,
            str(r.score),
            _level_text(r.level),
            verdict,
            evidence,
        )
    console.print(table)


@app.command("download", help=t("cli.download_help"))
def download_cmd(
    ext_id: Annotated[str, typer.Argument(help=t("cli.arg_ext_id"))],
    out: Annotated[Path | None, typer.Option("--out", help=t("cli.opt_out_dir"))] = None,
    unpack: Annotated[bool, typer.Option("--unpack", help=t("cli.opt_unpack"))] = False,
) -> None:
    from extrospect.acquire.crx_download import DownloadError, download_crx
    from extrospect.acquire.unpack import unpack_file

    ctx = _context()
    try:
        result = download_crx(ext_id, ctx.settings, ctx.http, dest_dir=out)
        console.print(
            t("cli.downloaded", path=str(result.path), size=result.size, sha=result.sha256[:16])
        )
        if unpack:
            dest = result.path.with_suffix("")
            unpack_file(result.path, dest)
            console.print(t("cli.unpacked_to", path=str(dest)))
    except DownloadError as exc:
        _fail(str(exc))
    finally:
        ctx.close()


# --------------------------------------------------------------------------- doctor


@app.command("doctor", help=t("cli.doctor_help"))
def doctor_cmd() -> None:
    from extrospect.acquire.local_profile import default_roots
    from extrospect.static.nodetools import resolve_tools, tool_version

    settings = _settings()
    tools = resolve_tools(settings.tools)
    table = Table(title=t("cli.doctor_title"))
    table.add_column(t("cli.col_check"))
    table.add_column(t("cli.col_status"))
    table.add_column(t("cli.col_detail"))

    def row(name: str, ok: bool | None, detail: str) -> None:
        mark = "[green]✔[/]" if ok else "[yellow]–[/]" if ok is None else "[red]✘[/]"
        table.add_row(name, mark, detail)

    row("Python", True, sys.version.split()[0])
    row("extrospect", True, f"{__version__} / pipeline {PIPELINE_VERSION}")
    row(t("cli.doctor_language"), True, f"{get_language()} ({', '.join(available_languages())})")
    config_path = STATE.config or default_config_path()
    row(t("cli.doctor_config"), config_path.is_file() or None, str(config_path))
    row(t("cli.doctor_data_dir"), True, str(settings.paths.data_dir))
    for name, path in (
        ("webcrack", tools.webcrack),
        ("prettier", tools.prettier),
        ("retire", tools.retire),
    ):
        row(
            name,
            bool(path) or None,
            (tool_version(path) or path) if path else t("cli.doctor_optional_missing", tool=name),
        )
    try:
        import litellm  # noqa: F401

        row("litellm", True, t("cli.doctor_engine_ready"))
    except ImportError:
        row("litellm", None, t("cli.doctor_install_llm"))
    keys = [
        k
        for k in (
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
            "GEMINI_API_KEY",
            "OPENROUTER_API_KEY",
            "AZURE_API_KEY",
        )
        if os.environ.get(k)
    ]
    row(
        t("cli.doctor_api_keys"),
        bool(keys) or None,
        ", ".join(keys) if keys else t("cli.doctor_no_keys"),
    )
    row(
        t("cli.doctor_models"),
        True,
        f"triage={settings.llm.triage.model}, investigator={settings.llm.investigator.model}",
    )
    try:
        import lancedb  # noqa: F401

        row("lancedb", True, t("cli.doctor_rag_ready"))
    except ImportError:
        row("lancedb", None, t("cli.doctor_rag_fallback"))
    roots = default_roots()
    row(
        t("cli.doctor_browsers"),
        bool(roots) or None,
        ", ".join(f"{r.browser}:{r.path}" for r in roots) or t("cli.doctor_no_browsers"),
    )
    row(
        t("cli.doctor_network"),
        not settings.network.offline,
        t("cli.doctor_offline") if settings.network.offline else t("cli.doctor_online"),
    )
    console.print(table)


# --------------------------------------------------------------------------- config


@config_app.command("path", help=t("cli.config_path_help"))
def config_path_cmd() -> None:
    console.print(str(STATE.config or default_config_path()))


@config_app.command("show", help=t("cli.config_show_help"))
def config_show_cmd() -> None:
    settings = _settings()
    console.print(default_config_toml(settings), markup=False, highlight=False)


@config_app.command("init", help=t("cli.config_init_help"))
def config_init_cmd(
    force: Annotated[bool, typer.Option("--force", help=t("cli.opt_force"))] = False,
) -> None:
    path = STATE.config or default_config_path()
    if path.exists() and not force:
        _fail(t("cli.config_exists", path=str(path)))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(default_config_toml(), encoding="utf-8")
    console.print(t("cli.config_written", path=str(path)))


# --------------------------------------------------------------------------- cache


@cache_app.command("stats", help=t("cli.cache_stats_help"))
def cache_stats_cmd() -> None:
    ctx = _context()
    try:
        for key, value in ctx.cache.stats().items():
            console.print(f"{key}: {value}")
        console.print(f"db: {ctx.settings.paths.cache_db}")
    finally:
        ctx.close()


@cache_app.command("clear", help=t("cli.cache_clear_help"))
def cache_clear_cmd(
    yes: Annotated[bool, typer.Option("--yes", "-y", help=t("cli.opt_yes"))] = False,
) -> None:
    import shutil

    ctx = _context()
    try:
        if not yes and not typer.confirm(t("cli.confirm_clear")):
            raise typer.Exit(0)
        ctx.cache.clear()
        shutil.rmtree(ctx.settings.paths.work_dir, ignore_errors=True)
        console.print(t("cli.cache_cleared"))
    finally:
        ctx.close()


# --------------------------------------------------------------------------- traces


@trace_app.command("list", help=t("cli.trace_list_help"))
def trace_list_cmd(
    limit: Annotated[int, typer.Option("--limit", help=t("cli.opt_limit"))] = 20,
) -> None:
    from extrospect.trace import list_traces

    settings = _settings()
    table = Table()
    table.add_column("trace")
    table.add_column(t("cli.col_name"))
    table.add_column(t("cli.col_events"))
    table.add_column(t("cli.col_cost"))
    for info in list_traces(settings.paths.traces_dir, limit):
        table.add_row(
            info["trace_id"],
            info.get("label") or "-",
            str(info["events"]),
            f"${info['cost_usd']:.4f}",
        )
    console.print(table)


@trace_app.command("show", help=t("cli.trace_show_help"))
def trace_show_cmd(
    trace_id: Annotated[str, typer.Argument(help="trace id")],
    full: Annotated[bool, typer.Option("--full", help=t("cli.opt_full"))] = False,
) -> None:
    from extrospect.trace import load_trace, render_trace

    settings = _settings()
    events = load_trace(settings.paths.traces_dir, trace_id)
    if not events:
        _fail(t("cli.no_trace", trace_id=trace_id))
    console.print(render_trace(events, full=full), markup=False, highlight=False)


# --------------------------------------------------------------------------- knowledge (RAG)


@knowledge_app.command("stats", help=t("cli.knowledge_stats_help"))
def knowledge_stats_cmd() -> None:
    from extrospect.knowledge.store import open_store

    settings = _settings()
    store = open_store(settings)
    for collection, count in store.stats().items():
        console.print(f"{collection}: {count}")
    console.print(f"backend: {store.backend}  path: {settings.paths.knowledge_dir}")


@knowledge_app.command("build-intel", help=t("cli.knowledge_build_intel_help"))
def knowledge_build_intel_cmd(
    dataset: Annotated[Path | None, typer.Option("--dataset", help=t("cli.opt_dataset"))] = None,
    samples: Annotated[Path | None, typer.Option("--samples", help=t("cli.opt_samples"))] = None,
    split: Annotated[str, typer.Option("--split", help=t("cli.opt_split"))] = "train",
) -> None:
    from extrospect.knowledge.intel import build_intel

    ctx = _context()
    try:
        count = build_intel(ctx, dataset=dataset, samples_dir=samples, split=split)
        console.print(t("cli.intel_built", count=count))
    finally:
        ctx.close()


@knowledge_app.command("build-advisories", help=t("cli.knowledge_build_advisories_help"))
def knowledge_build_advisories_cmd(
    cves: Annotated[
        list[str] | None,
        typer.Argument(help="CVE ids (default: all CVEs in the retire.js repository)"),
    ] = None,
    limit: Annotated[int, typer.Option("--limit", help=t("cli.opt_limit"))] = 200,
) -> None:
    from extrospect.knowledge.advisory import build_advisories

    ctx = _context()
    try:
        count = build_advisories(ctx, cves=cves, limit=limit)
        console.print(t("cli.advisories_built", count=count))
    finally:
        ctx.close()


@knowledge_app.command("listing", help=t("cli.knowledge_listing_help"))
def knowledge_listing_cmd(
    ext_id: Annotated[str, typer.Argument(help=t("cli.arg_ext_id"))],
    refresh: Annotated[bool, typer.Option("--refresh", help=t("cli.opt_refresh"))] = False,
) -> None:
    from extrospect.knowledge.listing import get_listing

    ctx = _context()
    try:
        listing = get_listing(ext_id, ctx, refresh=refresh)
        console.print_json(listing.model_dump_json() if listing else "null")
    finally:
        ctx.close()


def main() -> None:
    app()


if __name__ == "__main__":
    main()
