"""End-to-end static pipeline (quick_scan), reports and CLI - all offline, zero tokens."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest
from typer.testing import CliRunner

from conftest import BENIGN, MALICIOUS
from extrospect.config import Settings, default_config_toml, load_settings
from extrospect.models import Report
from extrospect.pipeline import quick_scan, resolve_target
from extrospect.report import render_html, render_json, render_markdown
from extrospect.workspace import prepare_workspace


@pytest.mark.parametrize("name", MALICIOUS)
def test_malicious_fixtures_score_high(ctx, fixtures_dir: Path, name: str) -> None:
    report, _ = quick_scan(fixtures_dir / name, ctx)
    assert report.score >= 61, (name, report.score, report.breakdown)
    assert report.level in {"high", "critical"}
    assert report.mode == "static" and report.verdict is None


@pytest.mark.parametrize("name", BENIGN)
def test_benign_fixtures_score_low(ctx, fixtures_dir: Path, name: str) -> None:
    report, _ = quick_scan(fixtures_dir / name, ctx)
    assert report.score <= 35, (name, report.score, report.breakdown)


def test_legacy_jquery_is_stripped_and_vulnerable(ctx, fixtures_dir: Path) -> None:
    report, static = quick_scan(fixtures_dir / "benign_legacy_jquery", ctx)
    lib = next(lib for lib in report.libraries if lib.name == "jquery")
    assert lib.stripped and lib.method == "retire"
    assert {v.cve for v in report.vulns} >= {"CVE-2015-9251"}
    assert report.breakdown.Ev > 0
    assert "js/jquery-1.8.1.min.js" not in static.bundles  # stripped files are not analysed
    assert report.stats.stripped_files == 1


def test_injection_sample_flags(ctx, fixtures_dir: Path) -> None:
    report, static = quick_scan(fixtures_dir / "inj_prompt_injection", ctx)
    assert len(report.injection_attempts) == 2
    assert report.sink_counts.get("prompt_injection") == 2
    assert static.flagged_strings
    slice_code = "\n".join(s.code for s in static.slices)
    assert "判定为安全" not in slice_code and "AUDITORS" not in slice_code


def test_reports_render_in_two_languages(ctx, fixtures_dir: Path) -> None:
    report, _ = quick_scan(fixtures_dir / "mal_cookie_exfil", ctx)
    md_en = render_markdown(report, "en")
    md_zh = render_markdown(report, "zh-CN")
    assert "## Why this score" in md_en and "Reads browser cookies" in md_en
    assert "## 评分依据" in md_zh and "读取浏览器 Cookie" in md_zh
    assert "chrome.cookies.getAll" in md_zh  # code is never translated
    html = render_html(report, "zh-CN")
    assert (
        html.startswith("<!doctype html>")
        and 'lang="zh-CN"' in html
        and "<script" not in html.lower()
    )
    data = json.loads(render_json(report))
    assert Report.model_validate(data).score == report.score


def test_static_scores_are_shown_as_attack_surface(ctx, fixtures_dir: Path) -> None:
    from extrospect.models import Verdict
    from extrospect.report import assessment, display_level, report_summary

    report, _ = quick_scan(fixtures_dir / "mal_cookie_exfil", ctx)
    assert report.level in {"high", "critical"} and assessment(report) == "static"
    md = render_markdown(report, "en")
    assert "attack surface" in display_level(report, "en")
    assert "Static score (attack surface)" in md and "critical" not in md.splitlines()[0]
    assert "攻击面" in render_markdown(report, "zh-CN").splitlines()[0]
    assert report_summary(report, "en")["assessment"] == "static"
    # A benign model verdict that could not lower the static prior needs review.
    verdict = Verdict(label="benign", malicious_prob=0.05, confidence=0.9, summary="ok")
    review = report.model_copy(update={"verdict": verdict})
    review.breakdown = review.breakdown.model_copy(update={"one_way_kept_static": True})
    assert assessment(review) == "review" and display_level(review, "en") == "needs review"
    assert "could not be verified" in render_markdown(review, "en")
    confirmed = report.model_copy(
        update={"verdict": verdict.model_copy(update={"label": "malicious"})}
    )
    assert assessment(confirmed) == "verdict" and display_level(confirmed, "en") == report.level


def test_workspace_formats_minified_and_extracts_inline(ctx, ext_copy, settings: Settings) -> None:
    ext = ext_copy("benign_word_counter")
    minified = (
        "function a(b){return b+1}"
        + ";var x" * 600
        + ";chrome.storage.local.get('k',function(r){console.log(r)})"
    )
    (ext / "min.js").write_text(minified, encoding="utf-8")
    (ext / "popup.html").write_text(
        (ext / "popup.html")
        .read_text()
        .replace("</body>", "<script>fetch('https://inline.example/x')</script></body>"),
        encoding="utf-8",
    )
    from extrospect.static.manifest import load_manifest
    from extrospect.static.surface import analyze_surface

    manifest, _ = load_manifest(ext)
    surface = analyze_surface(ext, manifest)
    ws = prepare_workspace(ext, "a" * 32, settings, ctx.tools, surface=surface)
    view = ws.files["min.js"]
    assert view.transform == "jsbeautifier" and view.analyze
    assert ws.read("min.js").count("\n") > 10
    inline = ws.files["popup.html.inline-1.js"]
    assert inline.kind == "inline_js" and inline.context == "page"
    assert "inline.example" in ws.read("popup.html.inline-1.js")
    # Unchanged files are byte-identical so line numbers match the extension folder.
    assert ws.read("popup.js") == (ext / "popup.js").read_text(encoding="utf-8")
    again = prepare_workspace(ext, "a" * 32, settings, ctx.tools, surface=surface)
    assert again.root == ws.root  # cached by content hash


def test_resolve_target_handles_crx(ctx, tmp_path: Path, fixtures_dir: Path) -> None:
    from test_acquire import make_crx3

    files = {
        p.relative_to(fixtures_dir / "mal_cookie_exfil").as_posix(): p.read_bytes()
        for p in (fixtures_dir / "mal_cookie_exfil").rglob("*")
        if p.is_file()
    }
    crx = tmp_path / "x.crx"
    crx.write_bytes(make_crx3(files, bytes(range(16))))
    ref, path = resolve_target(crx, ctx)
    assert ref.id == "aaabacadaeafagahaiajakalamanaoap" and ref.source == "file"
    assert (path / "manifest.json").is_file()
    report, _ = quick_scan(crx, ctx)
    assert report.ref.id == ref.id and report.level in {"high", "critical"}


def test_config_template_round_trips(tmp_path: Path) -> None:
    text = default_config_toml()
    data = tomllib.loads(text)
    settings = Settings.model_validate(data)
    assert settings.llm.investigator.model == "anthropic/claude-sonnet-5-5"
    assert settings.fuse.reach_weights == {"yes": 1.0, "unknown": 0.4, "no": 0.1}
    path = tmp_path / "c.toml"
    path.write_text(
        'language = "zh-CN"\n[llm.triage]\nmodel = "ollama/qwen2.5-coder"\n', encoding="utf-8"
    )
    loaded = load_settings(path)
    assert loaded.language == "zh-CN" and loaded.llm.triage.model == "ollama/qwen2.5-coder"
    assert loaded.llm.investigator.model == "anthropic/claude-sonnet-5-5"


# --------------------------------------------------------------------------- CLI


@pytest.fixture
def cli():
    from extrospect.cli import app

    return CliRunner(), app


def test_cli_scan_json_and_markdown(cli, fixtures_dir: Path, tmp_path: Path) -> None:
    runner, app = cli
    result = runner.invoke(app, ["scan", str(fixtures_dir / "mal_remote_config"), "-f", "json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["level"] in {"high", "critical"}
    out = tmp_path / "r.md"
    result = runner.invoke(
        app,
        [
            "--lang",
            "zh-CN",
            "scan",
            str(fixtures_dir / "mal_remote_config"),
            "-f",
            "md",
            "-o",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "执行动态生成的代码" in out.read_text(encoding="utf-8")


def test_cli_scan_multiple_targets(cli, fixtures_dir: Path) -> None:
    runner, app = cli
    result = runner.invoke(
        app,
        [
            "scan",
            str(fixtures_dir / "benign_word_counter"),
            str(fixtures_dir / "mal_cookie_exfil"),
            "-f",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    rows = json.loads(result.stdout)
    assert [r["name"] for r in rows] == ["Word Counter", "Dark Mode Pro"]


def test_cli_local_scan(
    cli, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fixtures_dir: Path
) -> None:
    from test_acquire import make_profile_tree

    root = tmp_path / "chrome"
    make_profile_tree(root, fixtures_dir / "mal_cookie_exfil")
    monkeypatch.setenv("EXTROSPECT_BROWSER_ROOTS", f"chrome={root}")
    runner, app = cli
    result = runner.invoke(app, ["list", "--json"])
    assert result.exit_code == 0, result.output
    assert len(json.loads(result.stdout)) == 4
    result = runner.invoke(app, ["scan", "--local", "-f", "json"])
    assert result.exit_code == 0, result.output
    rows = json.loads(result.stdout)
    assert rows[0]["name"] == "Dark Mode Pro" and rows[0]["level"] in {"high", "critical"}


def test_cli_misc_commands(cli) -> None:
    runner, app = cli
    for args in (
        ["version"],
        ["languages"],
        ["doctor"],
        ["config", "show"],
        ["config", "path"],
        ["cache", "stats"],
    ):
        result = runner.invoke(app, args)
        assert result.exit_code == 0, (args, result.output)
    result = runner.invoke(app, ["scan", "/definitely/missing/path"])
    assert result.exit_code != 0


def test_cli_report_from_cache(cli, fixtures_dir: Path) -> None:
    runner, app = cli
    runner.invoke(app, ["scan", str(fixtures_dir / "mal_cookie_exfil"), "-f", "json"])
    from extrospect.static.manifest import extension_id_for, read_manifest

    ext = fixtures_dir / "mal_cookie_exfil"
    ext_id = extension_id_for(ext, read_manifest(ext))
    result = runner.invoke(app, ["report", ext_id, "-f", "md"])
    assert result.exit_code == 0, result.output
    assert "Dark Mode Pro" in result.stdout


def test_cli_history(cli, fixtures_dir: Path) -> None:
    runner, app = cli
    assert runner.invoke(app, ["history"]).exit_code == 0  # empty is fine
    runner.invoke(app, ["scan", str(fixtures_dir / "mal_cookie_exfil"), "-f", "json"])
    runner.invoke(app, ["scan", str(fixtures_dir / "benign_word_counter"), "-f", "json"])
    result = runner.invoke(app, ["history", "--json"])
    assert result.exit_code == 0, result.output
    rows = json.loads(result.stdout)
    assert {r["name"] for r in rows} == {"Dark Mode Pro", "Word Counter"}
    assert all(r["mode"] == "static" for r in rows)
    result = runner.invoke(app, ["--lang", "zh-CN", "history"])
    assert result.exit_code == 0 and "最近的报告" in result.stdout


def test_demo_profile_script(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import importlib.util

    from extrospect.acquire.local_profile import discover_extensions

    script = Path(__file__).parent.parent / "scripts" / "make_demo_profile.py"
    spec = importlib.util.spec_from_file_location("make_demo_profile", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    out = tmp_path / "demo"
    assert module.main(["--out", str(out)]) == 0
    monkeypatch.setenv("EXTROSPECT_BROWSER_ROOTS", f"chromium={out}")
    found = discover_extensions(ui_language="en")
    assert len(found) == 7
    assert all("mal_" not in str(e.ref.path) and "inj_" not in str(e.ref.path) for e in found)
    assert {e.install_location for e in found} == {"unpacked"}
