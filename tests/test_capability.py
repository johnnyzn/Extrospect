from __future__ import annotations

from pathlib import Path

import pytest

from extrospect.i18n import t
from extrospect.models import ManifestSummary
from extrospect.static.csp import analyze_csp, parse_csp
from extrospect.static.manifest import load_manifest
from extrospect.static.permissions import compute_capability, explain_factor
from extrospect.static.surface import analyze_surface, classify_host_pattern


def capability(ext: Path):
    manifest, _ = load_manifest(ext)
    surface = analyze_surface(ext, manifest)
    return compute_capability(manifest, surface, analyze_csp(manifest)), surface


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        ("<all_urls>", "all"),
        ("*://*/*", "all"),
        ("https://*/*", "all"),
        ("http://*.com/*", "broad"),
        ("https://*.co.uk/*", "broad"),
        ("https://*.google.com/*", "specific"),
        ("https://api.example.com/v1/*", "specific"),
        ("file:///*", "file"),
        ("chrome://favicon/", "other"),
    ],
)
def test_host_pattern_breadth(pattern: str, expected: str) -> None:
    assert classify_host_pattern(pattern) == expected


def test_cookie_stealer_is_critical(fixtures_dir: Path) -> None:
    cap, surface = capability(fixtures_dir / "mal_cookie_exfil")
    assert cap.score == 1.0
    assert "ALL_URLS+COOKIES" in cap.flags
    assert "COMBO_CS_ALL_FRAMES" in cap.flags
    assert surface.cs_all_frames_all_sites
    assert surface.file_contexts["background.js"] == "background"
    assert surface.file_contexts["darkmode.js"] == "content_script"


def test_benign_popup_extension_is_moderate(fixtures_dir: Path) -> None:
    cap, surface = capability(fixtures_dir / "benign_word_counter")
    assert cap.score == pytest.approx(0.4)
    assert surface.file_contexts["popup.js"] == "page"
    assert surface.file_contexts["background.js"] == "background"


def test_mv2_broad_host_implies_script_injection(fixtures_dir: Path) -> None:
    cap, surface = capability(fixtures_dir / "mal_remote_config")
    assert "ALL_URLS+EXECUTESCRIPT_MV2" in cap.flags
    assert {"CSP_UNSAFE_EVAL", "CSP_REMOTE_SCRIPT", "COMBO_OFFSTORE_UPDATE"} <= set(cap.flags)
    assert surface.offstore_update_url


def test_search_hijack_surface(fixtures_dir: Path) -> None:
    cap, surface = capability(fixtures_dir / "mal_search_hijack")
    assert surface.overrides["search_url"].startswith("https://find-quick.example/")
    assert surface.dnr.redirect and surface.dnr.modify_headers
    assert surface.dnr.removed_security_headers == ["content-security-policy"]
    assert {"OVERRIDE_SEARCH", "DNR_MODIFY_HEADERS", "COMBO_DNR_STRIP_SECURITY"} <= set(cap.flags)
    assert surface.page_files["newtab.html"] == "override_newtab"


def test_optional_permissions_count_half(tmp_path: Path) -> None:
    manifest = ManifestSummary(name="x", manifest_version=3, optional_permissions=["debugger"])
    surface = analyze_surface(tmp_path, manifest)
    cap = compute_capability(manifest, surface, [])
    assert cap.score == pytest.approx(0.5)
    assert "OPTIONAL:PERM:debugger" in cap.flags


def test_combo_bonus_adds_015(tmp_path: Path) -> None:
    manifest = ManifestSummary(
        name="x",
        manifest_version=3,
        permissions=["storage"],
        externally_connectable={"matches": ["*://*/*"]},
    )
    cap = compute_capability(manifest, analyze_surface(tmp_path, manifest), [])
    assert cap.combo_count == 1
    assert cap.score == pytest.approx(0.1 + 0.15)


def test_csp_rules() -> None:
    assert parse_csp("script-src 'self' https://a.example; object-src 'self'")["script-src"] == [
        "'self'",
        "https://a.example",
    ]
    mv2 = ManifestSummary(
        name="x",
        manifest_version=2,
        csp="script-src 'self' 'unsafe-eval' https://cdn.example; object-src 'self'",
    )
    codes = {f.code for f in analyze_csp(mv2)}
    assert codes == {"CSP_UNSAFE_EVAL", "CSP_REMOTE_SCRIPT"}
    mv3 = ManifestSummary(
        name="x",
        manifest_version=3,
        csp={
            "extension_pages": "script-src 'self' 'wasm-unsafe-eval'",
            "sandbox": "sandbox allow-scripts; script-src 'self' 'unsafe-eval'",
        },
    )
    weights = {f.code: f.weight for f in analyze_csp(mv3)}
    assert weights == {"CSP_WASM_UNSAFE_EVAL": 0.1, "CSP_SANDBOX_UNSAFE_EVAL": 0.4}
    # Localhost sources are allowed for development and are not "remote".
    dev = ManifestSummary(
        name="x", manifest_version=2, csp="script-src 'self' http://localhost:8080"
    )
    assert analyze_csp(dev) == []


def test_explanations_are_localised(fixtures_dir: Path) -> None:
    cap, _ = capability(fixtures_dir / "mal_cookie_exfil")
    combo = next(f for f in cap.factors if f.code == "COMBO_BROAD_HOST_SENSITIVE")
    assert "cookies" in explain_factor(combo, "en")
    assert "全站访问权限" in explain_factor(combo, "zh-CN")
    assert t("tier.critical", "zh-CN") == "严重"
