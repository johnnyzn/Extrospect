from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from extrospect.static.manifest import (
    ManifestError,
    extension_id_for,
    id_from_manifest_key,
    load_manifest,
    parse_json_lenient,
    read_manifest,
    strip_json_noise,
    summarize_manifest,
)


def test_lenient_json_handles_comments_and_trailing_commas() -> None:
    text = """{
      // line comment
      "a": "http://x.example/path", /* block
      comment */ "b": [1, 2, ],
      "c": "// not a comment",
    }"""
    data = parse_json_lenient(text)
    assert data == {"a": "http://x.example/path", "b": [1, 2], "c": "// not a comment"}
    # Line structure is preserved so JSON error positions stay meaningful.
    assert strip_json_noise(text).count("\n") == text.count("\n")


def test_bom_is_accepted() -> None:
    assert parse_json_lenient(chr(0xFEFF) + '{"x": 1}') == {"x": 1}


def test_message_resolution_follows_ui_language(fixtures_dir: Path) -> None:
    ext = fixtures_dir / "benign_word_counter"
    en, _ = load_manifest(ext, "en")
    zh, _ = load_manifest(ext, "zh-CN")
    fr, _ = load_manifest(ext, "fr")
    assert en.name == "Word Counter"
    assert zh.name == "字数统计"
    assert zh.description == "统计当前页面的字数。"
    assert fr.name == "Word Counter"  # falls back to default_locale
    assert en.name_raw == "__MSG_appName__"


def test_mv2_permissions_are_split_into_hosts(fixtures_dir: Path) -> None:
    manifest, _ = load_manifest(fixtures_dir / "mal_remote_config")
    assert manifest.manifest_version == 2
    assert "<all_urls>" in manifest.host_permissions
    assert "<all_urls>" not in manifest.permissions
    assert {"tabs", "webRequest", "webRequestBlocking"} <= set(manifest.permissions)
    assert isinstance(manifest.csp, str)
    assert manifest.pages["popup"] == "popup.html"


def test_mv2_war_and_content_scripts_are_normalised(tmp_path: Path) -> None:
    raw = {
        "manifest_version": 2,
        "name": "x",
        "version": "1",
        "web_accessible_resources": ["img/*.png"],
        "content_scripts": [{"matches": ["<all_urls>"], "js": ["/cs.js"], "all_frames": True}],
        "optional_permissions": ["https://*/*", "bookmarks"],
        "author": {"email": "dev@example.org"},
    }
    summary = summarize_manifest(tmp_path, raw)
    assert summary.web_accessible_resources == [
        {"resources": ["img/*.png"], "matches": ["<all_urls>"], "legacy_mv2": True}
    ]
    assert summary.content_scripts[0]["js"] == ["cs.js"]
    assert summary.optional_host_permissions == ["https://*/*"]
    assert summary.optional_permissions == ["bookmarks"]
    assert summary.author == "dev@example.org"


def test_missing_manifest_raises(tmp_path: Path) -> None:
    with pytest.raises(ManifestError):
        read_manifest(tmp_path)
    (tmp_path / "manifest.json").write_text("[1, 2]")
    with pytest.raises(ManifestError):
        read_manifest(tmp_path)


def test_extension_ids_are_well_formed(tmp_path: Path) -> None:
    key = base64.b64encode(b"\x30\x82" + bytes(range(200))).decode()
    ext_id = id_from_manifest_key(key)
    assert ext_id is not None and len(ext_id) == 32 and set(ext_id) <= set("abcdefghijklmnop")
    (tmp_path / "manifest.json").write_text(json.dumps({"name": "x", "version": "1", "key": key}))
    assert extension_id_for(tmp_path, read_manifest(tmp_path)) == ext_id
    # Without a key the id is derived from the path (like Chrome's unpacked extensions).
    (tmp_path / "manifest.json").write_text(json.dumps({"name": "x", "version": "1"}))
    path_id = extension_id_for(tmp_path, read_manifest(tmp_path))
    assert len(path_id) == 32 and path_id != ext_id
