from __future__ import annotations

import hashlib
import io
import json
import os
import struct
import zipfile
from pathlib import Path

import httpx
import pytest

from extrospect.acquire.crx_download import ExtensionUnavailable, download_crx, download_url
from extrospect.acquire.local_profile import BrowserRoot, discover_extensions
from extrospect.acquire.unpack import UnpackError, extract_zip, parse_crx_header, unpack_package
from extrospect.http import HttpClient, OfflineError
from extrospect.static.manifest import id_from_bytes


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _field(number: int, payload: bytes) -> bytes:
    return _varint((number << 3) | 2) + _varint(len(payload)) + payload


def _zip(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def make_crx3(files: dict[str, bytes], crx_id: bytes, public_key: bytes = b"fake-der-key") -> bytes:
    signed_data = _field(1, crx_id)
    proof = _field(1, public_key) + _field(2, b"signature")
    header = _field(2, proof) + _field(10000, signed_data)
    return b"Cr24" + struct.pack("<II", 3, len(header)) + header + _zip(files)


def make_crx2(files: dict[str, bytes], public_key: bytes) -> bytes:
    signature = b"sig"
    return (
        b"Cr24"
        + struct.pack("<III", 2, len(public_key), len(signature))
        + public_key
        + signature
        + _zip(files)
    )


MANIFEST = json.dumps({"manifest_version": 3, "name": "T", "version": "1.0"}).encode()


def test_crx3_header_and_extension_id(tmp_path: Path) -> None:
    crx_id = bytes(range(16))
    data = make_crx3({"manifest.json": MANIFEST, "js/a.js": b"1"}, crx_id)
    info = parse_crx_header(data)
    assert info.format == "crx3"
    assert info.extension_id == id_from_bytes(crx_id) == "aaabacadaeafagahaiajakalamanaoap"
    assert info.public_key == b"fake-der-key"
    unpack_package(data, tmp_path / "out")
    assert (tmp_path / "out" / "js" / "a.js").read_bytes() == b"1"


def test_crx2_and_plain_zip(tmp_path: Path) -> None:
    key = b"\x30\x82\x01\x22" + bytes(100)
    info = parse_crx_header(make_crx2({"manifest.json": MANIFEST}, key))
    assert info.format == "crx2"
    expected = id_from_bytes(hashlib.sha256(key).digest())
    assert info.extension_id == expected
    zip_info = unpack_package(_zip({"manifest.json": MANIFEST}), tmp_path / "z")
    assert zip_info.format == "zip" and (tmp_path / "z" / "manifest.json").is_file()


def test_rejects_garbage() -> None:
    with pytest.raises(UnpackError):
        parse_crx_header(b"not a crx at all")
    with pytest.raises(UnpackError):
        parse_crx_header(b"Cr24" + struct.pack("<II", 3, 10_000) + b"short")


def test_zip_slip_is_blocked(tmp_path: Path) -> None:
    evil = _zip({"../../escape.js": b"x"})
    with pytest.raises(UnpackError):
        extract_zip(evil, tmp_path / "dest")
    assert not (tmp_path / "escape.js").exists()


def test_zip_bomb_limits(tmp_path: Path) -> None:
    big = _zip({"a.js": b"0" * 50_000, "b.js": b"0" * 50_000})
    with pytest.raises(UnpackError):
        extract_zip(big, tmp_path / "d1", max_bytes=60_000)
    with pytest.raises(UnpackError):
        extract_zip(big, tmp_path / "d2", max_files=1)


def test_symlinks_in_archives_are_skipped(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo("link")
        info.external_attr = 0o120777 << 16
        archive.writestr(info, "/etc/passwd")
        archive.writestr("manifest.json", MANIFEST)
    assert extract_zip(buffer.getvalue(), tmp_path / "s") == 1
    assert not (tmp_path / "s" / "link").exists()


def test_download_url_format() -> None:
    url = download_url("a" * 32, "150.0.0.0")
    assert url.startswith(
        "https://clients2.google.com/service/update2/crx?response=redirect&prodversion=150.0.0.0"
    )
    assert "x=id%3D" + "a" * 32 + "%26uc" in url


def test_download_with_mock_transport(settings, tmp_path: Path) -> None:
    crx = make_crx3({"manifest.json": MANIFEST}, bytes(16))

    def handler(request: httpx.Request) -> httpx.Response:
        if "b" * 32 in str(request.url):
            return httpx.Response(204)
        return httpx.Response(
            200, content=crx, headers={"content-type": "application/x-chrome-extension"}
        )

    settings.network.offline = False
    http = HttpClient(settings.network, transport=httpx.MockTransport(handler))
    result = download_crx("a" * 32, settings, http, dest_dir=tmp_path)
    assert result.path.read_bytes() == crx and result.crx_format == "crx3"
    with pytest.raises(ExtensionUnavailable):
        download_crx("b" * 32, settings, http, dest_dir=tmp_path)


def test_offline_mode_blocks_requests(settings) -> None:
    http = HttpClient(settings.network)
    with pytest.raises(OfflineError):
        http.get("https://example.com")


# --------------------------------------------------------------------------- local profiles


def _install(profile: Path, ext_id: str, version: str, manifest: dict) -> Path:
    directory = profile / "Extensions" / ext_id / f"{version}_0"
    directory.mkdir(parents=True)
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return directory


def make_profile_tree(root: Path, unpacked_dir: Path) -> None:
    (root / "Local State").parent.mkdir(parents=True, exist_ok=True)
    (root / "Local State").write_text(
        json.dumps(
            {
                "profile": {
                    "info_cache": {"Default": {"name": "Person 1"}, "Profile 1": {"name": "Work"}}
                }
            }
        ),
        encoding="utf-8",
    )
    default = root / "Default"
    work = root / "Profile 1"
    _install(
        default, "a" * 32, "1.0.0", {"manifest_version": 3, "name": "Alpha", "version": "1.0.0"}
    )
    _install(
        default, "a" * 32, "0.9.0", {"manifest_version": 3, "name": "Alpha old", "version": "0.9.0"}
    )
    _install(default, "b" * 32, "2.0", {"manifest_version": 2, "name": "Beta", "version": "2.0"})
    _install(
        default,
        "mhjfbmdgcfjbbpaeojofohoefgiehjai",
        "1",
        {"manifest_version": 2, "name": "PDF", "version": "1"},
    )
    secure = {
        "extensions": {
            "settings": {
                "a" * 32: {"location": 1, "from_webstore": True, "disable_reasons": []},
                "b" * 32: {"location": 1, "state": 0},
                "c" * 32: {"location": 4, "path": str(unpacked_dir), "disable_reasons": 0},
                "mhjfbmdgcfjbbpaeojofohoefgiehjai": {"location": 5},
            }
        }
    }
    (default / "Secure Preferences").write_text(json.dumps(secure), encoding="utf-8")
    _install(work, "d" * 32, "3.1", {"manifest_version": 3, "name": "Delta", "version": "3.1"})
    (work / "Preferences").write_text(
        json.dumps(
            {"extensions": {"settings": {"d" * 32: {"location": 1, "disable_reasons": [1]}}}}
        ),
        encoding="utf-8",
    )


def test_discover_extensions(tmp_path: Path, fixtures_dir: Path) -> None:
    root = tmp_path / "chrome"
    make_profile_tree(root, fixtures_dir / "benign_word_counter")
    found = discover_extensions([BrowserRoot("chrome", root)], ui_language="zh-CN")
    by_id = {e.ref.id: e for e in found}
    assert set(by_id) == {
        "a" * 32,
        "b" * 32,
        "c" * 32,
        "d" * 32,
    }  # component PDF viewer filtered out
    alpha = by_id["a" * 32]
    assert (
        alpha.ref.version == "1.0.0"
        and alpha.enabled is True
        and alpha.install_location == "webstore"
    )
    assert alpha.profile_name == "Person 1" and alpha.from_webstore is True
    assert by_id["b" * 32].enabled is False
    unpacked = by_id["c" * 32]
    assert unpacked.install_location == "unpacked" and unpacked.name == "字数统计"
    assert unpacked.ref.path == fixtures_dir / "benign_word_counter"
    delta = by_id["d" * 32]
    assert (
        delta.enabled is False and delta.ref.profile == "Profile 1" and delta.profile_name == "Work"
    )
    with_components = discover_extensions([BrowserRoot("chrome", root)], include_components=True)
    assert "mhjfbmdgcfjbbpaeojofohoefgiehjai" in {e.ref.id for e in with_components}


def test_browser_roots_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fixtures_dir: Path
) -> None:
    from extrospect.acquire.local_profile import default_roots

    root = tmp_path / "edge"
    make_profile_tree(root, fixtures_dir / "benign_word_counter")
    monkeypatch.setenv("EXTROSPECT_BROWSER_ROOTS", f"edge={root}{os.pathsep}{tmp_path / 'other'}")
    roots = default_roots()
    assert roots[0].browser == "edge" and roots[0].path == root
    assert roots[1].browser == "chromium"
    assert {e.ref.browser for e in discover_extensions()} == {"edge"}
