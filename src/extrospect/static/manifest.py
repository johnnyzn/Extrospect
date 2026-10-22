"""manifest.json parsing, MV2/MV3 normalisation and ``__MSG_name__`` resolution."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from extrospect.i18n import get_language, normalize_language
from extrospect.models import ManifestSummary
from extrospect.util import read_text, to_posix

_MSG_RE = re.compile(r"__MSG_([A-Za-z0-9_@]+)__")
_HOST_PREFIXES = ("http://", "https://", "*://", "file://", "ftp://", "ws://", "wss://", "urn:")


class ManifestError(ValueError):
    """The extension directory has no usable manifest.json."""


# --------------------------------------------------------------------------- lenient JSON


def strip_json_noise(text: str) -> str:
    """Remove ``//`` and ``/* */`` comments and trailing commas outside strings.

    Chrome tolerates comments in manifest.json, and hand-written ``messages.json``
    files often contain trailing commas.
    """
    out: list[str] = []
    i, n = 0, len(text)
    in_string = False
    escaped = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end == -1 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            chunk = text[i : (n if end == -1 else end + 2)]
            out.append("\n" * chunk.count("\n"))
            i = n if end == -1 else end + 2
        elif ch == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":
                i += 1  # drop trailing comma
            else:
                out.append(ch)
                i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def parse_json_lenient(text: str) -> Any:
    text = text.lstrip("﻿")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return json.loads(strip_json_noise(text))


def load_json_file(path: Path) -> Any:
    return parse_json_lenient(read_text(path))


# --------------------------------------------------------------------------- locales


def _locale_dirs(ext_dir: Path) -> dict[str, Path]:
    locales_root = ext_dir / "_locales"
    if not locales_root.is_dir():
        return {}
    return {p.name.lower(): p for p in locales_root.iterdir() if p.is_dir()}


def locale_candidates(ui_language: str | None, default_locale: str | None) -> list[str]:
    """Chrome-style locale folder candidates: ``zh-CN`` -> zh_cn, zh, <default>, en..."""
    candidates: list[str] = []
    lang = normalize_language(ui_language) or "en"
    folder = lang.replace("-", "_").lower()
    candidates.append(folder)
    base = folder.split("_", 1)[0]
    if base not in candidates:
        candidates.append(base)
    if base == "zh":
        candidates.append("zh_tw" if folder == "zh_tw" else "zh_cn")
    if default_locale:
        candidates.append(default_locale.lower())
    candidates.extend(["en", "en_us", "en_gb"])
    return list(dict.fromkeys(candidates))


def load_messages(ext_dir: Path, locale_folder: str) -> dict[str, dict[str, Any]]:
    folders = _locale_dirs(ext_dir)
    folder = folders.get(locale_folder.lower())
    if folder is None:
        return {}
    path = folder / "messages.json"
    if not path.is_file():
        return {}
    try:
        data = load_json_file(path)
    except (json.JSONDecodeError, OSError, UnicodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    # Message names are case-insensitive in Chrome.
    return {str(k).lower(): v for k, v in data.items() if isinstance(v, dict)}


def _render_message(entry: dict[str, Any]) -> str:
    message = str(entry.get("message", ""))
    placeholders = entry.get("placeholders") or {}
    if isinstance(placeholders, dict):
        lowered = {str(k).lower(): v for k, v in placeholders.items()}

        def repl(match: re.Match[str]) -> str:
            ph = lowered.get(match.group(1).lower())
            if isinstance(ph, dict):
                return str(ph.get("content", ""))
            return match.group(0)

        message = re.sub(r"\$([A-Za-z0-9_@]+)\$", repl, message)
    return message.replace("$$", "$")


class MessageResolver:
    """Resolves ``__MSG_name__`` using the preferred UI locale with Chrome-like fallback."""

    def __init__(self, ext_dir: Path, default_locale: str | None, ui_language: str | None = None):
        self.ext_dir = ext_dir
        self._chain = [
            msgs
            for folder in locale_candidates(ui_language or get_language(), default_locale)
            if (msgs := load_messages(ext_dir, folder))
        ]

    def lookup(self, name: str) -> str | None:
        key = name.lower()
        for messages in self._chain:
            entry = messages.get(key)
            if entry is not None:
                return _render_message(entry)
        return None

    def resolve(self, value: Any) -> str:
        if not isinstance(value, str):
            return "" if value is None else str(value)

        def repl(match: re.Match[str]) -> str:
            resolved = self.lookup(match.group(1))
            return resolved if resolved is not None else match.group(0)

        return _MSG_RE.sub(repl, value)


# --------------------------------------------------------------------------- extension ids


def id_from_bytes(digest: bytes) -> str:
    """Chrome maps the first 16 bytes of a SHA-256 to 32 chars in ``a``-``p``."""
    return "".join(chr(ord("a") + int(c, 16)) for c in digest[:16].hex())


def id_from_public_key(public_key_der: bytes) -> str:
    return id_from_bytes(hashlib.sha256(public_key_der).digest())


def id_from_manifest_key(key_b64: str) -> str | None:
    try:
        der = base64.b64decode(key_b64.strip(), validate=False)
    except (ValueError, TypeError):
        return None
    return id_from_public_key(der) if der else None


def id_from_path(path: Path) -> str:
    """ID Chrome assigns to an unpacked extension without ``key`` (hash of its path)."""
    return id_from_bytes(hashlib.sha256(str(path.resolve()).encode("utf-8")).digest())


# --------------------------------------------------------------------------- normalisation


def is_host_pattern(value: str) -> bool:
    return value == "<all_urls>" or value.startswith(_HOST_PREFIXES) or "://" in value


def _as_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    items: list[str] = []
    if isinstance(value, list | tuple):
        for item in value:
            if isinstance(item, str):
                items.append(item)
            elif isinstance(item, dict):
                # Legacy app permissions such as {"fileSystem": ["write"]}.
                items.extend(str(k) for k in item)
    return items


def _split_permissions(values: list[str]) -> tuple[list[str], list[str]]:
    perms: list[str] = []
    hosts: list[str] = []
    for value in values:
        (hosts if is_host_pattern(value) else perms).append(value)
    return perms, hosts


def _rel(path: Any) -> str | None:
    if not isinstance(path, str) or not path.strip():
        return None
    value = path.strip().split("#", 1)[0].split("?", 1)[0]
    if value.startswith(("http://", "https://", "data:", "javascript:")):
        return None
    return to_posix(value.lstrip("/"))


def _normalise_content_scripts(raw: Any) -> list[dict[str, Any]]:
    scripts: list[dict[str, Any]] = []
    if not isinstance(raw, list):
        return scripts
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        scripts.append(
            {
                "matches": _as_str_list(entry.get("matches")),
                "exclude_matches": _as_str_list(entry.get("exclude_matches")),
                "include_globs": _as_str_list(entry.get("include_globs")),
                "js": [p for p in (_rel(x) for x in _as_str_list(entry.get("js"))) if p],
                "css": [p for p in (_rel(x) for x in _as_str_list(entry.get("css"))) if p],
                "all_frames": bool(entry.get("all_frames", False)),
                "match_about_blank": bool(entry.get("match_about_blank", False)),
                "match_origin_as_fallback": bool(entry.get("match_origin_as_fallback", False)),
                "run_at": str(entry.get("run_at", "document_idle")),
                "world": str(entry.get("world", "ISOLATED")).upper(),
            }
        )
    return scripts


def _normalise_war(raw: Any, manifest_version: int) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or not raw:
        return []
    if all(isinstance(x, str) for x in raw):
        # MV2: a flat list of resources, reachable from every web page.
        return [{"resources": list(raw), "matches": ["<all_urls>"], "legacy_mv2": True}]
    entries: list[dict[str, Any]] = []
    for item in raw:
        if isinstance(item, dict):
            entries.append(
                {
                    "resources": _as_str_list(item.get("resources")),
                    "matches": _as_str_list(item.get("matches")),
                    "extension_ids": _as_str_list(item.get("extension_ids")),
                    "use_dynamic_url": bool(item.get("use_dynamic_url", False)),
                }
            )
        elif isinstance(item, str):
            entries.append({"resources": [item], "matches": ["<all_urls>"], "legacy_mv2": True})
    return entries


def _pages(raw: dict[str, Any]) -> dict[str, str]:
    pages: dict[str, str] = {}

    def put(role: str, value: Any) -> None:
        rel = _rel(value)
        if rel:
            pages[role] = rel

    for action_key in ("action", "browser_action", "page_action"):
        action = raw.get(action_key)
        if isinstance(action, dict):
            put("popup", action.get("default_popup"))
    put("options", raw.get("options_page"))
    options_ui = raw.get("options_ui")
    if isinstance(options_ui, dict):
        put("options", options_ui.get("page"))
    put("devtools", raw.get("devtools_page"))
    side_panel = raw.get("side_panel")
    if isinstance(side_panel, dict):
        put("side_panel", side_panel.get("default_path"))
    overrides = raw.get("chrome_url_overrides")
    if isinstance(overrides, dict):
        for key in ("newtab", "history", "bookmarks"):
            put(f"override_{key}", overrides.get(key))
    background = raw.get("background")
    if isinstance(background, dict):
        put("background_page", background.get("page"))
    return pages


def summarize_manifest(
    ext_dir: Path, raw: dict[str, Any], ui_language: str | None = None
) -> ManifestSummary:
    """Normalise a raw manifest dict into :class:`ManifestSummary`."""
    try:
        manifest_version = int(raw.get("manifest_version", 2))
    except (TypeError, ValueError):
        manifest_version = 2
    resolver = MessageResolver(ext_dir, raw.get("default_locale"), ui_language)

    perms_raw = _as_str_list(raw.get("permissions"))
    optional_raw = _as_str_list(raw.get("optional_permissions"))
    permissions, hosts_from_perms = _split_permissions(perms_raw)
    optional_permissions, optional_hosts = _split_permissions(optional_raw)
    host_permissions = hosts_from_perms + _as_str_list(raw.get("host_permissions"))
    optional_host_permissions = optional_hosts + _as_str_list(raw.get("optional_host_permissions"))

    csp: dict[str, Any] | str | None = raw.get("content_security_policy")
    if not isinstance(csp, dict | str):
        csp = None

    sandbox_pages: list[str] = []
    sandbox = raw.get("sandbox")
    if isinstance(sandbox, dict):
        sandbox_pages = [p for p in (_rel(x) for x in _as_str_list(sandbox.get("pages"))) if p]
        if manifest_version == 2 and isinstance(sandbox.get("content_security_policy"), str):
            # MV2 put the sandbox CSP under sandbox.content_security_policy.
            base = csp if isinstance(csp, str) else None
            csp = {
                "extension_pages": base,
                "sandbox": sandbox["content_security_policy"],
                "mv2": True,
            }

    author = raw.get("author")
    if isinstance(author, dict):
        author = author.get("email") or author.get("name")

    oauth2 = raw.get("oauth2")
    scopes = _as_str_list(oauth2.get("scopes")) if isinstance(oauth2, dict) else []

    background = raw.get("background") if isinstance(raw.get("background"), dict) else None
    externally_connectable = raw.get("externally_connectable")
    dnr = raw.get("declarative_net_request")

    name_raw = raw.get("name") if isinstance(raw.get("name"), str) else None
    name = resolver.resolve(raw.get("name")) or resolver.resolve(raw.get("short_name")) or "?"
    return ManifestSummary(
        name=name.strip(),
        name_raw=name_raw,
        description=resolver.resolve(raw.get("description")).strip(),
        version=str(raw.get("version", "")),
        manifest_version=manifest_version,
        default_locale=raw.get("default_locale")
        if isinstance(raw.get("default_locale"), str)
        else None,
        permissions=permissions,
        optional_permissions=optional_permissions,
        host_permissions=host_permissions,
        optional_host_permissions=optional_host_permissions,
        content_scripts=_normalise_content_scripts(raw.get("content_scripts")),
        csp=csp,
        web_accessible_resources=_normalise_war(
            raw.get("web_accessible_resources"), manifest_version
        ),
        externally_connectable=externally_connectable
        if isinstance(externally_connectable, dict)
        else None,
        update_url=raw.get("update_url") if isinstance(raw.get("update_url"), str) else None,
        background=background,
        homepage_url=raw.get("homepage_url") if isinstance(raw.get("homepage_url"), str) else None,
        author=author if isinstance(author, str) else None,
        chrome_settings_overrides=raw.get("chrome_settings_overrides")
        if isinstance(raw.get("chrome_settings_overrides"), dict)
        else None,
        chrome_url_overrides=raw.get("chrome_url_overrides")
        if isinstance(raw.get("chrome_url_overrides"), dict)
        else None,
        declarative_net_request=dnr if isinstance(dnr, dict) else None,
        sandbox_pages=sandbox_pages,
        pages=_pages(raw),
        has_key=isinstance(raw.get("key"), str),
        minimum_chrome_version=str(raw["minimum_chrome_version"])
        if raw.get("minimum_chrome_version") is not None
        else None,
        oauth2_scopes=scopes,
    )


def read_manifest(ext_dir: Path) -> dict[str, Any]:
    path = ext_dir / "manifest.json"
    if not path.is_file():
        raise ManifestError(f"manifest.json not found in {ext_dir}")
    try:
        data = load_json_file(path)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ManifestError(f"manifest.json is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ManifestError("manifest.json must contain a JSON object")
    return data


def load_manifest(
    ext_dir: Path, ui_language: str | None = None
) -> tuple[ManifestSummary, dict[str, Any]]:
    raw = read_manifest(ext_dir)
    return summarize_manifest(ext_dir, raw, ui_language), raw


def extension_id_for(ext_dir: Path, raw: dict[str, Any], fallback: str | None = None) -> str:
    """Best-effort extension id: explicit > manifest ``key`` > unpacked-path hash."""
    if fallback:
        return fallback
    key = raw.get("key")
    if isinstance(key, str):
        derived = id_from_manifest_key(key)
        if derived:
            return derived
    return id_from_path(ext_dir)


__all__ = [
    "ManifestError",
    "MessageResolver",
    "extension_id_for",
    "id_from_bytes",
    "id_from_manifest_key",
    "id_from_path",
    "id_from_public_key",
    "is_host_pattern",
    "load_json_file",
    "load_manifest",
    "locale_candidates",
    "parse_json_lenient",
    "read_manifest",
    "strip_json_noise",
    "summarize_manifest",
]
