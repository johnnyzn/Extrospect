"""Attack surface: content scripts, web-accessible resources, external messaging, DNR rules,
settings overrides, and which execution context each JS file runs in."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from pydantic import BaseModel, Field

from extrospect.models import ContextKind, ManifestSummary
from extrospect.static.manifest import load_json_file
from extrospect.util import (
    HTML_EXTENSIONS,
    JS_EXTENSIONS,
    is_public_suffix,
    iter_files,
    read_text,
    to_posix,
)

HostBreadth = Literal["all", "broad", "specific", "file", "none", "other"]

WEBSTORE_UPDATE_URLS = {
    "https://clients2.google.com/service/update2/crx",
    "http://clients2.google.com/service/update2/crx",
    "https://edge.microsoft.com/extensionwebstorebase/v1/crx",
    "https://extensionwebstorebase.edgesv.net/v1/crx",
}
SECURITY_HEADERS = {
    "content-security-policy",
    "content-security-policy-report-only",
    "x-frame-options",
    "strict-transport-security",
    "x-content-type-options",
    "x-xss-protection",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
    "permissions-policy",
    "referrer-policy",
}
SENSITIVE_REQUEST_HEADERS = {"cookie", "authorization", "referer", "origin", "user-agent"}

_PATTERN_RE = re.compile(r"^(\*|[a-z][a-z0-9+.-]*)://([^/]*)(/.*)?$", re.I)
_SCRIPT_SRC_RE = re.compile(r"<script\b[^>]*?\bsrc\s*=\s*[\"']?([^\"'\s>]+)", re.I)
_INLINE_SCRIPT_RE = re.compile(r"<script\b(?![^>]*\bsrc\s*=)([^>]*)>([\s\S]*?)</script\s*>", re.I)
_IMPORT_SCRIPTS_RE = re.compile(r"\bimportScripts\s*\(([^)]*)\)")
_IMPORT_FROM_RE = re.compile(
    r"""(?:^|[;\s])(?:import|export)\s[^'"`;]*?\bfrom\s*['"]([^'"]+)['"]|(?:^|[;\s])import\s*['"]([^'"]+)['"]|\bimport\(\s*['"]([^'"]+)['"]\s*\)""",
    re.M,
)
_QUOTED_RE = re.compile(r"['\"]([^'\"]+)['\"]")
_INJECT_FILES_RE = re.compile(r"\bfiles\s*:\s*\[([^\]]*)\]")
_INJECT_FILE_RE = re.compile(r"\bfile\s*:\s*['\"]([^'\"]+\.m?js)['\"]")
_WORKER_RE = re.compile(r"\bnew\s+(?:Shared)?Worker\s*\(\s*['\"]([^'\"]+)['\"]")


def classify_host_pattern(pattern: str) -> HostBreadth:
    """Classify a match pattern by how many sites it covers."""
    value = pattern.strip()
    if value == "<all_urls>":
        return "all"
    match = _PATTERN_RE.match(value)
    if not match:
        return "other"
    scheme, host = match.group(1).lower(), match.group(2).lower()
    if scheme == "file":
        return "file"
    if scheme not in {"*", "http", "https", "ws", "wss", "ftp"}:
        return "other"
    host = host.split("@")[-1].split(":")[0]
    if host in {"*", ""}:
        return "all"
    if host.startswith("*."):
        # "*.com" or "*.co.uk" (a bare public suffix) covers huge parts of the web.
        return "broad" if is_public_suffix(host[2:]) else "specific"
    if "*" in host:
        return "broad"
    return "specific"


def breadth_of(patterns: list[str]) -> HostBreadth:
    order: dict[HostBreadth, int] = {
        "none": 0,
        "other": 1,
        "specific": 2,
        "file": 2,
        "broad": 3,
        "all": 4,
    }
    best: HostBreadth = "none"
    for pattern in patterns:
        kind = classify_host_pattern(pattern)
        if order[kind] > order[best]:
            best = kind
    return best


class ContentScriptInfo(BaseModel):
    matches: list[str]
    js: list[str]
    all_frames: bool
    world: str
    run_at: str
    breadth: HostBreadth


class DnrInfo(BaseModel):
    rule_files: list[str] = Field(default_factory=list)
    rules: int = 0
    modify_headers: bool = False
    removed_security_headers: list[str] = Field(default_factory=list)
    modified_request_headers: list[str] = Field(default_factory=list)
    redirect: bool = False
    block: bool = False


class AttackSurface(BaseModel):
    content_scripts: list[ContentScriptInfo] = Field(default_factory=list)
    cs_all_sites: bool = False
    cs_all_frames_all_sites: bool = False
    cs_main_world_all_sites: bool = False
    cs_document_start_all_sites: bool = False
    war_open_all: bool = False
    war_resources_open: list[str] = Field(default_factory=list)
    ext_connectable_broad: bool = False
    ext_connectable_matches: list[str] = Field(default_factory=list)
    ext_connectable_any_extension: bool = False
    background_type: str | None = None
    background_files: list[str] = Field(default_factory=list)
    page_files: dict[str, str] = Field(default_factory=dict)  # html -> role
    file_contexts: dict[str, ContextKind] = Field(default_factory=dict)
    dnr: DnrInfo = Field(default_factory=DnrInfo)
    overrides: dict[str, Any] = Field(default_factory=dict)
    offstore_update_url: bool = False
    remote_script_tags: list[tuple[str, str]] = Field(default_factory=list)  # (html, src)
    inline_scripts: dict[str, int] = Field(default_factory=dict)  # html -> count
    wasm_files: list[str] = Field(default_factory=list)


def _resolve(base_file: str | None, ref: str) -> str | None:
    ref = ref.strip().split("#", 1)[0].split("?", 1)[0]
    if not ref or ref.startswith(("http://", "https://", "//", "data:", "blob:", "javascript:")):
        return None
    ref = re.sub(r"^chrome-extension://[^/]+/", "/", ref)
    if ref.startswith("/"):
        path = PurePosixPath(ref.lstrip("/"))
    else:
        parent = PurePosixPath(base_file).parent if base_file else PurePosixPath(".")
        path = parent / ref
    parts: list[str] = []
    for part in path.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/".join(parts) if parts else None


def _scripts_in_html(ext_dir: Path, html_rel: str) -> tuple[list[str], list[str], int]:
    """Return (local script files, remote script srcs, inline script count) for an HTML page."""
    path = ext_dir / html_rel
    if not path.is_file():
        return [], [], 0
    text = read_text(path, max_bytes=2_000_000)
    local, remote = [], []
    for src in _SCRIPT_SRC_RE.findall(text):
        if src.startswith(("http://", "https://", "//")):
            remote.append(src)
            continue
        resolved = _resolve(html_rel, src)
        if resolved:
            local.append(resolved)
    inline = sum(1 for m in _INLINE_SCRIPT_RE.finditer(text) if m.group(2).strip())
    return local, remote, inline


def _imports_of(ext_dir: Path, js_rel: str) -> list[str]:
    path = ext_dir / js_rel
    if not path.is_file():
        return []
    text = read_text(path, max_bytes=4_000_000)
    found: list[str] = []
    for args in _IMPORT_SCRIPTS_RE.findall(text):
        found.extend(_QUOTED_RE.findall(args))
    for groups in _IMPORT_FROM_RE.findall(text):
        found.extend(g for g in groups if g)
    found.extend(_WORKER_RE.findall(text))
    resolved = []
    for ref in found:
        rel = _resolve(js_rel, ref)
        if rel:
            resolved.append(rel)
    return resolved


def _injected_files(ext_dir: Path, js_rel: str) -> list[str]:
    path = ext_dir / js_rel
    if not path.is_file():
        return []
    text = read_text(path, max_bytes=4_000_000)
    refs: list[str] = []
    for group in _INJECT_FILES_RE.findall(text):
        refs.extend(_QUOTED_RE.findall(group))
    refs.extend(_INJECT_FILE_RE.findall(text))
    return [rel for ref in refs if (rel := _resolve(None, ref))]


def _closure(ext_dir: Path, roots: list[str], existing: set[str]) -> list[str]:
    seen: list[str] = []
    stack = [r for r in roots if r in existing]
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.append(current)
        for dep in _imports_of(ext_dir, current):
            if dep in existing and dep not in seen:
                stack.append(dep)
    return seen


def _analyze_dnr(ext_dir: Path, manifest: ManifestSummary) -> DnrInfo:
    info = DnrInfo()
    resources = (manifest.declarative_net_request or {}).get("rule_resources") or []
    for resource in resources if isinstance(resources, list) else []:
        if not isinstance(resource, dict):
            continue
        rel = _resolve(None, str(resource.get("path", "")))
        if not rel:
            continue
        info.rule_files.append(rel)
        path = ext_dir / rel
        if not path.is_file() or path.stat().st_size > 8_000_000:
            continue
        try:
            rules = load_json_file(path)
        except Exception:
            continue
        if not isinstance(rules, list):
            continue
        info.rules += len(rules)
        for rule in rules:
            action = rule.get("action") if isinstance(rule, dict) else None
            if not isinstance(action, dict):
                continue
            kind = action.get("type")
            if kind == "redirect":
                info.redirect = True
            elif kind == "block":
                info.block = True
            elif kind == "modifyHeaders":
                info.modify_headers = True
                for header in action.get("responseHeaders") or []:
                    name = str(header.get("header", "")).lower() if isinstance(header, dict) else ""
                    if name in SECURITY_HEADERS and name not in info.removed_security_headers:
                        info.removed_security_headers.append(name)
                for header in action.get("requestHeaders") or []:
                    name = str(header.get("header", "")).lower() if isinstance(header, dict) else ""
                    if (
                        name in SENSITIVE_REQUEST_HEADERS
                        and name not in info.modified_request_headers
                    ):
                        info.modified_request_headers.append(name)
    return info


def analyze_surface(ext_dir: Path, manifest: ManifestSummary) -> AttackSurface:
    surface = AttackSurface()
    all_files = [to_posix(p.relative_to(ext_dir)) for p in iter_files(ext_dir)]
    existing = set(all_files)
    js_files = [f for f in all_files if f.lower().endswith(JS_EXTENSIONS)]
    html_files = [f for f in all_files if f.lower().endswith(HTML_EXTENSIONS)]
    surface.wasm_files = [f for f in all_files if f.lower().endswith(".wasm")]

    # ---- content scripts
    for cs in manifest.content_scripts:
        breadth = breadth_of(cs.get("matches", []))
        info = ContentScriptInfo(
            matches=cs.get("matches", []),
            js=cs.get("js", []),
            all_frames=bool(cs.get("all_frames")),
            world=str(cs.get("world", "ISOLATED")),
            run_at=str(cs.get("run_at", "document_idle")),
            breadth=breadth,
        )
        surface.content_scripts.append(info)
        if breadth in {"all", "broad"} and info.js:
            surface.cs_all_sites = True
            if info.all_frames:
                surface.cs_all_frames_all_sites = True
            if info.world == "MAIN":
                surface.cs_main_world_all_sites = True
            if info.run_at == "document_start":
                surface.cs_document_start_all_sites = True

    # ---- web accessible resources
    for entry in manifest.web_accessible_resources:
        if breadth_of(entry.get("matches", [])) in {"all", "broad"}:
            surface.war_open_all = True
            surface.war_resources_open.extend(entry.get("resources", []))

    # ---- externally connectable
    ec = manifest.externally_connectable or {}
    matches = (
        [m for m in ec.get("matches", []) if isinstance(m, str)] if isinstance(ec, dict) else []
    )
    surface.ext_connectable_matches = matches
    surface.ext_connectable_broad = breadth_of(matches) in {"all", "broad"}
    ids = ec.get("ids", []) if isinstance(ec, dict) else []
    surface.ext_connectable_any_extension = isinstance(ids, list) and "*" in ids

    # ---- overrides & update url
    settings = manifest.chrome_settings_overrides or {}
    search = settings.get("search_provider") if isinstance(settings, dict) else None
    if isinstance(search, dict) and search.get("search_url"):
        surface.overrides["search_url"] = str(search.get("search_url"))
    if isinstance(settings, dict) and settings.get("homepage"):
        surface.overrides["homepage"] = str(settings.get("homepage"))
    if isinstance(settings, dict) and settings.get("startup_pages"):
        surface.overrides["startup_pages"] = list(settings.get("startup_pages") or [])
    for key, value in (manifest.chrome_url_overrides or {}).items():
        surface.overrides[f"url_{key}"] = str(value)
    if manifest.update_url and manifest.update_url.strip() not in WEBSTORE_UPDATE_URLS:
        surface.offstore_update_url = True

    surface.dnr = _analyze_dnr(ext_dir, manifest)

    # ---- execution contexts
    contexts: dict[str, ContextKind] = {}
    background_roots: list[str] = []
    bg = manifest.background or {}
    if isinstance(bg.get("service_worker"), str):
        surface.background_type = "service_worker"
        rel = _resolve(None, bg["service_worker"])
        if rel:
            background_roots.append(rel)
    if isinstance(bg.get("scripts"), list):
        surface.background_type = surface.background_type or "scripts"
        background_roots.extend(r for s in bg["scripts"] if (r := _resolve(None, str(s))))
    if isinstance(bg.get("page"), str):
        surface.background_type = surface.background_type or "page"
        page_rel = _resolve(None, bg["page"])
        if page_rel:
            local, remote, inline = _scripts_in_html(ext_dir, page_rel)
            background_roots.extend(local)
            surface.remote_script_tags.extend((page_rel, src) for src in remote)
            if inline:
                surface.inline_scripts[page_rel] = inline
    surface.background_files = _closure(ext_dir, background_roots, existing)
    for rel in surface.background_files:
        contexts[rel] = "background"

    # Pages: manifest-declared pages, sandbox pages and any other HTML document.
    page_roles: dict[str, str] = {}
    for role, rel in manifest.pages.items():
        page_roles[rel] = role
    for rel in manifest.sandbox_pages:
        page_roles.setdefault(rel, "sandbox")
    for rel in html_files:
        page_roles.setdefault(rel, "page")
    surface.page_files = page_roles
    page_scripts: list[str] = []
    for html_rel in page_roles:
        local, remote, inline = _scripts_in_html(ext_dir, html_rel)
        page_scripts.extend(local)
        surface.remote_script_tags.extend((html_rel, src) for src in remote)
        if inline:
            surface.inline_scripts[html_rel] = inline

    cs_roots = [f for cs in surface.content_scripts for f in cs.js]
    for rel in list(surface.background_files) + _closure(ext_dir, page_scripts, existing):
        cs_roots.extend(_injected_files(ext_dir, rel))
    for rel in _closure(ext_dir, cs_roots, existing):
        contexts.setdefault(rel, "content_script")
    for rel in _closure(ext_dir, page_scripts, existing):
        contexts.setdefault(rel, "page")
    for rel in js_files:
        contexts.setdefault(rel, "unknown")
    surface.file_contexts = contexts
    return surface


__all__ = [
    "SECURITY_HEADERS",
    "AttackSurface",
    "ContentScriptInfo",
    "DnrInfo",
    "HostBreadth",
    "analyze_surface",
    "breadth_of",
    "classify_host_pattern",
]
