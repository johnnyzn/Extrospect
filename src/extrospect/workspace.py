"""Analysis workspace: a normalised *view* of an extension that every later stage uses.

The view contains every text file of the extension; minified/bundled/obfuscated JS is
replaced by its formatted / deobfuscated version, bundles are split into modules
(``<file>@modules/<module>.js``) and inline ``<script>`` blocks become
``<page>.html.inline-<n>.js``. Line numbers in slices, LLM evidence and the Verifier all
refer to view files. The view is cached on disk by content hash.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from extrospect.config import PIPELINE_VERSION, Settings
from extrospect.models import CodeStats, ContextKind, LibraryInfo, Notice
from extrospect.static.deobfuscate import format_js, needs_rewrite, run_webcrack
from extrospect.static.libstrip import decide, identify_library
from extrospect.static.nodetools import NodeTools
from extrospect.static.surface import AttackSurface
from extrospect.util import (
    HTML_EXTENSIONS,
    JS_EXTENSIONS,
    decode_bytes,
    iter_files,
    safe_join,
    sha256_bytes,
    sha256_text,
    to_posix,
)

TEXT_EXTENSIONS = (
    JS_EXTENSIONS + HTML_EXTENSIONS + (".json", ".css", ".txt", ".md", ".xml", ".svg", ".ts")
)
MAX_TEXT_COPY_BYTES = 8 * 1024 * 1024
_INLINE_SCRIPT_RE = re.compile(r"<script\b(?![^>]*\bsrc\s*=)([^>]*)>([\s\S]*?)</script\s*>", re.I)

ViewKind = Literal["js", "module", "inline_js", "html", "json", "text"]


class ViewFile(BaseModel):
    rel: str  # path inside the view
    source: str  # original path inside the extension
    kind: ViewKind
    transform: str = "none"  # none / prettier / jsbeautifier / webcrack / webcrack-module / inline
    analyze: bool = False  # scanned for sinks and sliced
    library: str | None = None
    stripped: bool = False
    context: ContextKind = "unknown"
    bytes: int = 0
    line_offset: int = 0  # for inline scripts: line of the <script> tag in the page


class WorkspaceMeta(BaseModel):
    key: str
    pipeline_version: str
    files: dict[str, ViewFile] = Field(default_factory=dict)
    libraries: list[LibraryInfo] = Field(default_factory=list)
    stats: CodeStats = Field(default_factory=CodeStats)
    notices: list[Notice] = Field(default_factory=list)


class Workspace:
    def __init__(self, ext_dir: Path, root: Path, meta: WorkspaceMeta) -> None:
        self.ext_dir = ext_dir
        self.root = root
        self.meta = meta

    @property
    def view_dir(self) -> Path:
        return self.root / "view"

    @property
    def files(self) -> dict[str, ViewFile]:
        return self.meta.files

    def path(self, rel: str) -> Path:
        """Resolve a view path safely (raises PathEscapeError on traversal)."""
        return safe_join(self.view_dir, rel)

    def read(self, rel: str) -> str:
        return decode_bytes(self.path(rel).read_bytes())

    def analyzable(self) -> list[ViewFile]:
        return [f for f in self.meta.files.values() if f.analyze]

    def save(self) -> None:
        (self.root / "meta.json").write_text(self.meta.model_dump_json(indent=1), encoding="utf-8")

    def store_strings(self, strings: dict[str, str], flagged: set[str]) -> None:
        payload = {"strings": strings, "flagged": sorted(flagged)}
        (self.root / "strings.json").write_text(
            json.dumps(payload, ensure_ascii=False), encoding="utf-8"
        )

    def load_strings(self) -> tuple[dict[str, str], set[str]]:
        path = self.root / "strings.json"
        if not path.is_file():
            return {}, set()
        data = json.loads(path.read_text(encoding="utf-8"))
        return dict(data.get("strings", {})), set(data.get("flagged", []))


def _content_key(ext_dir: Path, settings: Settings, tools: NodeTools) -> str:
    parts = [
        PIPELINE_VERSION,
        f"fmt={settings.static.format_minified}",
        f"deob={settings.static.deobfuscate and bool(tools.webcrack)}",
        f"strip={settings.static.strip_libraries}",
        f"prettier={bool(tools.prettier)}",
    ]
    for path in iter_files(ext_dir):
        rel = to_posix(path.relative_to(ext_dir))
        try:
            digest = sha256_bytes(path.read_bytes())
        except OSError:
            continue
        parts.append(f"{rel}:{digest}")
    return sha256_text("\n".join(parts))[:20]


def _write(view_dir: Path, rel: str, text: str) -> int:
    target = safe_join(view_dir, rel)
    target.parent.mkdir(parents=True, exist_ok=True)
    data = text.encode("utf-8", "surrogatepass")
    target.write_bytes(data)
    return len(data)


def prepare_workspace(
    ext_dir: Path,
    ext_id: str,
    settings: Settings,
    tools: NodeTools,
    surface: AttackSurface | None = None,
    retire_libraries: dict[str, tuple[str, str]] | None = None,
    force: bool = False,
) -> Workspace:
    """Build (or reuse) the normalised view for ``ext_dir``."""
    file_contexts: dict[str, ContextKind] = surface.file_contexts if surface else {}
    inline_pages: dict[str, int] = surface.inline_scripts if surface else {}
    page_roles: dict[str, str] = surface.page_files if surface else {}
    key = _content_key(ext_dir, settings, tools)
    root = settings.paths.work_dir / ext_id / key
    meta_path = root / "meta.json"
    if meta_path.is_file() and not force:
        try:
            meta = WorkspaceMeta.model_validate_json(meta_path.read_text(encoding="utf-8"))
            if meta.pipeline_version == PIPELINE_VERSION:
                return Workspace(ext_dir, root, meta)
        except ValueError:
            pass
    if root.exists():
        shutil.rmtree(root)
    view_dir = root / "view"
    view_dir.mkdir(parents=True, exist_ok=True)

    meta = WorkspaceMeta(key=key, pipeline_version=PIPELINE_VERSION)
    stats = meta.stats
    contexts = file_contexts or {}
    retire_libraries = retire_libraries or {}
    cfg = settings.static

    for path in iter_files(ext_dir):
        rel = to_posix(path.relative_to(ext_dir))
        lower = rel.lower()
        size = path.stat().st_size
        if lower.endswith(".wasm"):
            stats.wasm_files += 1
            continue
        if not lower.endswith(TEXT_EXTENSIONS) or size > MAX_TEXT_COPY_BYTES:
            continue
        data = path.read_bytes()
        text = decode_bytes(data)
        if lower.endswith(HTML_EXTENSIONS):
            stats.html_files += 1
            meta.files[rel] = ViewFile(
                rel=rel, source=rel, kind="html", bytes=_write(view_dir, rel, text)
            )
            continue
        if not lower.endswith(JS_EXTENSIONS):
            kind: ViewKind = "json" if lower.endswith(".json") else "text"
            meta.files[rel] = ViewFile(
                rel=rel, source=rel, kind=kind, bytes=_write(view_dir, rel, text)
            )
            continue

        # ---- JavaScript
        stats.js_files += 1
        stats.total_bytes += size
        stats.total_lines += text.count("\n") + 1
        context = contexts.get(rel, "unknown")
        library = identify_library(rel, text, sha256_bytes(data), retire_libraries.get(rel))
        if library is not None:
            decision = decide(library, text) if cfg.strip_libraries else None
            meta.libraries.append(library)
            if decision is not None and decision.strip:
                stats.stripped_files += 1
                meta.files[rel] = ViewFile(
                    rel=rel,
                    source=rel,
                    kind="js",
                    library=library.name,
                    stripped=True,
                    context=context,
                    bytes=_write(view_dir, rel, text),
                )
                continue
        if size > cfg.max_parse_bytes:
            meta.notices.append(Notice(code="file_too_large", params={"file": rel, "size": size}))
            meta.files[rel] = ViewFile(
                rel=rel, source=rel, kind="js", context=context, bytes=_write(view_dir, rel, text)
            )
            continue

        minified, bundled, obfuscated = needs_rewrite(text)
        if minified:
            stats.minified_files += 1
        transform = "none"
        if cfg.deobfuscate and (bundled or obfuscated) and tools.webcrack:
            result = run_webcrack(path, tools, settings.tools.timeout_s)
            if result.ok and result.code is not None:
                stats.deobfuscated_files += 1
                if result.modules:
                    # Keep the whole deobfuscated file readable, analyse the modules.
                    meta.files[rel] = ViewFile(
                        rel=rel,
                        source=rel,
                        kind="js",
                        transform="webcrack",
                        context=context,
                        bytes=_write(view_dir, rel, result.code),
                    )
                    for module_rel, module_code in result.modules:
                        vrel = f"{rel}@modules/{module_rel}"
                        meta.files[vrel] = ViewFile(
                            rel=vrel,
                            source=rel,
                            kind="module",
                            transform="webcrack-module",
                            analyze=True,
                            context=context,
                            bytes=_write(view_dir, vrel, module_code),
                        )
                        stats.unpacked_modules += 1
                        stats.analyzed_bytes += len(module_code.encode("utf-8", "surrogatepass"))
                        stats.analyzed_lines += module_code.count("\n") + 1
                    continue
                text, transform = result.code, "webcrack"
            else:
                meta.notices.append(
                    Notice(
                        code="webcrack_failed", params={"file": rel, "error": result.error or ""}
                    )
                )
        elif cfg.deobfuscate and (bundled or obfuscated) and not tools.webcrack:
            meta.notices.append(Notice(code="webcrack_missing", params={"file": rel}, level="info"))
        if transform == "none" and minified and cfg.format_minified:
            text, transform = format_js(text, tools, settings.tools.timeout_s)
            if transform != "none":
                stats.formatted_files += 1
        written = _write(view_dir, rel, text)
        stats.analyzed_bytes += written
        stats.analyzed_lines += text.count("\n") + 1
        meta.files[rel] = ViewFile(
            rel=rel,
            source=rel,
            kind="js",
            transform=transform,
            analyze=True,
            context=context,
            bytes=written,
        )

    # ---- inline scripts in HTML pages
    for html_rel in inline_pages or {}:
        view = meta.files.get(html_rel)
        if view is None:
            continue
        html = (view_dir / html_rel).read_text(encoding="utf-8", errors="replace")
        for idx, match in enumerate(_INLINE_SCRIPT_RE.finditer(html), start=1):
            code = match.group(2)
            if not code.strip() or "json" in match.group(1).lower():
                continue
            vrel = f"{html_rel}.inline-{idx}.js"
            inline_context: ContextKind = (
                "background" if page_roles.get(html_rel) == "background_page" else "page"
            )
            meta.files[vrel] = ViewFile(
                rel=vrel,
                source=html_rel,
                kind="inline_js",
                transform="inline",
                analyze=True,
                context=inline_context,
                bytes=_write(view_dir, vrel, code),
                line_offset=html.count("\n", 0, match.start(2)),
            )

    workspace = Workspace(ext_dir, root, meta)
    workspace.save()
    return workspace


__all__ = ["ViewFile", "Workspace", "WorkspaceMeta", "prepare_workspace"]
