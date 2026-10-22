"""Deobfuscation / bundle unpacking (webcrack) and formatting (prettier or jsbeautifier).

Only minified, bundled or obfuscated files are rewritten; ordinary source files are kept
byte-for-byte so their line numbers match what the user sees in the extension folder.
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from extrospect.static.nodetools import NodeTools, run_tool
from extrospect.util import decode_bytes, is_minified

BUNDLE_MARKERS = (
    "__webpack_require__",
    "webpackChunk",
    "__webpack_modules__",
    "webpackJsonp",
    "parcelRequire",
    "System.register(",
)
_BROWSERIFY_RE = re.compile(
    r"^\s*(?:!\s*)?\(?\s*function\s*\w*\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*\)\s*\{\s*function\s+\w+\s*\(\s*\w+\s*,\s*\w+\s*\)\s*\{\s*if\s*\(\s*!\s*\w+\["
)
_OBF_IDENT_RE = re.compile(r"\b_0x[0-9a-f]{4,}\b")
_HEX_ESC_RE = re.compile(r"\\x[0-9a-fA-F]{2}")
JSBEAUTIFIER_MAX_BYTES = 4 * 1024 * 1024


def looks_bundled(text: str) -> bool:
    head = text[:200_000]
    return any(marker in head for marker in BUNDLE_MARKERS) or bool(
        _BROWSERIFY_RE.match(text[:400])
    )


def looks_obfuscated(text: str) -> bool:
    sample = text[:500_000]
    kb = max(1.0, len(sample) / 1024)
    obf_ids = len(_OBF_IDENT_RE.findall(sample))
    hex_escapes = len(_HEX_ESC_RE.findall(sample))
    return obf_ids >= 30 or obf_ids / kb > 2 or hex_escapes / kb > 25 or "while(!![])" in sample


@dataclass
class WebcrackResult:
    ok: bool
    code: str | None = None  # whole-file deobfuscated code
    bundle_type: str | None = None
    modules: list[tuple[str, str]] = field(default_factory=list)  # (module path, code)
    error: str | None = None


def run_webcrack(source: Path, tools: NodeTools, timeout: float) -> WebcrackResult:
    if not tools.webcrack:
        return WebcrackResult(ok=False, error="webcrack not installed")
    with tempfile.TemporaryDirectory(prefix="extrospect-webcrack-") as tmp:
        out_dir = Path(tmp) / "out"
        try:
            result = run_tool(
                [tools.webcrack, str(source), "-o", str(out_dir), "-f"], timeout=timeout
            )
        except subprocess.TimeoutExpired:
            return WebcrackResult(ok=False, error=f"webcrack timed out after {timeout:.0f}s")
        except OSError as exc:
            return WebcrackResult(ok=False, error=str(exc))
        main = out_dir / "deobfuscated.js"
        if result.returncode != 0 or not main.is_file():
            tail = (result.stderr or "").strip().splitlines()[-1:] or ["unknown error"]
            return WebcrackResult(ok=False, error=f"webcrack failed: {tail[0][:200]}")
        res = WebcrackResult(ok=True, code=decode_bytes(main.read_bytes()))
        bundle_json = out_dir / "bundle.json"
        if bundle_json.is_file():
            try:
                bundle = json.loads(bundle_json.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                bundle = {}
            res.bundle_type = bundle.get("type")
            for module in bundle.get("modules", []) or []:
                rel = str(module.get("path", "")).lstrip("./") or f"{module.get('id')}.js"
                path = (out_dir / rel).resolve()
                if out_dir.resolve() in path.parents and path.is_file():
                    res.modules.append((rel, decode_bytes(path.read_bytes())))
        return res


def format_with_prettier(text: str, tools: NodeTools, timeout: float) -> str | None:
    if not tools.prettier:
        return None
    try:
        result = run_tool(
            [tools.prettier, "--stdin-filepath", "input.js", "--print-width", "100"],
            input_text=text,
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    return result.stdout


def format_with_jsbeautifier(text: str) -> str | None:
    if len(text) > JSBEAUTIFIER_MAX_BYTES:
        return None
    try:
        import jsbeautifier

        options = jsbeautifier.default_options()
        options.indent_size = 2
        options.preserve_newlines = True
        options.max_preserve_newlines = 2
        return str(jsbeautifier.beautify(text, options))
    except Exception:
        return None


def format_js(text: str, tools: NodeTools, timeout: float) -> tuple[str, str]:
    """Return (formatted text, method). Falls back to the input when nothing works."""
    formatted = format_with_prettier(text, tools, timeout)
    if formatted is not None:
        return formatted, "prettier"
    formatted = format_with_jsbeautifier(text)
    if formatted is not None:
        return formatted, "jsbeautifier"
    return text, "none"


PARALLEL_MIN_FILES = 6
PARALLEL_MIN_BYTES = 1_500_000


def _format_job(job: tuple[str, NodeTools, float]) -> tuple[str, str]:
    text, tools, timeout = job
    return format_js(text, tools, timeout)


def format_many(texts: list[str], tools: NodeTools, timeout: float) -> list[tuple[str, str]]:
    """Format several files, using worker processes for large batches."""
    if len(texts) < PARALLEL_MIN_FILES and sum(map(len, texts)) < PARALLEL_MIN_BYTES:
        return [format_js(t, tools, timeout) for t in texts]
    import multiprocessing
    import os
    from concurrent.futures import ProcessPoolExecutor

    workers = max(1, min(8, (os.cpu_count() or 2) - 1, len(texts)))
    # "spawn" is safe even when the caller runs threads (the MCP server does).
    context = multiprocessing.get_context("spawn")
    try:
        with ProcessPoolExecutor(max_workers=workers, mp_context=context) as pool:
            return list(pool.map(_format_job, [(t, tools, timeout) for t in texts], chunksize=4))
    except (OSError, RuntimeError):
        return [format_js(t, tools, timeout) for t in texts]


def needs_rewrite(text: str) -> tuple[bool, bool, bool]:
    """(minified, bundled, obfuscated)."""
    return is_minified(text), looks_bundled(text), looks_obfuscated(text)


__all__ = [
    "BUNDLE_MARKERS",
    "WebcrackResult",
    "format_js",
    "format_many",
    "format_with_jsbeautifier",
    "format_with_prettier",
    "looks_bundled",
    "looks_obfuscated",
    "needs_rewrite",
    "run_webcrack",
]
