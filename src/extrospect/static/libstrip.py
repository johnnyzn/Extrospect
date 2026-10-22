"""Third-party library identification and stripping (roadmap 1f).

A file is treated as a known library when it is identified by retire.js, by a known
SHA-256, by a license banner or by its file name. Library files are excluded from
slicing, *unless* they call sensitive extension APIs - a vendored jQuery does not read
``chrome.cookies``; a trojanised one might. Such files stay in scope and get a note.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import cache
from importlib import resources

import regex

from extrospect.models import LibraryInfo

_BANNERS: list[tuple[str, regex.Pattern[str]]] = [
    (name, regex.compile(pattern, regex.I))
    for name, pattern in [
        ("jquery-ui", r"jQuery UI - v?(\d+\.\d+(?:\.\d+)?)"),
        ("jquery", r"jQuery (?:JavaScript Library )?v?(\d+\.\d+(?:\.\d+)?(?:-[a-z0-9.]+)?)"),
        ("react-dom", r"@license React[\s\S]{0,80}react-dom\.|react-dom\.production\.min\.js"),
        ("react", r"@license React(?: v(\d+\.\d+\.\d+))?"),
        ("vue", r"Vue\.js v(\d+\.\d+\.\d+)"),
        ("angularjs", r"@license AngularJS v(\d+\.\d+\.\d+)"),
        ("angular", r"@license Angular v(\d+\.\d+\.\d+)"),
        ("lodash", r"@license\s+(?:Lodash|lodash)(?: v?(\d+\.\d+\.\d+))?|lodash\.com/license"),
        ("underscore", r"Underscore\.js (\d+\.\d+\.\d+)"),
        ("moment", r"//! moment\.js(?:\s*//! version : (\d+\.\d+\.\d+))?"),
        ("bootstrap", r"Bootstrap v(\d+\.\d+\.\d+)"),
        ("axios", r"(?:/\*!? ?)?Axios v(\d+\.\d+\.\d+)"),
        ("d3", r"https://d3js\.org v(\d+\.\d+\.\d+)"),
        ("chart.js", r"Chart\.js v(\d+\.\d+\.\d+)"),
        ("pdf.js", r"pdfjsVersion|pdfjs-dist|PDFJSDev"),
        ("crypto-js", r"CryptoJS v(\d+\.\d+\.\d+)"),
        ("webextension-polyfill", r"webextension-polyfill"),
        ("dompurify", r"@license DOMPurify (\d+\.\d+\.\d+)|DOMPurify (\d+\.\d+\.\d+)"),
        ("sentry", r"@sentry/browser"),
        ("firebase", r"@firebase/app|Firebase JavaScript SDK"),
        ("socket.io", r"Socket\.IO v(\d+\.\d+\.\d+)"),
        ("highlight.js", r"Highlight\.js v?(\d+\.\d+\.\d+)"),
        ("marked", r"marked v(\d+\.\d+\.\d+)"),
        ("jszip", r"JSZip v(\d+\.\d+\.\d+)"),
        ("popper", r"@popperjs/core v(\d+\.\d+\.\d+)|Popper\.js v(\d+\.\d+\.\d+)"),
        ("core-js", r"core-js (\d+\.\d+\.\d+)"),
        ("handlebars", r"handlebars v(\d+\.\d+\.\d+)"),
        ("sweetalert2", r"sweetalert2 v(\d+\.\d+\.\d+)"),
        ("select2", r"Select2 (\d+\.\d+\.\d+)"),
        ("tesseract.js", r"tesseract\.js"),
        ("mozilla-readability", r"Readability\.js|Arc90"),
    ]
]

_FILENAME_RE = re.compile(
    r"(?:^|/)(jquery(?:-ui)?|react(?:-dom)?|vue|angular|lodash|underscore|moment|bootstrap|axios|d3|chart|"
    r"three|pdf(?:\.worker)?|crypto-js|browser-polyfill|purify|socket\.io|highlight|marked|jszip|popper|"
    r"sweetalert2?|select2|toastr|handlebars|mustache|dexie|localforage|tesseract|hls|video|swiper|"
    r"fontawesome|polyfill|core-js|regenerator-runtime|zepto|backbone|knockout|mathjax|katex|sortable)"
    r"(?:[-.@_]v?(\d+(?:\.\d+)+))?(?:\.(?:min|slim|bundle|umd|esm|production|prod))*\.m?js$",
    re.I,
)
_VENDOR_DIR_RE = re.compile(
    r"(?:^|/)(node_modules|bower_components|vendor|vendors|third[-_]?party|libs?)/", re.I
)
_SENSITIVE_API_RE = regex.compile(
    r"\b(?:chrome|browser)\s*\??\.\s*(cookies|tabs|scripting|webRequest|declarativeNetRequest|history|management|"
    r"debugger|proxy|downloads|bookmarks|identity|webNavigation|privacy|topSites|sessions|desktopCapture|"
    r"tabCapture|pageCapture|userScripts)\s*\??\.\s*\w+"
)
_POLYFILLS = {"webextension-polyfill"}


@dataclass
class LibraryDecision:
    info: LibraryInfo
    strip: bool


@cache
def known_hashes() -> dict[str, str]:
    """sha256 -> "name@version" for popular library builds (see scripts/build_lib_hashes.py)."""
    path = resources.files("extrospect.data").joinpath("lib_hashes.json")
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if not k.startswith("_")}


def identify_library(
    rel: str, text: str, sha256: str | None = None, retire_hit: tuple[str, str] | None = None
) -> LibraryInfo | None:
    if sha256 and sha256 in known_hashes():
        name, _, version = known_hashes()[sha256].partition("@")
        return LibraryInfo(file=rel, name=name, version=version or None, method="hash")
    if retire_hit:
        return LibraryInfo(
            file=rel, name=retire_hit[0], version=retire_hit[1] or None, method="retire"
        )
    head = text[:4000]
    for name, pattern in _BANNERS:
        match = pattern.search(head, timeout=0.5)
        if match:
            banner_version: str | None = next((g for g in match.groups() if g), None)
            return LibraryInfo(file=rel, name=name, version=banner_version, method="banner")
    match = _FILENAME_RE.search(rel)
    if match:
        return LibraryInfo(
            file=rel, name=match.group(1).lower(), version=match.group(2), method="filename"
        )
    if _VENDOR_DIR_RE.search(rel) and len(text) > 20_000:
        name = rel.rsplit("/", 1)[-1].split(".")[0]
        return LibraryInfo(file=rel, name=name, version=None, method="path")
    return None


def decide(info: LibraryInfo, text: str) -> LibraryDecision:
    """Strip a library file unless it touches sensitive extension APIs."""
    if info.method != "hash" and info.name not in _POLYFILLS:
        match = _SENSITIVE_API_RE.search(text, timeout=2.0)
        if match:
            info.stripped = False
            info.note = f"library file calls {match.group(0)} - kept in scope"
            return LibraryDecision(info=info, strip=False)
    info.stripped = True
    return LibraryDecision(info=info, strip=True)


__all__ = ["LibraryDecision", "decide", "identify_library", "known_hashes"]
