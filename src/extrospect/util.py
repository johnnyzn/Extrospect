"""Small shared helpers: hashing, text decoding, token estimates, safe paths, domains."""

from __future__ import annotations

import hashlib
import math
import os
import re
import shutil
from collections import Counter
from collections.abc import Iterable, Iterator
from functools import cache
from pathlib import Path, PurePosixPath
from typing import Any

JS_EXTENSIONS = (".js", ".mjs", ".cjs", ".jsx")
HTML_EXTENSIONS = (".html", ".htm")
SKIP_DIRS = {"_metadata", ".git", "__MACOSX"}


class PathEscapeError(ValueError):
    """Raised when a user/LLM supplied path tries to leave its sandbox directory."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8", "surrogatepass"))


def sha256_file(path: Path, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def short_hash(text: str, length: int = 16) -> str:
    return sha256_text(text)[:length]


def decode_bytes(data: bytes) -> str:
    """Decode source text the way browsers would for extension files (UTF-8 first)."""
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", "replace")
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", "replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", "replace")


def read_text(path: Path, max_bytes: int | None = None) -> str:
    with path.open("rb") as fh:
        data = fh.read(max_bytes) if max_bytes else fh.read()
    return decode_bytes(data)


def estimate_tokens(text: str) -> int:
    """Cheap token estimate: ~4 chars per token for ASCII, ~1 token per CJK/other char."""
    if not text:
        return 0
    non_ascii = sum(1 for ch in text if ord(ch) > 127)
    ascii_chars = len(text) - non_ascii
    return math.ceil(ascii_chars / 4.0 + non_ascii * 0.9)


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def truncate(text: str, limit: int, marker: str = "…") -> str:
    if len(text) <= limit:
        return text
    return text[: max(0, limit - len(marker))] + marker


def one_line(text: str, limit: int = 200) -> str:
    return truncate(re.sub(r"\s+", " ", text).strip(), limit)


def is_minified(text: str) -> bool:
    """Heuristic: minified/bundled code has very long lines or very few newlines."""
    if len(text) < 2_000:
        return False
    lines = text.splitlines() or [text]
    longest = max(len(line) for line in lines)
    average = len(text) / max(1, len(lines))
    return longest > 2_000 or average > 250


def to_posix(rel: str | Path) -> str:
    return PurePosixPath(str(rel).replace("\\", "/")).as_posix()


def safe_join(root: Path, rel: str | Path) -> Path:
    """Resolve ``rel`` under ``root`` and refuse anything that escapes it."""
    rel_str = str(rel).replace("\\", "/").strip()
    if not rel_str:
        raise PathEscapeError("empty path")
    if re.match(r"^[A-Za-z]:", rel_str) or "\x00" in rel_str:
        raise PathEscapeError(f"absolute or invalid path not allowed: {rel}")
    # Extension paths like "/js/app.js" are relative to the extension root.
    rel_str = rel_str.lstrip("/")
    root_resolved = root.resolve()
    candidate = (root_resolved / rel_str).resolve()
    if candidate != root_resolved and root_resolved not in candidate.parents:
        raise PathEscapeError(f"path escapes the extension directory: {rel}")
    return candidate


def iter_files(root: Path, suffixes: Iterable[str] | None = None) -> Iterator[Path]:
    """Yield files under ``root`` (sorted, no symlinks, skipping metadata dirs)."""
    wanted = tuple(s.lower() for s in suffixes) if suffixes else None
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.is_symlink():
                continue
            if wanted is None or name.lower().endswith(wanted):
                yield path


def find_executable(name: str, configured: str | None = None) -> str | None:
    """Return a runnable path for ``name`` (configured path wins, then PATH)."""
    if configured:
        candidate = Path(configured).expanduser()
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
        found = shutil.which(configured)
        if found:
            return found
        return None
    return shutil.which(name)


@cache
def _tld_extractor() -> Any:
    import tldextract

    # Offline: use the public-suffix snapshot bundled with tldextract, never fetch it.
    return tldextract.TLDExtract(
        suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
    )


_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def registrable_domain(host: str) -> str:
    """``api.grammarly.com`` -> ``grammarly.com`` (public-suffix aware, offline)."""
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return ""
    if host.startswith("[") or _IP_RE.match(host) or host == "localhost":
        return host
    result = _tld_extractor()(host)
    domain = getattr(result, "top_domain_under_public_suffix", None)
    if domain is None:  # older tldextract
        domain = getattr(result, "registered_domain", "")
    if not domain and not getattr(result, "suffix", ""):
        # Unknown TLD (e.g. reserved ".test"/".example"/".internal"): use the last two labels.
        labels = host.split(".")
        return ".".join(labels[-2:]) if len(labels) >= 2 else host
    return domain or host


def is_public_suffix(host: str) -> bool:
    """True for bare public suffixes such as ``com`` or ``co.uk`` (no registrable label)."""
    host = (host or "").strip().lower().rstrip(".")
    if not host or _IP_RE.match(host):
        return False
    result = _tld_extractor()(host)
    return not getattr(result, "domain", "") and bool(getattr(result, "suffix", ""))


def host_of(url: str) -> str:
    match = re.match(r"^(?:[a-z][a-z0-9+.-]*:)?//([^/?#:@]+@)?([^/?#:]+)", url.strip(), re.I)
    if not match:
        return ""
    return match.group(2).lower()


def human_bytes(size: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


__all__ = [
    "HTML_EXTENSIONS",
    "JS_EXTENSIONS",
    "PathEscapeError",
    "decode_bytes",
    "estimate_tokens",
    "find_executable",
    "host_of",
    "human_bytes",
    "is_minified",
    "is_public_suffix",
    "iter_files",
    "one_line",
    "read_text",
    "registrable_domain",
    "safe_join",
    "sha256_bytes",
    "sha256_file",
    "sha256_text",
    "shannon_entropy",
    "short_hash",
    "to_posix",
    "truncate",
]
