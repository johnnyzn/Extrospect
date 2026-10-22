"""Known-vulnerable libraries (retire.js) + EPSS enrichment (roadmap 1e).

Backends, in order of preference (``static.retire_mode = auto``):

* ``cli``    - the ``retire`` Node CLI (``--outputformat json``)
* ``python`` - a pure-Python matcher over retire's ``jsrepository-v5.json`` (filename,
  file-content and hash extractors), downloaded once per day when online
* ``off``    - CVE dimension reported as unknown

Reachability is recorded as ``unknown`` here; the LLM stage decides it later (M3).
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import regex

from extrospect.cache import Cache
from extrospect.config import Settings
from extrospect.http import HttpClient, OfflineError
from extrospect.models import Notice, VulnFinding
from extrospect.static.nodetools import NodeTools, run_tool
from extrospect.util import JS_EXTENSIONS, iter_files, read_text, to_posix

RETIRE_REPO_URL = (
    "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v5.json"
)
EPSS_URL = "https://api.first.org/data/v1/epss"
REPO_MAX_AGE_S = 24 * 3600
EPSS_TTL_S = 24 * 3600
_VERSION_PLACEHOLDER = "§§version§§"
_VERSION_RE = r"[0-9][0-9.a-z_\-]+"
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
CONTENT_HEAD = 100_000
CONTENT_TAIL = 20_000


@dataclass
class VulnScan:
    findings: list[VulnFinding] = field(default_factory=list)
    libraries: dict[str, tuple[str, str]] = field(
        default_factory=dict
    )  # rel -> (component, version)
    backend: str = "off"
    notices: list[Notice] = field(default_factory=list)


# --------------------------------------------------------------------------- versions


def _comparable(part: str | None) -> int | str:
    if not part:
        return 0
    return int(part) if part.isdigit() else part


def is_at_or_above(version1: str, version2: str) -> bool:
    """Port of retire.js ``isAtOrAbove`` (numbers sort above pre-release strings)."""
    v1 = re.split(r"[.\-]", version1)
    v2 = re.split(r"[.\-]", version2)
    for i in range(max(len(v1), len(v2))):
        a = _comparable(v1[i] if i < len(v1) else None)
        b = _comparable(v2[i] if i < len(v2) else None)
        if type(a) is not type(b):
            return isinstance(a, int)
        if a > b:  # type: ignore[operator]
            return True
        if a < b:  # type: ignore[operator]
            return False
    return True


def is_vulnerable(version: str, vuln: dict[str, Any]) -> bool:
    below = vuln.get("below")
    at_or_above = vuln.get("atOrAbove")
    if at_or_above and not is_at_or_above(version, str(at_or_above)):
        return False
    if below and is_at_or_above(version, str(below)):
        return False
    return bool(below or at_or_above)


_VERSION_SUFFIX_RE = re.compile(
    r"[.\-_](min|slim|prod|production|umd|bundle|esm|dev|debug|pack|packed)$", re.I
)


def clean_version(version: str) -> str:
    """``1.8.1.min`` -> ``1.8.1`` (file-name extractors capture build suffixes)."""
    previous = None
    version = version.strip().strip(".-_")
    while previous != version:
        previous = version
        version = _VERSION_SUFFIX_RE.sub("", version)
    return version


# --------------------------------------------------------------------------- findings


def _finding(component: str, version: str, vuln: dict[str, Any], rel: str | None) -> VulnFinding:
    identifiers = vuln.get("identifiers") or {}
    cves = [c for c in identifiers.get("CVE", []) or [] if isinstance(c, str)]
    ghsa = identifiers.get("githubID")
    summary = identifiers.get("summary")
    primary = (
        cves[0]
        if cves
        else (ghsa or (f"{component}:{summary[:60]}" if summary else f"{component}@{version}"))
    )
    ids = list(dict.fromkeys(cves + ([ghsa] if ghsa else [])))
    return VulnFinding(
        library=component,
        version=version,
        cve=primary,
        identifiers=ids,
        severity=vuln.get("severity"),
        summary=summary,
        file=rel,
        info=[str(i) for i in vuln.get("info", []) or []][:6],
    )


# --------------------------------------------------------------------------- CLI backend


def scan_with_cli(ext_dir: Path, tools: NodeTools, settings: Settings) -> VulnScan:
    scan = VulnScan(backend="cli")
    if not tools.retire:
        raise FileNotFoundError("retire CLI not installed")
    cache_dir = settings.paths.cache_dir / "retire"
    cache_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="extrospect-retire-") as tmp:
        out = Path(tmp) / "retire.json"
        cmd = [
            tools.retire,
            "--path",
            str(ext_dir),
            "--outputformat",
            "json",
            "--outputpath",
            str(out),
            "--cachedir",
            str(cache_dir),
        ]
        result = run_tool(cmd, timeout=settings.tools.timeout_s * 2)
        if result.returncode not in (0, 13) or not out.is_file():
            raise RuntimeError((result.stderr or result.stdout or "retire failed").strip()[:300])
        data = json.loads(out.read_text(encoding="utf-8"))
    root = ext_dir.resolve()
    for entry in data.get("data", []) or []:
        file_path = entry.get("file")
        rel = None
        if file_path:
            try:
                rel = to_posix(Path(file_path).resolve().relative_to(root))
            except ValueError:
                rel = to_posix(file_path)
        for res in entry.get("results", []) or []:
            component, version = str(res.get("component", "?")), str(res.get("version", "?"))
            if rel:
                scan.libraries[rel] = (component, version)
            for vuln in res.get("vulnerabilities", []) or []:
                scan.findings.append(_finding(component, version, vuln, rel))
    return scan


# --------------------------------------------------------------------------- python backend


def _repo_path(settings: Settings) -> Path:
    return settings.paths.cache_dir / "retire" / "jsrepository-v5.json"


def load_repository(settings: Settings, http: HttpClient | None) -> dict[str, Any] | None:
    path = _repo_path(settings)
    fresh = path.is_file() and (time.time() - path.stat().st_mtime) < REPO_MAX_AGE_S
    if not fresh and http is not None and not http.offline:
        try:
            response = http.get(RETIRE_REPO_URL, timeout=60)
            response.raise_for_status()
            data = response.json()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data), encoding="utf-8")
            return data if isinstance(data, dict) else None
        except (OfflineError, Exception):
            pass
    if path.is_file():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            return loaded if isinstance(loaded, dict) else None
        except (OSError, json.JSONDecodeError):
            return None
    return None


def _expand_replacement(template: str, groups: list[str | None]) -> str:
    """Expand ``$1``-style references of a retire ``filecontentreplace`` template."""

    def repl(match: re.Match[str]) -> str:
        index = int(match.group(1))
        return (groups[index] or "") if index < len(groups) else ""

    return re.sub(r"\$(\d)", repl, template)


class RetireMatcher:
    """Applies retire.js extractors (filename / filecontent / filecontentreplace / hashes)."""

    def __init__(self, repository: dict[str, Any]) -> None:
        self.repo = {
            k: v for k, v in repository.items() if isinstance(v, dict) and k != "retire-example"
        }
        self._compiled: dict[str, dict[str, list[Any]]] = {}

    def _patterns(self, component: str, kind: str) -> list[Any]:
        cache = self._compiled.setdefault(component, {})
        if kind in cache:
            return cache[kind]
        raw = (self.repo[component].get("extractors") or {}).get(kind) or []
        compiled: list[Any] = []
        for pattern in raw:
            try:
                if kind == "filecontentreplace":
                    # Format: /regex/replacement/
                    body = pattern[1:]
                    split_at = body.rfind("/", 0, len(body) - 1)
                    rx, repl = body[:split_at], body[split_at + 1 : -1]
                    compiled.append(
                        (regex.compile(rx.replace(_VERSION_PLACEHOLDER, _VERSION_RE)), repl)
                    )
                else:
                    compiled.append(
                        regex.compile(pattern.replace(_VERSION_PLACEHOLDER, _VERSION_RE))
                    )
            except (regex.error, ValueError):
                continue
        cache[kind] = compiled
        return compiled

    def identify(self, rel: str, text: str, sha1: str) -> tuple[str, str] | None:
        hit = self._identify(rel, text, sha1)
        return (hit[0], clean_version(hit[1])) if hit else None

    def _identify(self, rel: str, text: str, sha1: str) -> tuple[str, str] | None:
        name = rel.rsplit("/", 1)[-1]
        if len(text) > CONTENT_HEAD + CONTENT_TAIL:
            # Version banners and markers live near the start (or the end) of library files;
            # scanning whole multi-megabyte bundles with ~400 regexes is too slow.
            text = text[:CONTENT_HEAD] + "\n" + text[-CONTENT_TAIL:]
        for component, lib in self.repo.items():
            hashes = (lib.get("extractors") or {}).get("hashes") or {}
            if sha1 in hashes:
                return component, str(hashes[sha1])
        for component in self.repo:
            for pattern in self._patterns(component, "filename"):
                match = pattern.search(name, timeout=0.2)
                if match and match.groups():
                    return component, match.group(1)
        for component in self.repo:
            for pattern in self._patterns(component, "filecontent"):
                try:
                    match = pattern.search(text, timeout=1.0)
                except TimeoutError:
                    continue
                if match and match.groups() and match.group(1):
                    return component, match.group(1)
            for pattern, repl in self._patterns(component, "filecontentreplace"):
                try:
                    match = pattern.search(text, timeout=1.0)
                except TimeoutError:
                    continue
                if match:
                    version = _expand_replacement(repl, [match.group(0), *match.groups()])
                    if version:
                        return component, version
        return None

    def vulnerabilities(self, component: str, version: str) -> list[dict[str, Any]]:
        return [
            v
            for v in self.repo.get(component, {}).get("vulnerabilities", []) or []
            if is_vulnerable(version, v)
        ]


def scan_with_python(ext_dir: Path, repository: dict[str, Any], max_bytes: int) -> VulnScan:
    scan = VulnScan(backend="python")
    matcher = RetireMatcher(repository)
    for path in iter_files(ext_dir, JS_EXTENSIONS):
        if path.stat().st_size > max_bytes:
            continue
        rel = to_posix(path.relative_to(ext_dir))
        data = path.read_bytes()
        hit = matcher.identify(rel, read_text(path), hashlib.sha1(data).hexdigest())
        if not hit:
            continue
        component, version = hit
        scan.libraries[rel] = (component, version)
        for vuln in matcher.vulnerabilities(component, version):
            scan.findings.append(_finding(component, version, vuln, rel))
    return scan


# --------------------------------------------------------------------------- EPSS


def fetch_epss(
    cves: list[str], http: HttpClient | None, cache: Cache | None
) -> dict[str, tuple[float, float]]:
    """CVE -> (epss probability, percentile). Cached for a day; missing on failure."""
    result: dict[str, tuple[float, float]] = {}
    missing: list[str] = []
    for cve in dict.fromkeys(c.upper() for c in cves if _CVE_RE.match(c)):
        cached = cache.get_kv("epss", cve) if cache else None
        if cached is not None:
            if cached:
                result[cve] = (float(cached[0]), float(cached[1]))
        else:
            missing.append(cve)
    if not missing or http is None or http.offline:
        return result
    for i in range(0, len(missing), 80):
        batch = missing[i : i + 80]
        try:
            payload = http.get_json(EPSS_URL, params={"cve": ",".join(batch)})
        except Exception:
            continue
        seen: set[str] = set()
        for row in payload.get("data", []) or []:
            cve = str(row.get("cve", "")).upper()
            try:
                value = (float(row.get("epss")), float(row.get("percentile")))
            except (TypeError, ValueError):
                continue
            result[cve] = value
            seen.add(cve)
            if cache:
                cache.put_kv("epss", cve, list(value), ttl_s=EPSS_TTL_S)
        if cache:
            for cve in set(batch) - seen:
                cache.put_kv("epss", cve, [], ttl_s=EPSS_TTL_S)  # known-unknown, avoid refetching
    return result


def enrich_epss(findings: list[VulnFinding], http: HttpClient | None, cache: Cache | None) -> None:
    cves = [i for f in findings for i in ([f.cve, *f.identifiers]) if _CVE_RE.match(i)]
    scores = fetch_epss(cves, http, cache)
    for finding in findings:
        best: tuple[float, float] | None = None
        for ident in [finding.cve, *finding.identifiers]:
            score = scores.get(ident.upper())
            if score and (best is None or score[1] > best[1]):
                best = score
        if best:
            finding.epss, finding.epss_percentile = best


# --------------------------------------------------------------------------- entry point


def scan_vulnerabilities(
    ext_dir: Path,
    settings: Settings,
    tools: NodeTools,
    http: HttpClient | None,
    cache: Cache | None,
) -> VulnScan:
    mode = settings.static.retire_mode
    scan: VulnScan | None = None
    notices: list[Notice] = []
    if mode in {"auto", "cli"} and tools.retire:
        try:
            scan = scan_with_cli(ext_dir, tools, settings)
        except (RuntimeError, OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            notices.append(Notice(code="retire_cli_failed", params={"error": str(exc)[:200]}))
    if scan is None and mode in {"auto", "python"}:
        repository = load_repository(settings, http)
        if repository:
            scan = scan_with_python(ext_dir, repository, settings.static.max_parse_bytes)
        else:
            notices.append(Notice(code="vulns_unavailable"))
    if scan is None:
        scan = VulnScan(backend="off")
        if mode == "off":
            notices.append(Notice(code="vulns_disabled", level="info"))
    scan.notices.extend(notices)
    if scan.findings and settings.network.epss:
        enrich_epss(scan.findings, http, cache)
        if http is None or http.offline:
            scan.notices.append(Notice(code="epss_offline", level="info"))
    return scan


__all__ = [
    "RetireMatcher",
    "VulnScan",
    "clean_version",
    "enrich_epss",
    "fetch_epss",
    "is_at_or_above",
    "is_vulnerable",
    "load_repository",
    "scan_vulnerabilities",
    "scan_with_cli",
    "scan_with_python",
]
