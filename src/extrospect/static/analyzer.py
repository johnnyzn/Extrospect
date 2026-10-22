"""Static pipeline orchestration: manifest -> capability -> CVEs -> view -> sinks -> slices."""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from extrospect.cache import Cache
from extrospect.config import Settings
from extrospect.http import HttpClient
from extrospect.knowledge.domains import categorize_domain, first_party_domains, is_first_party
from extrospect.llm.sanitize import injection_weight, sanitize_source
from extrospect.models import (
    CapabilityProfile,
    CodeSlice,
    CodeStats,
    Endpoint,
    ExtensionRef,
    InjectionAttempt,
    LibraryInfo,
    ManifestSummary,
    Notice,
    Sink,
    VulnFinding,
)
from extrospect.static.csp import analyze_csp
from extrospect.static.jsparse import parse_js
from extrospect.static.manifest import load_manifest
from extrospect.static.nodetools import NodeTools
from extrospect.static.permissions import compute_capability
from extrospect.static.sinks import FileScan, scan_file
from extrospect.static.slicer import FileBundle, build_slices
from extrospect.static.surface import AttackSurface, analyze_surface
from extrospect.static.vulns import scan_vulnerabilities
from extrospect.util import one_line, sha256_text
from extrospect.workspace import Workspace, prepare_workspace

ANALYZER_VERSION = "scan-1"


@dataclass
class StaticResult:
    ref: ExtensionRef
    manifest: ManifestSummary
    raw_manifest: dict[str, Any]
    surface: AttackSurface
    capability: CapabilityProfile
    vulns: list[VulnFinding]
    vuln_backend: str
    workspace: Workspace
    bundles: dict[str, FileBundle]
    sinks: list[Sink]
    slices: list[CodeSlice]
    endpoints: list[Endpoint]
    libraries: list[LibraryInfo]
    stats: CodeStats
    injections: list[InjectionAttempt]
    notices: list[Notice]
    strings: dict[str, str]
    flagged_strings: set[str]
    chrome_apis: Counter[str]
    first_party: set[str]
    duration_s: float
    language: str = "en"
    extra: dict[str, Any] = field(default_factory=dict)

    def slice_by_id(self, slice_id: str) -> CodeSlice | None:
        return next((s for s in self.slices if s.slice_id == slice_id), None)


def _injection_sinks(injections: list[InjectionAttempt], bundle: FileBundle) -> list[Sink]:
    sinks = []
    for attempt in injections:
        sinks.append(
            Sink(
                kind="prompt_injection",
                group="suspicious",
                api="text addressed to AI auditors",
                file=attempt.file,
                line=attempt.line,
                snippet=one_line(bundle.parsed.line_text(attempt.line), 200),
                weight=injection_weight(attempt),
                detail=f"{attempt.pattern}: {attempt.text[:120]}",
            )
        )
    return sinks


def run_static(
    ext_dir: Path,
    ref: ExtensionRef,
    settings: Settings,
    *,
    tools: NodeTools,
    cache: Cache | None = None,
    http: HttpClient | None = None,
    language: str = "en",
) -> StaticResult:
    started = time.perf_counter()
    manifest, raw = load_manifest(ext_dir, language)
    if not ref.version:
        ref.version = manifest.version or None
    surface = analyze_surface(ext_dir, manifest)
    capability = compute_capability(manifest, surface, analyze_csp(manifest), language)
    vuln_scan = scan_vulnerabilities(ext_dir, settings, tools, http, cache)
    workspace = prepare_workspace(
        ext_dir, ref.id, settings, tools, surface=surface, retire_libraries=vuln_scan.libraries
    )

    notices: list[Notice] = list(vuln_scan.notices) + list(workspace.meta.notices)
    bundles: dict[str, FileBundle] = {}
    sinks: list[Sink] = []
    endpoints: list[Endpoint] = []
    injections: list[InjectionAttempt] = []
    strings: dict[str, str] = {}
    flagged: set[str] = set()
    chrome_apis: Counter[str] = Counter()
    obfuscation = 0.0
    parse_errors = 0

    for view in sorted(workspace.analyzable(), key=lambda v: v.rel):
        text = workspace.read(view.rel)
        parsed = parse_js(view.rel, text)
        cache_key = f"{ANALYZER_VERSION}:{view.context}"
        digest = sha256_text(text)
        cached = cache.get_file(digest, cache_key) if cache else None
        if cached is not None:
            scan = FileScan.from_dict(cached, rel=view.rel)
        else:
            scan = scan_file(parsed, view.context)
            if cache:
                cache.put_file(digest, cache_key, scan.to_dict())
        sanitized = sanitize_source(parsed, settings.static.long_string_threshold)
        bundle = FileBundle(parsed=parsed, scan=scan, sanitized=sanitized, context=view.context)
        if sanitized.injections:
            injections.extend(sanitized.injections)
            scan.sinks.extend(_injection_sinks(sanitized.injections, bundle))
        bundles[view.rel] = bundle
        sinks.extend(scan.sinks)
        endpoints.extend(scan.endpoints)
        strings.update(sanitized.strings)
        flagged |= sanitized.flagged
        chrome_apis.update(scan.chrome_apis)
        obfuscation = max(obfuscation, scan.obfuscation.score)
        parse_errors += int(scan.parse_error)

    slices = build_slices(list(bundles.values()), settings.static)
    workspace.store_strings(strings, flagged)

    author_email = manifest.author if manifest.author and "@" in manifest.author else None
    first_party = first_party_domains(
        [manifest.homepage_url, manifest.update_url if surface.offstore_update_url else None],
        [author_email],
    )
    for endpoint in endpoints:
        endpoint.first_party = is_first_party(endpoint.host, first_party)
        endpoint.category = endpoint.category or categorize_domain(endpoint.host)

    stats = workspace.meta.stats.model_copy()
    stats.obfuscation_score = round(obfuscation, 3)
    stats.parse_errors = parse_errors
    if not tools.retire and vuln_scan.backend == "python":
        notices.append(Notice(code="retire_missing", level="info"))
    if not tools.webcrack and settings.static.deobfuscate and stats.minified_files:
        notices.append(Notice(code="webcrack_missing_summary", level="info"))

    return StaticResult(
        ref=ref,
        manifest=manifest,
        raw_manifest=raw,
        surface=surface,
        capability=capability,
        vulns=vuln_scan.findings,
        vuln_backend=vuln_scan.backend,
        workspace=workspace,
        bundles=bundles,
        sinks=sinks,
        slices=slices,
        endpoints=_dedupe_endpoints(endpoints),
        libraries=workspace.meta.libraries,
        stats=stats,
        injections=injections,
        notices=_dedupe_notices(notices),
        strings=strings,
        flagged_strings=flagged,
        chrome_apis=chrome_apis,
        first_party=first_party,
        duration_s=time.perf_counter() - started,
        language=language,
    )


def _dedupe_endpoints(endpoints: list[Endpoint]) -> list[Endpoint]:
    seen: set[tuple[str, str]] = set()
    unique = []
    for endpoint in endpoints:
        key = (endpoint.url, endpoint.file)
        if key in seen:
            continue
        seen.add(key)
        unique.append(endpoint)
    return unique


def _dedupe_notices(notices: list[Notice]) -> list[Notice]:
    seen: set[str] = set()
    unique = []
    for notice in notices:
        key = notice.code + repr(sorted(notice.params.items()))
        if key in seen:
            continue
        seen.add(key)
        unique.append(notice)
    return unique


__all__ = ["ANALYZER_VERSION", "StaticResult", "run_static"]
