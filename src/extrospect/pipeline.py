"""Top-level orchestration: resolve a target, run the static pipeline, optionally the LLM
pipeline (Engine mode), fuse the scores and produce a :class:`~extrospect.models.Report`.

Entry points:

* :func:`quick_scan` - static only, zero tokens (CLI ``scan``, MCP ``quick_scan``)
* :func:`analyze`    - full Engine mode with the user's own API key (CLI ``analyze``)
"""

from __future__ import annotations

import time
import uuid
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from extrospect.acquire.crx_download import download_crx
from extrospect.acquire.local_profile import find_installed
from extrospect.acquire.unpack import UnpackError, parse_crx_header, unpack_file
from extrospect.baseline.rules import rule_score
from extrospect.cache import Cache
from extrospect.config import PIPELINE_VERSION, Settings, load_settings
from extrospect.fuse import FuseInputs, fuse
from extrospect.http import HttpClient
from extrospect.i18n import get_language
from extrospect.knowledge.domains import is_first_party
from extrospect.models import (
    EXTENSION_ID_RE,
    ExtensionRef,
    ListingInfo,
    LlmUsage,
    Notice,
    Report,
    SliceSummary,
    TriageResult,
    Verdict,
)
from extrospect.static.analyzer import StaticResult, run_static
from extrospect.static.manifest import extension_id_for, read_manifest
from extrospect.static.nodetools import NodeTools, resolve_tools
from extrospect.static.sinks import EXFIL_KINDS, sink_counts
from extrospect.util import sha256_file

TOP_SINKS_IN_REPORT = 60


class TargetError(ValueError):
    """The analysis target could not be resolved."""


@dataclass
class Context:
    """Long-lived services shared by every analysis (cache, HTTP, tools, settings)."""

    settings: Settings
    cache: Cache
    http: HttpClient
    tools: NodeTools
    language: str = "en"
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        settings: Settings | None = None,
        language: str | None = None,
        cache: Cache | None = None,
        http: HttpClient | None = None,
    ) -> Context:
        settings = settings or load_settings()
        settings.ensure_dirs()
        return cls(
            settings=settings,
            cache=cache or Cache(settings.paths.cache_db),
            http=http or HttpClient(settings.network),
            tools=resolve_tools(settings.tools),
            language=language or get_language(),
        )

    def close(self) -> None:
        self.http.close()
        self.cache.close()


# --------------------------------------------------------------------------- targets


def resolve_target(
    target: str | Path, ctx: Context, prefer_local: bool = True, allow_download: bool = True
) -> tuple[ExtensionRef, Path]:
    """Return (ref, unpacked directory) for a path, CRX/ZIP file or extension id."""
    text = str(target).strip()
    path = Path(text).expanduser()
    if path.exists():
        if path.is_dir():
            raw = read_manifest(path)
            ext_id = extension_id_for(path, raw)
            return ExtensionRef(
                id=ext_id, version=str(raw.get("version") or "") or None, source="file", path=path
            ), path
        if path.suffix.lower() in {".crx", ".zip"}:
            digest = sha256_file(path)
            dest = ctx.settings.paths.cache_dir / "unpacked" / digest[:20]
            if (dest / "manifest.json").is_file():
                with path.open("rb") as fh:
                    head = fh.read(1 << 20)
                try:
                    crx_id = parse_crx_header(head).extension_id
                except UnpackError:
                    crx_id = None
            else:
                info = unpack_file(
                    path,
                    dest,
                    max_bytes=ctx.settings.static.max_unpack_bytes,
                    max_files=ctx.settings.static.max_unpack_files,
                )
                crx_id = info.extension_id
            raw = read_manifest(dest)
            ext_id = crx_id or extension_id_for(dest, raw)
            return ExtensionRef(
                id=ext_id, version=str(raw.get("version") or "") or None, source="file", path=dest
            ), dest
        raise TargetError(
            f"unsupported file type: {path.name} (expected a directory, .crx or .zip)"
        )

    ext_id = text.lower()
    if not EXTENSION_ID_RE.match(ext_id):
        raise TargetError(f"not a path or an extension id: {text}")
    if prefer_local:
        installed = find_installed(ext_id)
        if installed is not None and installed.ref.path is not None:
            return installed.ref, installed.ref.path
    if allow_download:
        result = download_crx(ext_id, ctx.settings, ctx.http)
        crx_path, digest = result.path, result.sha256
    else:
        # A copy downloaded earlier (e.g. before an MCP server restart) needs no new download.
        downloads = ctx.settings.paths.downloads_dir
        cached = (
            sorted(downloads.glob(f"{ext_id}_*.crx"), key=lambda p: p.stat().st_mtime)
            if downloads.is_dir()
            else []
        )
        if not cached:
            raise TargetError(f"{ext_id} is not installed locally and downloads are disabled")
        crx_path, digest = cached[-1], sha256_file(cached[-1])
    dest = ctx.settings.paths.cache_dir / "unpacked" / digest[:20]
    if not (dest / "manifest.json").is_file():
        unpack_file(
            crx_path,
            dest,
            max_bytes=ctx.settings.static.max_unpack_bytes,
            max_files=ctx.settings.static.max_unpack_files,
        )
    raw = read_manifest(dest)
    return ExtensionRef(
        id=ext_id, version=str(raw.get("version") or "") or None, source="webstore", path=dest
    ), dest


# --------------------------------------------------------------------------- report


def exfil_targets_first_party(
    static: StaticResult, verdict: Verdict | None, first_party: set[str]
) -> bool:
    """True when every host data is sent to is first-party (and there is at least one)."""
    if not first_party:
        return False
    targets: list[str] = list(verdict.exfil_targets) if verdict and verdict.exfil_targets else []
    if not targets:
        exfil_files = {s.file for s in static.sinks if s.kind in EXFIL_KINDS}
        targets = [e.host for e in static.endpoints if e.file in exfil_files]
    if not targets:
        return False
    return all(is_first_party(t, first_party) for t in targets)


def build_report(
    static: StaticResult,
    ctx: Context,
    *,
    mode: str = "static",
    verdict: Verdict | None = None,
    triage: list[TriageResult] | None = None,
    usage: LlmUsage | None = None,
    listing: ListingInfo | None = None,
    gbm_prob: float | None = None,
    trace_id: str | None = None,
    notices: list[Notice] | None = None,
    started: float | None = None,
) -> Report:
    rules = rule_score(
        static.sinks, static.capability, static.injections, static.stats.obfuscation_score
    )
    first_party = set(static.first_party)
    if listing is not None:
        first_party |= set(listing.first_party_domains)
        for endpoint in static.endpoints:
            endpoint.first_party = is_first_party(endpoint.host, first_party)
    inputs = FuseInputs(
        capability=static.capability,
        vulns=static.vulns,
        verdict=verdict,
        gbm_prob=gbm_prob,
        rules_prob=rules.probability,
        exfil_all_first_party=exfil_targets_first_party(static, verdict, first_party),
    )
    score, level, breakdown = fuse(inputs, ctx.settings.fuse)
    usage = usage or LlmUsage()
    top = sorted(static.sinks, key=lambda s: -s.weight)[:TOP_SINKS_IN_REPORT]
    report = Report(
        ref=static.ref,
        manifest=static.manifest,
        capability=static.capability,
        vulns=static.vulns,
        verdict=verdict,
        score=score,
        level=level,
        cost_usd=round(usage.cost_usd, 6),
        tokens={
            "input": usage.input_tokens,
            "output": usage.output_tokens,
            "cache_read": usage.cache_read_tokens,
            "cache_write": usage.cache_write_tokens,
            "calls": usage.calls,
        },
        pipeline_version=PIPELINE_VERSION,
        trace_id=trace_id or uuid.uuid4().hex[:16],
        mode=mode,  # type: ignore[arg-type]
        language=ctx.language,
        breakdown=breakdown,
        sink_counts=sink_counts(static.sinks),
        top_sinks=top,
        slices=[
            SliceSummary(
                slice_id=s.slice_id,
                file=s.file,
                start_line=s.start_line,
                end_line=s.end_line,
                context=s.context,
                danger=s.danger,
                sink_kinds=sorted({k.kind for k in s.sinks}),
            )
            for s in static.slices
        ],
        triage=triage or [],
        endpoints=static.endpoints[:200],
        libraries=static.libraries,
        stats=static.stats,
        listing=listing,
        injection_attempts=static.injections,
        notices=list(static.notices) + list(notices or []),
        duration_s=round(time.perf_counter() - started, 3)
        if started
        else round(static.duration_s, 3),
    )
    report.breakdown.rules_prob = rules.probability
    return report


def save_report(report: Report, ctx: Context) -> None:
    ctx.cache.put_report(
        report.ref.id,
        report.ref.version or "",
        report.pipeline_version,
        report.mode,
        report.language,
        report.model_dump(mode="json"),
    )


def load_cached_report(ext_id: str, version: str | None, mode: str, ctx: Context) -> Report | None:
    data = ctx.cache.get_report(ext_id, version or "", PIPELINE_VERSION, mode)
    return Report.model_validate(data) if data else None


# --------------------------------------------------------------------------- entry points


def static_for(
    target: str | Path, ctx: Context, *, prefer_local: bool = True, allow_download: bool = True
) -> StaticResult:
    ref, ext_dir = resolve_target(
        target, ctx, prefer_local=prefer_local, allow_download=allow_download
    )
    return run_static(
        ext_dir,
        ref,
        ctx.settings,
        tools=ctx.tools,
        cache=ctx.cache,
        http=ctx.http,
        language=ctx.language,
    )


def quick_scan(
    target: str | Path,
    ctx: Context,
    *,
    prefer_local: bool = True,
    allow_download: bool = True,
    use_cache: bool = True,
) -> tuple[Report, StaticResult]:
    """Static analysis + rule baseline + fusion. Never calls an LLM."""
    started = time.perf_counter()
    static = static_for(target, ctx, prefer_local=prefer_local, allow_download=allow_download)
    report = build_report(static, ctx, mode="static", started=started)
    save_report(report, ctx)
    del use_cache  # static scans are cheap; per-file results are cached inside run_static
    return report, static


def analyze(
    target: str | Path,
    ctx: Context,
    *,
    prefer_local: bool = True,
    allow_download: bool = True,
    use_cache: bool = True,
    llm: Any = None,
) -> Report:
    """Full Engine-mode analysis (static + layered LLM pipeline). Requires an API key."""
    from extrospect.llm.engine import run_engine

    started = time.perf_counter()
    static = static_for(target, ctx, prefer_local=prefer_local, allow_download=allow_download)
    if use_cache:
        cached = load_cached_report(static.ref.id, static.ref.version, "engine", ctx)
        if cached is not None:
            cached.notices.append(Notice(code="report_from_cache", level="info"))
            return cached
    outcome = run_engine(static, ctx, llm=llm)
    for finding in static.vulns:
        reach = outcome.reachability.get(finding.cve)
        if reach:
            finding.reachable, finding.reachability_evidence = reach
    report = build_report(
        static,
        ctx,
        mode="engine",
        verdict=outcome.verdict,
        triage=outcome.triage,
        usage=outcome.usage,
        listing=outcome.listing,
        gbm_prob=outcome.gbm_prob,
        trace_id=outcome.trace_id,
        notices=outcome.notices,
        started=started,
    )
    save_report(report, ctx)
    return report


def summarize_counts(reports: list[Report]) -> dict[str, int]:
    return dict(Counter(r.level for r in reports))


__all__ = [
    "Context",
    "TargetError",
    "analyze",
    "build_report",
    "exfil_targets_first_party",
    "load_cached_report",
    "quick_scan",
    "resolve_target",
    "save_report",
    "static_for",
]
