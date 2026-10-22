"""Call-relation based code slicing around sinks (roadmap 1g).

A slice is centred on the function containing a sink, enlarged to its parent when the
function is a tiny anonymous callback, and complemented with up to ``caller_depth``
levels of same-file callers (matched by name). Overlapping slices are merged. Every
slice stays within ``slice_max_lines`` lines / ``slice_max_tokens`` tokens; long minified
lines are clipped. Code comes from the *sanitised* text (comments stripped, long strings
elided) while line numbers stay those of the analysed file.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from extrospect.config import StaticConfig
from extrospect.llm.sanitize import SanitizedSource
from extrospect.models import CodeSlice, ContextKind, Sink
from extrospect.static.jsparse import FunctionInfo, ParsedJs
from extrospect.static.sinks import FileScan
from extrospect.util import estimate_tokens, short_hash

MIN_SLICE_WEIGHT = 0.2
MAX_CALL_SITES = 3
CALLER_FULL_LINES = 60
LONG_LINE = 400
_COMMON_NAMES = {
    "init",
    "get",
    "set",
    "run",
    "main",
    "start",
    "stop",
    "send",
    "load",
    "then",
    "catch",
    "push",
    "call",
    "apply",
    "bind",
    "callback",
    "handler",
    "handle",
    "update",
    "render",
    "default",
    "value",
    "next",
    "done",
    "resolve",
    "reject",
    "log",
}

Segment = tuple[int, int]


@dataclass
class FileBundle:
    """Everything the slicer needs about one analysed JS file."""

    parsed: ParsedJs
    scan: FileScan
    sanitized: SanitizedSource
    context: ContextKind

    @property
    def rel(self) -> str:
        return self.parsed.rel


@dataclass
class _Region:
    segments: list[Segment]
    sinks: list[Sink] = field(default_factory=list)
    functions: list[str] = field(default_factory=list)

    @property
    def size(self) -> int:
        return sum(e - s + 1 for s, e in merge_segments(self.segments))


def merge_segments(segments: list[Segment], gap: int = 2) -> list[Segment]:
    merged: list[Segment] = []
    for start, end in sorted(segments):
        if merged and start <= merged[-1][1] + gap + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _overlaps(a: list[Segment], b: list[Segment], gap: int = 2) -> bool:
    for s1, e1 in a:
        for s2, e2 in b:
            if s1 <= e2 + gap and s2 <= e1 + gap:
                return True
    return False


def _clip(seg: Segment, total_lines: int) -> Segment:
    return (max(1, seg[0]), min(total_lines, seg[1]))


def _center_function(bundle: FileBundle, sink: Sink, max_lines: int) -> FunctionInfo | None:
    parsed = bundle.parsed
    fn = parsed.function_at(sink.line, sink.column)
    while fn is not None and fn.parent is not None and fn.lines < 12:
        parent = parsed.function_by_index(fn.parent)
        if parent is None or parent.lines > max_lines:
            break
        fn = parent
    return fn


def _function_region(
    fn: FunctionInfo, focus_line: int, max_lines: int, window: int = 40
) -> list[Segment]:
    if fn.lines <= max_lines:
        return [(fn.start_line, fn.end_line)]
    start = max(fn.start_line, focus_line - window)
    end = min(fn.end_line, focus_line + window)
    segments = [(start, end)]
    if start > fn.start_line:
        segments.append((fn.start_line, fn.start_line))
    return segments


def _caller_segments(
    bundle: FileBundle, fn: FunctionInfo, depth: int, max_lines: int
) -> tuple[list[Segment], list[str]]:
    segments: list[Segment] = []
    names: list[str] = []
    frontier = [fn]
    seen = {fn.index}
    for _ in range(depth):
        next_frontier: list[FunctionInfo] = []
        for current in frontier:
            name = current.name
            if not name or len(name) < 3 or name in _COMMON_NAMES:
                continue
            sites = bundle.scan.call_sites.get(name, [])[:MAX_CALL_SITES]
            for line, caller_idx in sites:
                caller = bundle.parsed.function_by_index(caller_idx)
                if caller is None:
                    segments.append((line - 3, line + 3))
                    continue
                if caller.index in seen:
                    continue
                seen.add(caller.index)
                names.append(caller.display)
                if caller.lines <= CALLER_FULL_LINES:
                    segments.append((caller.start_line, caller.end_line))
                else:
                    segments.append((caller.start_line, caller.start_line))
                    segments.append((line - 8, line + 8))
                next_frontier.append(caller)
        frontier = next_frontier
        if not frontier:
            break
    return segments, names


def _region_for(bundle: FileBundle, sink: Sink, cfg: StaticConfig) -> _Region:
    total = len(bundle.parsed.lines)
    fn = _center_function(bundle, sink, cfg.slice_max_lines)
    if fn is None:
        segments = [_clip((sink.line - 15, sink.line + 15), total)]
        return _Region(segments=segments, sinks=[sink], functions=[])
    segments = [_clip(s, total) for s in _function_region(fn, sink.line, cfg.slice_max_lines)]
    functions = [fn.display]
    if cfg.caller_depth > 0:
        callers, names = _caller_segments(bundle, fn, cfg.caller_depth, cfg.slice_max_lines)
        candidate = merge_segments(segments + [_clip(s, total) for s in callers])
        if sum(e - s + 1 for s, e in candidate) <= cfg.slice_max_lines:
            segments = candidate
            functions.extend(names)
    return _Region(segments=merge_segments(segments), sinks=[sink], functions=functions)


def _shrink(region: _Region, max_lines: int, window: int) -> list[Segment]:
    """Keep only windows around sink lines when a region is too large."""
    focus = sorted({s.line for s in region.sinks})
    segments = merge_segments([(line - window, line + window) for line in focus])
    while sum(e - s + 1 for s, e in segments) > max_lines and window > 3:
        window = max(3, window // 2)
        segments = merge_segments([(line - window, line + window) for line in focus])
    return segments


def _render(bundle: FileBundle, segments: list[Segment]) -> tuple[str, list[int]]:
    lines = bundle.sanitized.lines
    out: list[str] = []
    line_map: list[int] = []
    previous_end = 0
    for start, end in segments:
        if out and start > previous_end + 1:
            out.append(f"/* … lines {previous_end + 1}-{start - 1} omitted … */")
            line_map.append(0)
        for number in range(start, end + 1):
            text = lines[number - 1] if number - 1 < len(lines) else ""
            if len(text) > LONG_LINE:
                text = text[:LONG_LINE] + f" …[+{len(text) - LONG_LINE} chars]"
            out.append(text)
            line_map.append(number)
        previous_end = end
    return "\n".join(out), line_map


def _danger(sinks: list[Sink], context: ContextKind) -> float:
    if not sinks:
        return 0.0
    top = max(s.weight for s in sinks)
    groups = {s.group for s in sinks}
    bonus = 0.05 * (len(groups) - 1)
    if context == "background" and any(s.group in {"exfil", "source"} for s in sinks):
        bonus += 0.02
    return round(min(1.0, top + bonus), 3)


def _finalize(bundle: FileBundle, region: _Region, cfg: StaticConfig) -> CodeSlice:
    total = len(bundle.parsed.lines)
    segments = [_clip(s, total) for s in merge_segments(region.segments)]
    if sum(e - s + 1 for s, e in segments) > cfg.slice_max_lines:
        segments = [_clip(s, total) for s in _shrink(region, cfg.slice_max_lines, 40)]
    code, line_map = _render(bundle, segments)
    window = 30
    while estimate_tokens(code) > cfg.slice_max_tokens and window >= 4:
        segments = [_clip(s, total) for s in _shrink(region, cfg.slice_max_lines, window)]
        code, line_map = _render(bundle, segments)
        window //= 2
    sinks = sorted(region.sinks, key=lambda s: (s.line, -s.weight))
    return CodeSlice(
        slice_id=short_hash(f"{bundle.context}\n{code}", 16),
        file=bundle.rel,
        start_line=segments[0][0],
        end_line=segments[-1][1],
        code=code,
        line_map=line_map,
        sinks=sinks,
        context=bundle.context,
        segments=segments,
        functions=list(dict.fromkeys(region.functions)),
        danger=_danger(sinks, bundle.context),
        tokens=estimate_tokens(code),
    )


def build_file_slices(
    bundle: FileBundle, cfg: StaticConfig, min_weight: float = MIN_SLICE_WEIGHT
) -> list[CodeSlice]:
    sinks = [s for s in bundle.scan.sinks if s.weight >= min_weight and not s.in_library]
    if not sinks:
        return []
    regions = [_region_for(bundle, sink, cfg) for sink in sorted(sinks, key=lambda s: -s.weight)]
    merged: list[_Region] = []
    for region in regions:
        for existing in merged:
            if _overlaps(existing.segments, region.segments):
                combined = merge_segments(existing.segments + region.segments)
                if sum(e - s + 1 for s, e in combined) <= cfg.slice_max_lines:
                    existing.segments = combined
                    existing.sinks.extend(region.sinks)
                    existing.functions.extend(region.functions)
                    break
        else:
            merged.append(region)
    return [_finalize(bundle, region, cfg) for region in merged]


def build_slices(
    bundles: list[FileBundle], cfg: StaticConfig, min_weight: float = MIN_SLICE_WEIGHT
) -> list[CodeSlice]:
    slices: list[CodeSlice] = []
    seen: set[str] = set()
    for bundle in bundles:
        for slice_ in build_file_slices(bundle, cfg, min_weight):
            if slice_.slice_id in seen:
                continue
            seen.add(slice_.slice_id)
            slices.append(slice_)
    slices.sort(key=lambda s: (-s.danger, s.file, s.start_line))
    return slices


def select_slices(
    slices: list[CodeSlice], max_tokens: int, max_count: int
) -> tuple[list[CodeSlice], bool]:
    """Router #1 helper: top slices by danger within a token budget. Returns (picked, truncated)."""
    picked: list[CodeSlice] = []
    used = 0
    for slice_ in sorted(slices, key=lambda s: -s.danger):
        if len(picked) >= max_count:
            break
        if used + slice_.tokens > max_tokens and picked:
            continue
        picked.append(slice_)
        used += slice_.tokens
    return picked, len(picked) < len(slices)


__all__ = ["FileBundle", "build_file_slices", "build_slices", "merge_segments", "select_slices"]
