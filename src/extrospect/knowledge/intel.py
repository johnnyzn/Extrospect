"""RAG-B: known malicious code techniques, searchable by code similarity.

Sources:
* a built-in corpus of technique exemplars (``data/intel_builtin.jsonl``) written for
  this project - generic re-implementations of publicly documented techniques;
* slices of malicious samples from the **training split** of an evaluation dataset
  (``build_intel``). Never index dev/test samples: that would leak labels into the
  evaluation.
"""

from __future__ import annotations

import json
import threading
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING, Any

from extrospect.knowledge.embeddings import get_embedder
from extrospect.knowledge.store import open_store
from extrospect.util import short_hash

if TYPE_CHECKING:
    from extrospect.pipeline import Context

COLLECTION = "intel"
BUILTIN_VERSION = "builtin-1"
MIN_SLICE_DANGER = 0.5


def builtin_entries() -> list[dict[str, Any]]:
    text = (
        resources.files("extrospect.data")
        .joinpath("intel_builtin.jsonl")
        .read_text(encoding="utf-8")
    )
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _index(ctx: Context, entries: list[dict[str, Any]]) -> int:
    if not entries:
        return 0
    embedder = get_embedder(ctx.settings.knowledge.embedding_model)
    store = open_store(ctx.settings)
    vectors = embedder.embed([e["code"] for e in entries])
    items = [
        (
            e["id"],
            vector,
            e["code"],
            {
                k: e.get(k)
                for k in ("family", "technique", "description", "source", "ext_id", "file")
            },
        )
        for e, vector in zip(entries, vectors, strict=True)
    ]
    return store.add(COLLECTION, embedder.name, items)


_BUILTIN_LOCK = threading.Lock()


def ensure_builtin(ctx: Context) -> None:
    if not ctx.settings.knowledge.use_builtin_intel:
        return
    with _BUILTIN_LOCK:  # parallel first searches must not index the corpus twice
        _ensure_builtin(ctx)


def _ensure_builtin(ctx: Context) -> None:
    embedder = get_embedder(ctx.settings.knowledge.embedding_model)
    marker = ctx.cache.get_kv("intel-builtin", embedder.name)
    if marker == BUILTIN_VERSION and open_store(ctx.settings).count(COLLECTION, embedder.name) > 0:
        return
    _index(ctx, builtin_entries())
    ctx.cache.put_kv("intel-builtin", embedder.name, BUILTIN_VERSION)


def search_intel(code: str, ctx: Context, k: int = 5) -> list[dict[str, Any]]:
    ensure_builtin(ctx)
    embedder = get_embedder(ctx.settings.knowledge.embedding_model)
    vector = embedder.embed([code])[0]
    hits = open_store(ctx.settings).search(COLLECTION, embedder.name, vector, k)
    return [
        {
            "id": hit.id,
            "similarity": round(hit.score, 3),
            "family": hit.metadata.get("family"),
            "technique": hit.metadata.get("technique"),
            "description": hit.metadata.get("description"),
            "source": hit.metadata.get("source"),
            "example": hit.text[:600],
        }
        for hit in hits
    ]


def _dataset_rows(dataset: Path) -> list[dict[str, Any]]:
    rows = []
    for line in dataset.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            rows.append(json.loads(line))
    return rows


def build_intel(
    ctx: Context, dataset: Path | None = None, samples_dir: Path | None = None, split: str = "train"
) -> int:
    """Index the built-in corpus plus malicious slices of the dataset's ``split``."""
    from extrospect.pipeline import static_for

    count = _index(ctx, builtin_entries()) if ctx.settings.knowledge.use_builtin_intel else 0
    if dataset is None:
        return count
    entries: list[dict[str, Any]] = []
    for row in _dataset_rows(dataset):
        if row.get("label") != "malicious" or row.get("split", "train") != split:
            continue
        sample = None
        if row.get("path"):
            sample = Path(row["path"])
        elif samples_dir is not None:
            for candidate in (
                samples_dir / row["id"],
                samples_dir / f"{row['id']}.crx",
                samples_dir / f"{row['id']}.zip",
            ):
                if candidate.exists():
                    sample = candidate
                    break
        if sample is None or not sample.exists():
            continue
        try:
            static = static_for(sample, ctx, allow_download=False)
        except Exception:
            continue
        for slice_ in static.slices:
            if slice_.danger < MIN_SLICE_DANGER:
                continue
            entries.append(
                {
                    "id": f"{row['id']}:{short_hash(slice_.code, 12)}",
                    "family": row.get("family") or "unknown",
                    "technique": ", ".join(sorted({s.kind for s in slice_.sinks}))[:120],
                    "description": row.get("notes") or f"slice of {row.get('name') or row['id']}",
                    "code": slice_.code,
                    "source": row.get("source") or "dataset",
                    "ext_id": row["id"],
                    "file": slice_.file,
                }
            )
    return count + _index(ctx, entries)


__all__ = ["COLLECTION", "build_intel", "builtin_entries", "ensure_builtin", "search_intel"]
