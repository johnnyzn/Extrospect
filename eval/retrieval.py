"""RAG-B retrieval evaluation: can a malicious slice recall other samples of its family?

Leave-one-sample-out over the malicious samples of one split: every high-danger slice
queries all slices of *other* samples; a hit means one of the top-k neighbours has the
same family. Reports recall@k and MRR per embedding model, which is how the default
embedder for the intel index is chosen (roadmap M4).

    uv run python eval/retrieval.py --dataset eval/datasets/seed.jsonl --samples eval/samples \
        --embedders hash,litellm:text-embedding-3-small
"""

from __future__ import annotations

import argparse
import math
import sys
from dataclasses import dataclass
from pathlib import Path

from extrospect.config import load_settings
from extrospect.evaluation import load_dataset, resolve_sample
from extrospect.knowledge.embeddings import get_embedder

ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Entry:
    ext_id: str
    family: str
    code: str


def collect(
    dataset: Path, samples: Path, split: str, min_danger: float, offline: bool
) -> list[Entry]:
    from extrospect.pipeline import Context, static_for

    overrides = {"network": {"offline": True}} if offline else {}
    ctx = Context.create(settings=load_settings(overrides=overrides), language="en")
    entries: list[Entry] = []
    try:
        for row in load_dataset(dataset):
            if row.label != "malicious" or (split != "all" and row.split != split):
                continue
            sample = resolve_sample(row, samples, dataset.parent)
            if sample is None:
                continue
            try:
                static = static_for(sample, ctx, allow_download=False)
            except Exception as exc:
                print(f"skip {row.id}: {exc}", file=sys.stderr)
                continue
            entries.extend(
                Entry(row.id, row.family, s.code) for s in static.slices if s.danger >= min_danger
            )
    finally:
        ctx.close()
    return entries


def evaluate(entries: list[Entry], embedder_spec: str, k: int) -> dict[str, float]:
    embedder = get_embedder(embedder_spec)
    vectors = embedder.embed([e.code for e in entries])
    norms = [math.sqrt(sum(v * v for v in vec)) or 1.0 for vec in vectors]
    family_samples: dict[str, set[str]] = {}
    for entry in entries:
        family_samples.setdefault(entry.family, set()).add(entry.ext_id)
    hits = 0
    reciprocal = 0.0
    queries = 0
    for i, entry in enumerate(entries):
        if len(family_samples[entry.family]) < 2:
            continue  # no other sample of this family to recall
        queries += 1
        scored = []
        for j, other in enumerate(entries):
            if other.ext_id == entry.ext_id:
                continue
            dot = sum(a * b for a, b in zip(vectors[i], vectors[j], strict=False))
            scored.append((dot / (norms[i] * norms[j]), other.family))
        scored.sort(key=lambda x: -x[0])
        ranks = [
            rank for rank, (_, family) in enumerate(scored[:k], start=1) if family == entry.family
        ]
        if ranks:
            hits += 1
            reciprocal += 1.0 / ranks[0]
    return {
        "queries": float(queries),
        f"recall@{k}": hits / queries if queries else 0.0,
        "mrr": reciprocal / queries if queries else 0.0,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--dataset", type=Path, default=ROOT / "eval/datasets/seed.jsonl")
    parser.add_argument("--samples", type=Path, default=ROOT / "eval/samples")
    parser.add_argument("--split", default="train")
    parser.add_argument("--embedders", default="hash")
    parser.add_argument("--k", type=int, default=5)
    parser.add_argument("--min-danger", type=float, default=0.5)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args(argv)
    entries = collect(args.dataset, args.samples, args.split, args.min_danger, args.offline)
    if not entries:
        print("no malicious slices found - fetch or import samples first", file=sys.stderr)
        return 1
    print(
        f"{len(entries)} slices from {len({e.ext_id for e in entries})} samples, {len({e.family for e in entries})} families"
    )
    print(f"| embedder | queries | recall@{args.k} | MRR |")
    print("|---|---|---|---|")
    for spec in [s.strip() for s in args.embedders.split(",") if s.strip()]:
        result = evaluate(entries, spec, args.k)
        print(
            f"| {spec} | {int(result['queries'])} | {result[f'recall@{args.k}'] * 100:.1f}% | {result['mrr']:.3f} |"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
