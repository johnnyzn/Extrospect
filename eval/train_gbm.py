"""Train the LightGBM baseline on a dataset split (groups = families, no leakage).

uv run python eval/train_gbm.py --dataset eval/datasets/seed.jsonl --samples eval/samples --split train
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from extrospect.baseline.gbm import train
from extrospect.config import load_settings
from extrospect.evaluation import load_dataset, resolve_sample
from extrospect.static.features import feature_vector

ROOT = Path(__file__).resolve().parent.parent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--dataset", type=Path, default=ROOT / "eval/datasets/seed.jsonl")
    parser.add_argument("--samples", type=Path, default=ROOT / "eval/samples")
    parser.add_argument("--split", default="train")
    parser.add_argument("--out", type=Path, help="Model directory (default: <data dir>/models).")
    parser.add_argument("--rounds", type=int, default=300)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args(argv)

    from extrospect.pipeline import Context, static_for

    overrides = {"network": {"offline": True}} if args.offline else {}
    ctx = Context.create(settings=load_settings(overrides=overrides), language="en")
    vectors: list[list[float]] = []
    labels: list[int] = []
    groups: list[str] = []
    try:
        for row in load_dataset(args.dataset):
            if args.split != "all" and row.split != args.split:
                continue
            sample = resolve_sample(row, args.samples, args.dataset.parent)
            if sample is None:
                continue
            try:
                static = static_for(sample, ctx, allow_download=False)
            except Exception as exc:
                print(f"skip {row.id}: {exc}", file=sys.stderr)
                continue
            vectors.append(feature_vector(static))
            labels.append(1 if row.positive else 0)
            groups.append(row.family)
        if len(set(labels)) < 2:
            print(
                f"need both classes; found {len(labels)} sample(s) with labels {sorted(set(labels))}",
                file=sys.stderr,
            )
            return 1
        result = train(
            vectors, labels, groups, args.out or ctx.settings.paths.models_dir, rounds=args.rounds
        )
    finally:
        ctx.close()
    auc = f"{result.cv_auc:.3f}" if result.cv_auc is not None else "n/a (not enough families)"
    print(
        f"trained on {result.samples} samples ({result.positives} malicious); grouped CV AUC = {auc}"
    )
    print(f"model: {result.model_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
