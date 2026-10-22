"""Run the ablation study and write docs/eval_results.md.

Examples (zero tokens):
    uv run python eval/run_eval.py --dataset eval/datasets/fixtures.jsonl --configs rules
    uv run python eval/run_eval.py --dataset eval/datasets/fixtures.jsonl --configs rules,rag_all --fake-llm

Real LLM configurations spend API credits; they only run with --yes after a cost estimate.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from extrospect.config import load_settings
from extrospect.evaluation import (
    DEFAULT_THRESHOLD,
    ConfigSpec,
    Metrics,
    compute_metrics,
    load_ablations,
    load_dataset,
    results_table,
    run_config,
    write_results,
)
from extrospect.i18n import set_language
from extrospect.models import utcnow

ROOT = Path(__file__).resolve().parent.parent
EST_COST_PER_EXTENSION = 0.08  # roadmap target for Sonnet-class investigators


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--dataset", type=Path, default=ROOT / "eval/datasets/fixtures.jsonl")
    parser.add_argument(
        "--samples",
        type=Path,
        default=ROOT / "eval/samples",
        help="Directory with downloaded samples.",
    )
    parser.add_argument("--ablations", type=Path, default=ROOT / "eval/ablations.yaml")
    parser.add_argument(
        "--configs", default="rules", help="Comma-separated config names, or 'all'."
    )
    parser.add_argument("--split", default="all", help="train / dev / test / all")
    parser.add_argument(
        "--limit", type=int, default=0, help="Evaluate at most N samples (0 = all)."
    )
    parser.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD)
    parser.add_argument("--output", type=Path, default=ROOT / "docs/eval_results.md")
    parser.add_argument(
        "--no-write", action="store_true", help="Do not write the results markdown."
    )
    parser.add_argument(
        "--runs-dir", type=Path, default=ROOT / "eval/runs", help="Per-sample JSONL output."
    )
    parser.add_argument("--offline", action="store_true")
    parser.add_argument(
        "--fake-llm",
        action="store_true",
        help="Use the heuristic fake model (dry run, zero tokens).",
    )
    parser.add_argument(
        "--yes", action="store_true", help="Confirm that real LLM configurations may spend credits."
    )
    parser.add_argument("--lang", default="en")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument(
        "--note", action="append", default=[], help="Extra note for the results file (repeatable)."
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    set_language(args.lang)
    rows = load_dataset(args.dataset)
    if args.split != "all":
        rows = [r for r in rows if r.split == args.split]
    if args.limit:
        rows = rows[: args.limit]
    specs = load_ablations(args.ablations)
    if args.configs != "all":
        wanted = [c.strip() for c in args.configs.split(",") if c.strip()]
        unknown = set(wanted) - {s.name for s in specs}
        if unknown:
            print(f"unknown configs: {', '.join(sorted(unknown))}", file=sys.stderr)
            return 2
        specs = [s for s in specs if s.name in wanted]
    llm_specs = [s for s in specs if s.uses_llm]
    if llm_specs and not args.fake_llm and not args.yes:
        estimate = len(rows) * len(llm_specs) * EST_COST_PER_EXTENSION
        print(
            f"{len(llm_specs)} configuration(s) call real LLMs on {len(rows)} sample(s): "
            f"roughly ${estimate:.2f} at ${EST_COST_PER_EXTENSION}/extension. Re-run with --yes to proceed, "
            "or with --fake-llm for a zero-token dry run.",
            file=sys.stderr,
        )
        return 3

    overrides: dict = {}
    if args.offline:
        overrides["network"] = {"offline": True}
    from extrospect.pipeline import Context

    ctx = Context.create(settings=load_settings(overrides=overrides), language=args.lang)
    llm = None
    if args.fake_llm:
        from extrospect.llm.fake import HeuristicBackend

        llm = HeuristicBackend()

    def progress(config: str, sample: str, result: object) -> None:
        if not args.quiet:
            score = getattr(result, "score", None)
            error = getattr(result, "error", None)
            print(f"  [{config}] {sample}: {error or score}", file=sys.stderr)

    table: list[tuple[ConfigSpec, Metrics]] = []
    args.runs_dir.mkdir(parents=True, exist_ok=True)
    run_file = args.runs_dir / f"{utcnow().strftime('%Y%m%d-%H%M%S')}.jsonl"
    try:
        for spec in specs:
            if not args.quiet:
                print(f"== {spec.name}: {spec.description}", file=sys.stderr)
            results = run_config(
                rows,
                spec,
                ctx,
                args.samples,
                args.dataset.parent,
                llm=llm if spec.uses_llm else None,
                progress=progress,
            )
            with run_file.open("a", encoding="utf-8") as fh:
                for result in results:
                    fh.write(
                        json.dumps({"config": spec.name, **asdict(result)}, ensure_ascii=False)
                        + "\n"
                    )
            table.append((spec, compute_metrics(results, args.threshold)))
    finally:
        ctx.close()

    print(results_table(table))
    notes = list(args.note)
    if args.fake_llm and llm_specs:
        notes.append(
            "LLM rows were produced with the heuristic fake model (--fake-llm): plumbing check only, not real results."
        )
    missing = sum(m.errors for _, m in table)
    if missing:
        notes.append(
            f"{missing} sample evaluation(s) failed or were missing (see {run_file.relative_to(ROOT) if run_file.is_relative_to(ROOT) else run_file})."
        )
    if not args.no_write:
        dataset_name = (
            str(args.dataset.relative_to(ROOT))
            if args.dataset.is_relative_to(ROOT)
            else str(args.dataset)
        )
        write_results(
            args.output,
            dataset_name,
            table,
            args.threshold,
            None if args.split == "all" else args.split,
            notes,
        )
        print(f"written {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
