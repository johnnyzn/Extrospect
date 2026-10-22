"""Evaluation harness behind ``eval/run_eval.py`` (roadmap M2 + section 9).

* datasets are JSONL manifests (id, label, subset, family, split, source...) - samples
  themselves are never committed;
* configurations come from ``eval/ablations.yaml`` and map to settings overrides;
* metrics: precision, recall, F1, AUC, FPR on hard benign extensions, $/extension,
  P95 latency, plus prompt-injection consistency;
* results are written to ``docs/eval_results.md``.
"""

from __future__ import annotations

import json
import math
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from extrospect.pipeline import Context

DEFAULT_THRESHOLD = 61  # level "high" or above counts as a positive (malicious) prediction


class DatasetRow(BaseModel):
    id: str
    label: str  # malicious / benign
    subset: str = "benign"
    family: str = "unknown"
    split: str = "test"
    name: str | None = None
    version: str | None = None
    sha256: str | None = None
    source: str | None = None
    source_url: str | None = None
    notes: str | None = None
    path: str | None = None
    pair_of: str | None = None  # injection variants point at their clean sample

    @property
    def positive(self) -> bool:
        return self.label == "malicious"


def load_dataset(path: Path) -> list[DatasetRow]:
    rows: list[DatasetRow] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        try:
            rows.append(DatasetRow.model_validate(json.loads(text)))
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"{path}:{number}: {exc}") from exc
    return rows


def resolve_sample(row: DatasetRow, samples_dir: Path | None, base_dir: Path) -> Path | None:
    """Find the sample on disk: explicit path, <samples>/<id>[/], <samples>/<id>.crx|.zip."""
    if row.path:
        candidate = Path(row.path)
        if not candidate.is_absolute():
            candidate = (base_dir / candidate).resolve()
        return candidate if candidate.exists() else None
    if samples_dir is None:
        return None
    for candidate in (
        samples_dir / row.id,
        samples_dir / f"{row.id}.crx",
        samples_dir / f"{row.id}.zip",
        samples_dir / row.id / (row.version or ""),
    ):
        if candidate.is_dir() and (candidate / "manifest.json").is_file():
            return candidate
        if candidate.is_file():
            return candidate
    matches = sorted(samples_dir.glob(f"{row.id}_*.crx"))
    return matches[-1] if matches else None


class ConfigSpec(BaseModel):
    name: str
    mode: str = "rules"  # rules / gbm / engine
    description: str = ""
    overrides: dict[str, Any] = Field(default_factory=dict)
    uses_llm: bool = False


def load_ablations(path: Path) -> list[ConfigSpec]:
    import yaml

    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    configs: dict[str, Any] = data.get("configs", data) or {}
    return [
        ConfigSpec.model_validate({"name": name, **(spec or {})}) for name, spec in configs.items()
    ]


@dataclass
class SampleResult:
    id: str
    label: str
    subset: str
    family: str
    score: int | None = None
    level: str | None = None
    verdict: str | None = None
    cost_usd: float = 0.0
    latency_s: float = 0.0
    error: str | None = None
    pair_of: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.score is not None


@dataclass
class Metrics:
    n: int = 0
    errors: int = 0
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    precision: float | None = None
    recall: float | None = None
    f1: float | None = None
    fpr: float | None = None
    hard_benign_fpr: float | None = None
    auc: float | None = None
    cost_per_ext: float = 0.0
    p95_latency_s: float = 0.0
    injection_consistency: float | None = None
    extra: dict[str, Any] = field(default_factory=dict)


def _ratio(num: int, den: int) -> float | None:
    return num / den if den else None


def auc_score(positives: list[float], negatives: list[float]) -> float | None:
    """Mann-Whitney U based ROC AUC (ties count half)."""
    if not positives or not negatives:
        return None
    wins = 0.0
    for p in positives:
        for n in negatives:
            wins += 1.0 if p > n else 0.5 if p == n else 0.0
    return wins / (len(positives) * len(negatives))


def percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(q * len(ordered)) - 1))
    return ordered[index]


def compute_metrics(results: Iterable[SampleResult], threshold: int = DEFAULT_THRESHOLD) -> Metrics:
    results = list(results)
    metrics = Metrics(n=len(results))
    ok = [r for r in results if r.ok]
    metrics.errors = len(results) - len(ok)
    hard_negatives = hard_fp = 0
    for r in ok:
        predicted = (r.score or 0) >= threshold
        actual = r.label == "malicious"
        if predicted and actual:
            metrics.tp += 1
        elif predicted and not actual:
            metrics.fp += 1
        elif actual:
            metrics.fn += 1
        else:
            metrics.tn += 1
        if r.subset == "benign_hard":
            hard_negatives += 1
            hard_fp += int(predicted)
    metrics.precision = _ratio(metrics.tp, metrics.tp + metrics.fp)
    metrics.recall = _ratio(metrics.tp, metrics.tp + metrics.fn)
    if (
        metrics.precision is not None
        and metrics.recall is not None
        and (metrics.precision + metrics.recall)
    ):
        metrics.f1 = 2 * metrics.precision * metrics.recall / (metrics.precision + metrics.recall)
    metrics.fpr = _ratio(metrics.fp, metrics.fp + metrics.tn)
    metrics.hard_benign_fpr = _ratio(hard_fp, hard_negatives)
    metrics.auc = auc_score(
        [float(r.score or 0) for r in ok if r.label == "malicious"],
        [float(r.score or 0) for r in ok if r.label != "malicious"],
    )
    metrics.cost_per_ext = sum(r.cost_usd for r in ok) / len(ok) if ok else 0.0
    metrics.p95_latency_s = percentile([r.latency_s for r in ok], 0.95)
    metrics.injection_consistency = injection_consistency(ok, threshold)
    return metrics


def injection_consistency(
    results: list[SampleResult], threshold: int = DEFAULT_THRESHOLD
) -> float | None:
    """Share of injection variants whose decision equals their clean sample's decision."""
    by_id = {r.id: r for r in results}
    pairs = [(r, by_id[r.pair_of]) for r in results if r.pair_of and r.pair_of in by_id]
    if not pairs:
        return None
    same = sum(
        1 for a, b in pairs if ((a.score or 0) >= threshold) == ((b.score or 0) >= threshold)
    )
    return same / len(pairs)


# --------------------------------------------------------------------------- running


def apply_overrides(ctx: Context, overrides: dict[str, Any]) -> Context:
    """A Context copy whose settings include ``overrides`` (deep-merged)."""
    from extrospect.config import Settings
    from extrospect.pipeline import Context as ContextCls

    data = ctx.settings.model_dump()

    def merge(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
        for key, value in extra.items():
            if isinstance(value, dict) and isinstance(base.get(key), dict):
                merge(base[key], value)
            else:
                base[key] = value
        return base

    settings = Settings.model_validate(merge(data, overrides))
    return ContextCls(
        settings=settings, cache=ctx.cache, http=ctx.http, tools=ctx.tools, language=ctx.language
    )


def evaluate_sample(
    row: DatasetRow, sample: Path, spec: ConfigSpec, ctx: Context, llm: Any = None
) -> SampleResult:
    from extrospect.pipeline import analyze, build_report, static_for

    result = SampleResult(
        id=row.id, label=row.label, subset=row.subset, family=row.family, pair_of=row.pair_of
    )
    started = time.perf_counter()
    try:
        if spec.mode == "engine":
            report = analyze(sample, ctx, allow_download=False, use_cache=False, llm=llm)
        else:
            static = static_for(sample, ctx, allow_download=False)
            gbm_prob = None
            if spec.mode == "gbm":
                from extrospect.baseline.gbm import predict_static

                gbm_prob = predict_static(static, ctx)
                if gbm_prob is None:
                    raise RuntimeError("no trained GBM model - run eval/train_gbm.py first")
            report = build_report(static, ctx, mode="static", gbm_prob=gbm_prob)
        result.score = report.score
        result.level = report.level
        result.verdict = report.verdict.label if report.verdict else None
        result.cost_usd = report.cost_usd
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {str(exc)[:200]}"
    result.latency_s = time.perf_counter() - started
    return result


def run_config(
    rows: list[DatasetRow],
    spec: ConfigSpec,
    ctx: Context,
    samples_dir: Path | None,
    base_dir: Path,
    llm: Any = None,
    progress: Any = None,
) -> list[SampleResult]:
    configured = apply_overrides(ctx, spec.overrides)
    results: list[SampleResult] = []
    for row in rows:
        sample = resolve_sample(row, samples_dir, base_dir)
        if sample is None:
            results.append(
                SampleResult(
                    id=row.id,
                    label=row.label,
                    subset=row.subset,
                    family=row.family,
                    error="sample not found",
                    pair_of=row.pair_of,
                )
            )
        else:
            results.append(evaluate_sample(row, sample, spec, configured, llm))
        if progress is not None:
            progress(spec.name, row.id, results[-1])
    return results


# --------------------------------------------------------------------------- reporting


def _fmt(value: float | None, pct: bool = True) -> str:
    if value is None:
        return "-"
    return f"{value * 100:.1f}%" if pct else f"{value:.3f}"


def results_table(rows: list[tuple[ConfigSpec, Metrics]]) -> str:
    lines = [
        "| Config | Precision | Recall | F1 | Hard-benign FPR | AUC | $/ext | P95 latency | n (errors) |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for spec, m in rows:
        lines.append(
            f"| {spec.name} | {_fmt(m.precision)} | {_fmt(m.recall)} | {_fmt(m.f1)} | {_fmt(m.hard_benign_fpr)} | "
            f"{_fmt(m.auc, pct=False)} | ${m.cost_per_ext:.4f} | {m.p95_latency_s:.1f}s | {m.n} ({m.errors}) |"
        )
    return "\n".join(lines)


def write_results(
    path: Path,
    dataset: str,
    rows: list[tuple[ConfigSpec, Metrics]],
    threshold: int,
    split: str | None,
    notes: list[str] | None = None,
) -> None:
    from extrospect.config import PIPELINE_VERSION
    from extrospect.models import utcnow

    lines = [
        "# Evaluation results",
        "",
        "> Generated by `eval/run_eval.py` - do not edit by hand.",
        "",
        f"- Dataset: `{dataset}`" + (f" (split: {split})" if split else ""),
        f"- Decision threshold: score >= {threshold} (level high or critical) counts as malicious",
        f"- Pipeline: {PIPELINE_VERSION}",
        f"- Generated: {utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        results_table(rows),
        "",
        "Column notes: *Hard-benign FPR* is the false-positive rate on deep-integration benign extensions "
        "(password managers, translators, ad blockers, AI sidebars...). *$/ext* is the mean LLM cost per extension.",
    ]
    consistency = [
        (spec.name, m.injection_consistency)
        for spec, m in rows
        if m.injection_consistency is not None
    ]
    if consistency:
        lines += ["", "Prompt-injection consistency (decision unchanged by injected comments):", ""]
        lines += [f"- {name}: {value * 100:.1f}%" for name, value in consistency]
    if notes:
        lines += ["", *[f"- {n}" for n in notes]]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


__all__ = [
    "DEFAULT_THRESHOLD",
    "ConfigSpec",
    "DatasetRow",
    "Metrics",
    "SampleResult",
    "apply_overrides",
    "auc_score",
    "compute_metrics",
    "evaluate_sample",
    "injection_consistency",
    "load_ablations",
    "load_dataset",
    "percentile",
    "resolve_sample",
    "results_table",
    "run_config",
    "write_results",
]
