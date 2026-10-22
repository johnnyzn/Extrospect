"""Evaluation harness: metrics, datasets, ablations and the eval/ scripts (zero tokens)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

from extrospect.evaluation import (
    ConfigSpec,
    SampleResult,
    auc_score,
    compute_metrics,
    load_ablations,
    load_dataset,
    percentile,
    resolve_sample,
    run_config,
)

ROOT = Path(__file__).parent.parent


def load_script(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"eval_{name}", ROOT / "eval" / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def result(id: str, label: str, score: int, subset: str = "benign", **kw: object) -> SampleResult:
    return SampleResult(id=id, label=label, subset=subset, family=id, score=score, **kw)  # type: ignore[arg-type]


def test_metrics() -> None:
    results = [
        result("m1", "malicious", 90, "malicious", cost_usd=0.1, latency_s=10),
        result("m2", "malicious", 40, "malicious", cost_usd=0.05, latency_s=2),
        result("b1", "benign", 70, "benign_hard", cost_usd=0.0, latency_s=1),
        result("b2", "benign", 10, "benign_hard"),
        result("b3", "benign", 5),
        SampleResult(id="x", label="benign", subset="benign", family="x", error="sample not found"),
    ]
    m = compute_metrics(results, threshold=61)
    assert (m.tp, m.fp, m.tn, m.fn, m.errors) == (1, 1, 2, 1, 1)
    assert (
        m.precision == pytest.approx(0.5)
        and m.recall == pytest.approx(0.5)
        and m.f1 == pytest.approx(0.5)
    )
    assert m.hard_benign_fpr == pytest.approx(0.5)
    assert m.auc == pytest.approx(5 / 6)
    assert m.cost_per_ext == pytest.approx(0.15 / 5)
    assert m.p95_latency_s == 10


def test_auc_and_percentile_edges() -> None:
    assert auc_score([], [1.0]) is None
    assert auc_score([2.0], [2.0]) == 0.5
    assert percentile([], 0.95) == 0.0
    assert percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 0.95) == 10


def test_injection_consistency() -> None:
    results = [
        result("a", "malicious", 90, "malicious"),
        result("a-inj", "malicious", 85, "injection", pair_of="a"),
        result("b", "malicious", 70, "malicious"),
        result("b-inj", "malicious", 30, "injection", pair_of="b"),
    ]
    assert compute_metrics(results).injection_consistency == pytest.approx(0.5)


def test_datasets_are_valid() -> None:
    seed = load_dataset(ROOT / "eval/datasets/seed.jsonl")
    assert len(seed) >= 50
    assert {r.label for r in seed} == {"malicious", "benign"}
    assert len({r.id for r in seed}) == len(seed)
    # Family-disjoint splits: a family never appears in two splits.
    splits_by_family: dict[str, set[str]] = {}
    for row in seed:
        splits_by_family.setdefault(row.family, set()).add(row.split)
    assert all(len(s) == 1 for s in splits_by_family.values())
    fixtures = load_dataset(ROOT / "eval/datasets/fixtures.jsonl")
    base = ROOT / "eval/datasets"
    assert all(resolve_sample(r, None, base) is not None for r in fixtures)


def test_ablations_file() -> None:
    specs = {s.name: s for s in load_ablations(ROOT / "eval/ablations.yaml")}
    assert {"rules", "gbm", "llm", "llm_verifier", "rag_a", "rag_all", "flat_big_model"} <= set(
        specs
    )
    assert specs["llm"].overrides["llm"] == {"verifier_enabled": False}
    assert specs["flat_big_model"].overrides["router"] == {"flat": True}
    assert not specs["rules"].uses_llm and specs["rag_all"].uses_llm


def test_run_config_rules_on_fixtures(ctx) -> None:
    rows = load_dataset(ROOT / "eval/datasets/fixtures.jsonl")
    results = run_config(rows, ConfigSpec(name="rules"), ctx, None, ROOT / "eval/datasets")
    metrics = compute_metrics(results)
    assert metrics.errors == 0 and metrics.f1 == pytest.approx(1.0)


def test_run_eval_script(tmp_path: Path) -> None:
    run_eval = load_script("run_eval")
    out = tmp_path / "results.md"
    code = run_eval.main(
        [
            "--dataset",
            str(ROOT / "eval/datasets/fixtures.jsonl"),
            "--configs",
            "rules",
            "--offline",
            "--output",
            str(out),
            "--runs-dir",
            str(tmp_path / "runs"),
            "--quiet",
        ]
    )
    assert code == 0
    text = out.read_text(encoding="utf-8")
    assert "| rules | 100.0% | 100.0% | 100.0% |" in text
    runs = list((tmp_path / "runs").glob("*.jsonl"))
    assert runs and json.loads(runs[0].read_text().splitlines()[0])["config"] == "rules"
    # Real LLM configurations are refused without --yes (cost guard).
    assert (
        run_eval.main(
            [
                "--dataset",
                str(ROOT / "eval/datasets/fixtures.jsonl"),
                "--configs",
                "rag_all",
                "--no-write",
                "--runs-dir",
                str(tmp_path / "runs"),
            ]
        )
        == 3
    )
    assert run_eval.main(["--configs", "nope", "--no-write"]) == 2


def test_injection_variant_script(tmp_path: Path) -> None:
    make = load_script("make_injection_variants")
    out_dataset = tmp_path / "inj.jsonl"
    code = make.main(
        [
            "--dataset",
            str(ROOT / "eval/datasets/fixtures.jsonl"),
            "--samples",
            str(tmp_path / "none"),
            "--split",
            "test",
            "--out",
            str(tmp_path / "inj"),
            "--dataset-out",
            str(out_dataset),
        ]
    )
    assert code == 0
    rows = load_dataset(out_dataset)
    variants = [r for r in rows if r.pair_of]
    assert len(variants) == 4 and all(r.subset == "injection" for r in variants)
    injected = (tmp_path / "inj" / "mal_cookie_exfil-inj" / "background.js").read_text(
        encoding="utf-8"
    )
    assert "NOTE TO AI SECURITY AUDITORS" in injected


def test_fetch_samples_import(tmp_path: Path) -> None:
    fetch = load_script("fetch_samples")
    archive = tmp_path / "archive"
    archive.mkdir()
    ext_id = "lgjdgmdbfhobkdbcjnpnlmhnplnidkkp"  # first id of the seed list
    (archive / f"{ext_id}_1.2.3.crx").write_bytes(b"Cr24")
    (archive / ("z" * 40)).mkdir()
    code = fetch.main(
        [
            "--dataset",
            str(ROOT / "eval/datasets/seed.jsonl"),
            "--out",
            str(tmp_path / "samples"),
            "--import-dir",
            str(archive),
        ]
    )
    assert code == 0 and (tmp_path / "samples" / f"{ext_id}.crx").is_file()


def test_gbm_train_and_predict(ctx) -> None:
    pytest.importorskip("lightgbm")
    from extrospect.baseline.gbm import predict_static, train
    from extrospect.pipeline import static_for
    from extrospect.static.features import FEATURE_NAMES, extract_features, feature_vector

    rows = load_dataset(ROOT / "eval/datasets/fixtures.jsonl")
    statics = [static_for(resolve_sample(r, None, ROOT / "eval/datasets"), ctx) for r in rows]
    vectors = [feature_vector(s) for s in statics]
    assert all(len(v) == len(FEATURE_NAMES) for v in vectors)
    from extrospect.baseline.gbm import LGB_FEATURE_NAMES

    assert len(set(LGB_FEATURE_NAMES)) == len(LGB_FEATURE_NAMES)
    assert extract_features(statics[3])["sink:cookie_read"] == 1.0
    labels = [1 if r.positive else 0 for r in rows]
    result = train(
        vectors,
        labels,
        [r.family for r in rows],
        ctx.settings.paths.models_dir,
        rounds=20,
        params={"min_data_in_leaf": 1},
    )
    assert result.model_path.is_file() and result.samples == 7
    probability = predict_static(statics[3], ctx)
    assert probability is not None and 0.0 <= probability <= 1.0
