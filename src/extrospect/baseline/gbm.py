"""LightGBM baseline (roadmap M2), written from scratch on public data only.

Training uses grouped cross-validation (groups = malware family / source) so samples of
one family never sit on both sides of a split. The trained model is stored under
``<data_dir>/models/gbm.txt`` with its feature list; ``predict_static`` returns ``None``
when no model exists (the rule baseline is used instead).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from extrospect.static.features import FEATURE_NAMES, feature_vector

if TYPE_CHECKING:
    from extrospect.pipeline import Context
    from extrospect.static.analyzer import StaticResult

MODEL_FILE = "gbm.txt"
META_FILE = "gbm.meta.json"
DEFAULT_PARAMS: dict[str, Any] = {
    "objective": "binary",
    "learning_rate": 0.05,
    "num_leaves": 15,
    "min_data_in_leaf": 5,
    "feature_fraction": 0.8,
    "bagging_fraction": 0.8,
    "bagging_freq": 1,
    "lambda_l2": 1.0,
    "verbose": -1,
    "seed": 13,
}


@dataclass
class TrainResult:
    model_path: Path
    cv_auc: float | None
    cv_scores: list[float] = field(default_factory=list)
    samples: int = 0
    positives: int = 0


def model_dir(ctx: Context) -> Path:
    return ctx.settings.paths.models_dir


def train(
    rows: list[list[float]],
    labels: list[int],
    groups: list[str],
    out_dir: Path,
    params: dict[str, Any] | None = None,
    folds: int = 5,
    rounds: int = 300,
) -> TrainResult:
    import lightgbm as lgb
    import numpy as np

    x = np.asarray(rows, dtype="float64")
    y = np.asarray(labels, dtype="int32")
    params = {**DEFAULT_PARAMS, **(params or {})}
    scores: list[float] = []
    unique_groups = sorted(set(groups))
    if len(unique_groups) >= 2 and len(set(labels)) == 2:
        from sklearn.metrics import roc_auc_score
        from sklearn.model_selection import GroupKFold

        splitter = GroupKFold(n_splits=min(folds, len(unique_groups)))
        for train_idx, test_idx in splitter.split(x, y, groups):
            if len(set(y[train_idx])) < 2 or len(set(y[test_idx])) < 2:
                continue
            booster = lgb.train(
                params, lgb.Dataset(x[train_idx], y[train_idx], feature_name=FEATURE_NAMES), rounds
            )
            scores.append(float(roc_auc_score(y[test_idx], booster.predict(x[test_idx]))))
    booster = lgb.train(params, lgb.Dataset(x, y, feature_name=FEATURE_NAMES), rounds)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / MODEL_FILE
    booster.save_model(str(path))
    (out_dir / META_FILE).write_text(
        json.dumps(
            {
                "features": FEATURE_NAMES,
                "cv_auc": scores,
                "samples": len(labels),
                "positives": int(sum(labels)),
            }
        ),
        encoding="utf-8",
    )
    return TrainResult(
        model_path=path,
        cv_auc=sum(scores) / len(scores) if scores else None,
        cv_scores=scores,
        samples=len(labels),
        positives=int(sum(labels)),
    )


_MODELS: dict[str, Any] = {}


def load_model(directory: Path) -> Any | None:
    path = directory / MODEL_FILE
    meta_path = directory / META_FILE
    if not path.is_file() or not meta_path.is_file():
        return None
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    if meta.get("features") != FEATURE_NAMES:
        return None  # feature set changed: model must be retrained
    key = f"{path}:{path.stat().st_mtime}"
    if key not in _MODELS:
        import lightgbm as lgb

        _MODELS[key] = lgb.Booster(model_file=str(path))
    return _MODELS[key]


def predict_static(static: StaticResult, ctx: Context) -> float | None:
    try:
        model = load_model(model_dir(ctx))
    except ImportError:
        return None
    if model is None:
        return None
    return float(model.predict([feature_vector(static)])[0])


__all__ = ["DEFAULT_PARAMS", "TrainResult", "load_model", "predict_static", "train"]
