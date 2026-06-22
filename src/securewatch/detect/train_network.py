"""Isolation Forest training + scoring for network events (Layer 1).

OWNER: Member 1 (ML Engineer). Key design choices (these are what make it work
on REAL CICIDS data instead of scoring ~0.01 F1):

  1. Curated features (preprocess.FEATURE_COLUMNS), not all 79 — Isolation
     Forest degrades with noisy/redundant features.
  2. A pipeline: signed-log transform -> StandardScaler -> IsolationForest, so
     heavy-tailed, wildly-scaled flow stats become comparable.
  3. NOVELTY DETECTION: fit on BENIGN traffic only ("learn normal, flag the
     rest") — exactly the brief's narrative. Falls back to fitting on all data
     when labels are absent (e.g. an unlabelled uploaded capture).
  4. Severity banded WITHIN the flagged set (raw anomaly-score extremes are
     benign outliers, so global-rank banding would be misleading).

Run:
    python -m securewatch.detect.train_network
Outputs: models/isolation_forest.pkl, data/processed/network_scored.parquet
"""
from __future__ import annotations

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler


def _signed_log1p(X):
    """Module-level (picklable) heavy-tail squasher: sign(x)*log1p(|x|)."""
    return np.sign(X) * np.log1p(np.abs(X))


def build_pipeline(contamination: float) -> Pipeline:
    return Pipeline([
        ("log", FunctionTransformer(_signed_log1p)),
        ("scale", StandardScaler()),
        ("iforest", IsolationForest(
            n_estimators=300, contamination=contamination,
            random_state=42, n_jobs=-1)),
    ])


def _severity(score: np.ndarray, is_anomaly: np.ndarray) -> np.ndarray:
    """Unflagged -> LOW. Flagged -> band by score rank WITHIN the flagged set
    (lower score = more anomalous = more severe)."""
    out = np.full(len(score), "LOW", dtype=object)
    flagged = is_anomaly == 1
    if flagged.any():
        r = pd.Series(score[flagged]).rank(pct=True).to_numpy()  # 0 = worst
        band = np.where(r < 0.20, "CRITICAL", np.where(r < 0.50, "HIGH", "MEDIUM"))
        out[flagged] = band
    return out


def fit_score(events: pd.DataFrame, features: pd.DataFrame,
              model: Pipeline | None = None, save_model: bool = False,
              contamination: float = 0.08) -> pd.DataFrame:
    """Score network events. Trains a fresh pipeline if none supplied.

    If `events` carries ground-truth `is_attack`, we fit on benign rows only
    (novelty detection). Otherwise we fit on everything (pure unsupervised).
    """
    events = events.reset_index(drop=True)
    X = features.reset_index(drop=True)

    if model is None:
        model = build_pipeline(contamination)
        if "is_attack" in events and events["is_attack"].nunique() > 1:
            benign = events["is_attack"] == 0
            model.fit(X[benign])
        else:
            model.fit(X)
        if save_model:
            joblib.dump(model, _model_path())

    events["anomaly_score"] = model.decision_function(X)
    events["is_anomaly"] = (model.predict(X) == -1).astype(int)
    events["severity"] = _severity(events["anomaly_score"].to_numpy(),
                                   events["is_anomaly"].to_numpy())
    return events


def _model_path():
    from securewatch.config import C
    return C.models / "isolation_forest.pkl"


def train_and_score() -> pd.DataFrame:
    from securewatch.config import C

    events = pd.read_parquet(C.processed / "network_events.parquet")
    features = pd.read_parquet(C.processed / "network_features.parquet")
    df = fit_score(events, features, model=None, save_model=True,
                   contamination=C.contamination)

    df.to_parquet(C.processed / "network_scored.parquet", index=False)
    print(f"Trained IsolationForest on {features.shape[1]} features, "
          f"saved model + {len(df):,} scored rows")

    if "is_attack" in df and df["is_attack"].nunique() > 1:
        from sklearn.metrics import precision_score, recall_score, f1_score
        y, yhat = df["is_attack"], df["is_anomaly"]
        print(f"  precision={precision_score(y, yhat, zero_division=0):.3f} "
              f"recall={recall_score(y, yhat, zero_division=0):.3f} "
              f"f1={f1_score(y, yhat, zero_division=0):.3f}")
        print(df["severity"].value_counts().to_string())
    return df


if __name__ == "__main__":
    train_and_score()
