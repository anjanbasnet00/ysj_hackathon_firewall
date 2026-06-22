"""Shared analysis service — the single entry point for BOTH the CLI pipeline
and the dashboard's upload feature.

The whole point: a CSV uploaded in the browser and a CSV sitting in data/raw/
go through the EXACT same code here. The UI just hands us a DataFrame.

    from securewatch import service
    scored = service.analyze_network_csv(uploaded_file)   # Streamlit UploadedFile or path
    scored = service.analyze_document_csv(uploaded_file)
    alerts = service.build_alerts(net_scored, doc_scored)
"""
from __future__ import annotations

from typing import IO

import joblib
import pandas as pd

from securewatch.config import C
from securewatch.detect import doc_rules, train_network
from securewatch.preprocess.clean_network import clean_with_features
from securewatch.schemas import ALERT_COLUMNS, DOC_EVENT_COLUMNS


def _read_csv(src: str | IO) -> pd.DataFrame:
    """Accepts a file path, a file-like object, or a Streamlit UploadedFile."""
    return pd.read_csv(src, low_memory=False, encoding="latin-1")


# ---------------------------------------------------------------------------
# Layer 1 — network
# ---------------------------------------------------------------------------
def analyze_network_csv(src: str | IO, use_saved_model: bool = True) -> pd.DataFrame:
    """Raw network CSV (CICIDS-format) -> cleaned + Isolation-Forest-scored df."""
    raw = _read_csv(src)
    events, features = clean_with_features(raw)

    model = None
    model_path = C.models / "isolation_forest.pkl"
    if use_saved_model and model_path.exists():
        # Safe: this .pkl is produced locally by our own train_network.py and is
        # gitignored — never an external/untrusted artifact.
        try:
            model = joblib.load(model_path)
        except Exception:
            model = None  # fall back to fitting fresh on the uploaded data
    return train_network.fit_score(events, features, model=model,
                                   contamination=C.contamination)


# ---------------------------------------------------------------------------
# Layer 2 — documents
# ---------------------------------------------------------------------------
def analyze_document_csv(src: str | IO) -> pd.DataFrame:
    """Document-access CSV -> behaviourally scored df."""
    df = _read_csv(src)
    # be forgiving about missing optional columns
    if "timestamp" in df:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    if "hour" not in df and "timestamp" in df:
        df["hour"] = df["timestamp"].dt.hour
    missing = [c for c in ("user_id", "file_path", "department", "file_sensitivity",
                           "action", "bytes", "hour") if c not in df]
    if missing:
        raise ValueError(f"Document CSV missing required columns: {missing}\n"
                         f"Expected columns: {DOC_EVENT_COLUMNS}")
    return doc_rules.score(df)


# ---------------------------------------------------------------------------
# Correlation — works on in-memory frames (for upload) or None (skip a layer)
# ---------------------------------------------------------------------------
def build_alerts(net_scored: pd.DataFrame | None = None,
                 doc_scored: pd.DataFrame | None = None) -> pd.DataFrame:
    alerts: list[dict] = []

    if net_scored is not None and len(net_scored):
        for _, r in net_scored[net_scored["is_anomaly"] == 1].iterrows():
            lbl = str(r["label"]).upper()
            kind = "" if lbl in ("BENIGN", "UNKNOWN") else f" ({r['label']})"
            alerts.append({
                "timestamp": r["timestamp"], "layer": "network",
                "severity": r["severity"], "entity": r["src_ip"],
                "summary": f"Anomalous network flow from {r['src_ip']}{kind}",
                "score": float(-r["anomaly_score"]),
            })

    if doc_scored is not None and len(doc_scored):
        for _, r in doc_scored[doc_scored["is_flagged"] == 1].iterrows():
            name = r.get("user_name", r["user_id"])
            alerts.append({
                "timestamp": r["timestamp"], "layer": "document",
                "severity": r["severity"], "entity": r["user_id"],
                "summary": f"{name} — {r['reason']} ({r['file_path']})",
                "score": float(r["risk_score"]),
            })

    df = pd.DataFrame(alerts, columns=ALERT_COLUMNS)
    if len(df):
        df = df.sort_values("timestamp").reset_index(drop=True)
    return df
