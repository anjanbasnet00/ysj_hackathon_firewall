"""Clean raw CICIDS 2017 into the network_events data contract + ML features.

Handles the dataset's well-known landmines:
  - column names with leading/trailing spaces  (" Flow Duration")
  - Infinity and NaN in Flow Bytes/s & Flow Packets/s
  - duplicate rows
  - the Label column -> binary is_attack
CICIDS flows have no usable timestamp/IP for the ML CSVs, so we synthesise
plausible ones for the timeline + alert feed (clearly a demo simplification).

Produces TWO aligned outputs (same row order):
  - network_events.parquet   : display contract (schemas.NETWORK_EVENT_COLUMNS)
  - network_features.parquet : curated numeric feature matrix for the model

Run:
    python -m securewatch.preprocess.clean_network
"""
from __future__ import annotations

from datetime import datetime, timedelta

import numpy as np
import pandas as pd

from securewatch.config import C
from securewatch.ingest.load_network import load_raw
from securewatch.schemas import NETWORK_EVENT_COLUMNS

# Curated CICIDS features that actually separate attacks (more = worse for
# Isolation Forest due to the curse of dimensionality; these were chosen
# empirically). Names are post-normalisation (lowercase, spaces->_, /->_per_).
FEATURE_COLUMNS = [
    "flow_duration", "total_fwd_packets", "total_backward_packets",
    "total_length_of_fwd_packets", "total_length_of_bwd_packets",
    "flow_bytes_per_s", "flow_packets_per_s", "flo w_iat_mean",
    "fwd_iat_mean", "bwd_iat_mean", "fwd_packet_length_mean",
    "bwd_packet_length_mean", "min_packet_length", "max_packet_length",
    "packet_length_mean", "average_packet_size", "destination_port",
]


def _norm_cols(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = (
        df.columns.str.strip()
        .str.replace(r"\s+", "_", regex=True)
        .str.replace("/", "_per_")
        .str.lower()
    )
    return df


def _pick(df: pd.DataFrame, *candidates: str) -> str | None:
    for c in candidates:
        if c in df.columns:
            return c
    return None


def _prepare(df_raw: pd.DataFrame) -> pd.DataFrame:
    """Normalise columns, kill inf, drop dup rows. Single source of truth so the
    events frame and the feature matrix stay row-aligned."""
    df = _norm_cols(df_raw).replace([np.inf, -np.inf], np.nan)
    return df.drop_duplicates().reset_index(drop=True)


def _feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """Curated numeric features, coerced + median-filled. Raw scale — the model
    pipeline applies log-transform + scaling, so the saved .pkl is self-contained."""
    feats = [c for c in FEATURE_COLUMNS if c in df.columns]
    X = df[feats].apply(pd.to_numeric, errors="coerce")
    return X.fillna(X.median())


def clean_with_features(df_raw: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Raw CICIDS df -> (events display frame, numeric feature matrix), aligned."""
    df = _prepare(df_raw)
    n = len(df)

    label_col = _pick(df, "label")
    dur = _pick(df, "flow_duration")
    fbytes = _pick(df, "flow_bytes_per_s", "flow_bytes_s")
    fpkts = _pick(df, "flow_packets_per_s", "flow_packets_s")
    proto = _pick(df, "protocol")
    for c in (dur, fbytes, fpkts):
        if c:
            df[c] = pd.to_numeric(df[c], errors="coerce")
            df[c] = df[c].fillna(df[c].median())

    # synthesise a 24h timeline for the demo dashboard
    base = datetime.now() - timedelta(hours=24)
    ts = base + pd.to_timedelta(
        np.sort(np.random.default_rng(C.random_seed).uniform(0, 24 * 3600, n)), unit="s"
    )

    if label_col is not None:
        labels = df[label_col].astype(str).str.strip()
        is_attack = (labels.str.upper() != "BENIGN").astype(int)
    else:  # uploaded captures won't be labelled
        labels = pd.Series(["UNKNOWN"] * n)
        is_attack = pd.Series([0] * n)

    events = pd.DataFrame({
        "timestamp": ts,
        "src_ip": [f"172.16.{i % 255}.{(i * 7) % 254 + 1}" for i in range(n)],
        "dst_ip": [f"192.168.{i % 255}.{(i * 13) % 254 + 1}" for i in range(n)],
        "protocol": df[proto].astype(str) if proto else "TCP",
        "flow_duration": df[dur] if dur else 0.0,
        "flow_bytes_s": df[fbytes] if fbytes else 0.0,
        "flow_packets_s": df[fpkts] if fpkts else 0.0,
        "label": labels.values,
        "is_attack": is_attack.values,
    })[NETWORK_EVENT_COLUMNS]

    return events, _feature_matrix(df)


def clean(df_raw: pd.DataFrame) -> pd.DataFrame:
    """Back-compat: just the events display frame."""
    return clean_with_features(df_raw)[0]


def main() -> None:
    raw = load_raw()
    events, features = clean_with_features(raw)
    events.to_parquet(C.processed / "network_events.parquet", index=False)
    features.to_parquet(C.processed / "network_features.parquet", index=False)
    print(f"Wrote {len(events):,} events + {features.shape[1]} features "
          f"-> data/processed/network_{{events,features}}.parquet")
    print(f"  attack rate: {events['is_attack'].mean():.1%}")
    print(events["label"].value_counts().head(10).to_string())


if __name__ == "__main__":
    main()
