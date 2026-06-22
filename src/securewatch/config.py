"""Central config — every path and tunable lives here so the team never
hardcodes a path in two places. Import `from securewatch.config import C`.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# Repo root = three parents up from this file (src/securewatch/config.py)
ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Config:
    root: Path = ROOT

    # --- data lake layout ---
    raw: Path = ROOT / "data" / "raw"            # untouched CICIDS 2017 CSVs (gitignored)
    interim: Path = ROOT / "data" / "interim"    # scratch
    processed: Path = ROOT / "data" / "processed"  # THE DATA CONTRACT lives here
    models: Path = ROOT / "models"               # trained .pkl files

    # --- network pipeline knobs ---
    # Keep a sample so the day-of demo loads instantly. Set to None for full data.
    network_sample_rows: int | None = 150_000
    random_seed: int = 42

    # --- synthetic document-log knobs ---
    n_users: int = 60
    n_files: int = 800
    doc_log_days: int = 14
    doc_events_per_day: int = 4_000
    doc_anomaly_rate: float = 0.03  # ~3% injected malicious/insider events

    # --- isolation forest knobs (ML engineer tunes these) ---
    # ~0.08 gives the best F1 on real CICIDS with benign-only (novelty) fitting
    contamination: float = 0.08


C = Config()

# Make sure the directories exist on import (cheap, idempotent).
for _p in (C.raw, C.interim, C.processed, C.models):
    _p.mkdir(parents=True, exist_ok=True)
