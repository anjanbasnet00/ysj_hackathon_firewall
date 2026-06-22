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

    # --- live Google Drive document layer ---
    # The document layer is now a LIVE feed of real Google Drive activity
    # (no synthetic data). These knobs make behavioural rules fire reliably
    # from a human acting on stage during the demo.
    live_poll_seconds: int = 5          # how often the dashboard polls Drive
    live_lookback_days: int = 7         # on connect, seed the scan with this much recent history
    live_bulk_threshold: int = 5        # N actions by a user within the window -> bulk burst
    live_bulk_window: str = "2min"      # short window so a quick burst trips it
    live_large_bytes: int = 10_000_000  # > 10 MB in one event -> "large transfer"

    # --- isolation forest knobs (ML engineer tunes these) ---
    # ~0.08 gives the best F1 on real CICIDS with benign-only (novelty) fitting
    contamination: float = 0.08

    # --- local LLM (LM Studio, OpenAI-compatible) for the RAG assistant ---
    # Runs fully offline on the analyst's machine — no alert data leaves the box.
    lm_base_url: str = "http://127.0.0.1:1234"
    lm_model: str = "qwen2.5-coder-7b-instruct-mlx"
    lm_max_context_alerts: int = 14     # how many retrieved alerts to stuff in the prompt
    lm_timeout_s: int = 120


C = Config()

# Make sure the directories exist on import (cheap, idempotent).
for _p in (C.raw, C.interim, C.processed, C.models):
    _p.mkdir(parents=True, exist_ok=True)
