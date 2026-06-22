"""End-to-end pipeline orchestrator (network layer).

    python -m securewatch.pipeline    # clean + train + score real CICIDS, build alerts

The document layer is now a LIVE Google Drive feed handled inside the dashboard
(see securewatch.ingest.gdrive + the dashboard's "Live Drive" tab), so it is no
longer part of this batch run.
"""
from __future__ import annotations

import pandas as pd

from securewatch.config import C
from securewatch import service


def build_alerts() -> pd.DataFrame:
    """Build the severity-ranked alert feed from the scored network layer
    (delegates to securewatch.service so the CLI and dashboard share logic).
    If a live Drive session has written document_scored.parquet, it's folded in."""
    net_path = C.processed / "network_scored.parquet"
    doc_path = C.processed / "document_scored.parquet"
    net = pd.read_parquet(net_path) if net_path.exists() else None
    doc = pd.read_parquet(doc_path) if doc_path.exists() else None

    df = service.build_alerts(net, doc)
    out = C.processed / "alerts.parquet"
    df.to_parquet(out, index=False)
    print(f"Built unified alert feed: {len(df):,} alerts -> {out}")
    return df


def run() -> None:
    print("== Network layer (CICIDS 2017) ==")
    from securewatch.preprocess import clean_network
    from securewatch.detect import train_network

    clean_network.main()
    train_network.train_and_score()

    print("\n== Correlate ==")
    build_alerts()
    print("\nDone. Launch the dashboard with:  streamlit run dashboard/app.py")


if __name__ == "__main__":
    run()
