"""End-to-end pipeline orchestrator.

    python -m securewatch.pipeline            # full run (needs CICIDS in data/raw)
    python -m securewatch.pipeline --docs-only  # skip network (no download needed)
"""
from __future__ import annotations

import argparse

import pandas as pd

from securewatch.config import C
from securewatch import service


def build_alerts() -> pd.DataFrame:
    """Correlate both layers into one severity-ranked alert feed (delegates to
    securewatch.service so the CLI and the dashboard share identical logic)."""
    net_path = C.processed / "network_scored.parquet"
    doc_path = C.processed / "document_scored.parquet"
    net = pd.read_parquet(net_path) if net_path.exists() else None
    doc = pd.read_parquet(doc_path) if doc_path.exists() else None

    df = service.build_alerts(net, doc)
    out = C.processed / "alerts.parquet"
    df.to_parquet(out, index=False)
    print(f"Built unified alert feed: {len(df):,} alerts -> {out}")
    return df


def run(docs_only: bool = False) -> None:
    from securewatch.ingest import generate_doc_logs
    from securewatch.detect import doc_rules

    print("== Layer 2: document logs ==")
    generate_doc_logs.main()
    doc_rules.main()

    if not docs_only:
        print("\n== Layer 1: network ==")
        from securewatch.preprocess import clean_network
        from securewatch.detect import train_network

        clean_network.main()
        train_network.train_and_score()

    print("\n== Correlate ==")
    build_alerts()
    print("\nDone. Launch the dashboard with:  streamlit run dashboard/app.py")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--docs-only", action="store_true",
                    help="skip the network layer (no CICIDS download needed)")
    args = ap.parse_args()
    run(docs_only=args.docs_only)
