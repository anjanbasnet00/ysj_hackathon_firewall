"""Generate a realistic CICIDS-2017-SHAPED sample CSV for development/demo.

This is NOT the real dataset — it's a stand-in that mimics the real file's
structure so the exact same cleaning/scoring code runs. It deliberately
reproduces CICIDS quirks: column names with leading spaces, Infinity/NaN in
the rate columns, and a ' Label' column with BENIGN + attack classes.

Swap in the real CICIDS CSVs (data/raw/) whenever you download them — the
pipeline treats both identically.

Run:  python scripts/make_sample_cicids.py
Out:  data/raw/sample_cicids2017.csv
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from securewatch.config import C  # noqa: E402

rng = np.random.default_rng(C.random_seed)
N = 40_000
ATTACK_RATE = 0.18
ATTACKS = ["DDoS", "PortScan", "Bot", "FTP-Patator", "DoS Hulk", "Web Attack"]


def make() -> pd.DataFrame:
    n_attack = int(N * ATTACK_RATE)
    n_benign = N - n_attack

    # benign: moderate, tight distributions
    benign = {
        "flow_duration": rng.gamma(2.0, 50_000, n_benign),
        "flow_bytes_s": rng.gamma(2.0, 3_000, n_benign),
        "flow_packets_s": rng.gamma(2.0, 20, n_benign),
        "label": rng.choice(["BENIGN"], n_benign),
    }
    # attack: extreme / bursty -> what Isolation Forest should isolate
    attack = {
        "flow_duration": rng.gamma(1.2, 5_000, n_attack),
        "flow_bytes_s": rng.gamma(5.0, 90_000, n_attack),
        "flow_packets_s": rng.gamma(5.0, 600, n_attack),
        "label": rng.choice(ATTACKS, n_attack),
    }
    df = pd.concat([pd.DataFrame(benign), pd.DataFrame(attack)], ignore_index=True)
    df = df.sample(frac=1, random_state=C.random_seed).reset_index(drop=True)
    df["protocol"] = rng.choice([6, 17, 0], len(df))  # TCP/UDP/HOPOPT like real data

    # inject the real-world mess: ~0.5% Infinity and NaN in the rate columns
    inf_idx = rng.choice(len(df), int(len(df) * 0.005), replace=False)
    nan_idx = rng.choice(len(df), int(len(df) * 0.005), replace=False)
    df.loc[inf_idx, "flow_bytes_s"] = np.inf
    df.loc[nan_idx, "flow_packets_s"] = np.nan

    # rename to the REAL CICIDS column style (leading spaces, slashes, caps)
    df = df.rename(columns={
        "flow_duration": " Flow Duration",
        "flow_bytes_s": "Flow Bytes/s",
        "flow_packets_s": " Flow Packets/s",
        "protocol": " Protocol",
        "label": " Label",
    })
    return df


if __name__ == "__main__":
    df = make()
    out = C.raw / "sample_cicids2017.csv"
    df.to_csv(out, index=False)
    print(f"Wrote {len(df):,} rows -> {out}")
    print(f"  attack rate: {(df[' Label'] != 'BENIGN').mean():.1%}")
    print(df[" Label"].value_counts().to_string())
