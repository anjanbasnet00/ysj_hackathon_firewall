"""Load raw CICIDS 2017 CSVs from data/raw/.

The dataset ships as ~8 CSVs (MachineLearningCVE / GeneratedLabelledFlows).
Download from: https://www.unb.ca/cic/datasets/ids-2017.html
Drop the unzipped .csv files into data/raw/ before running the pipeline.

Run:
    python -m securewatch.ingest.load_network   # quick sanity check
"""
from __future__ import annotations

import glob

import pandas as pd

from securewatch.config import C


def list_raw_csvs() -> list[str]:
    return sorted(glob.glob(str(C.raw / "*.csv")) + glob.glob(str(C.raw / "*.CSV")))


def load_raw(sample_rows: int | None = C.network_sample_rows) -> pd.DataFrame:
    """Concatenate all CICIDS CSVs. Optionally sample to keep things fast.

    Reads in chunks and samples per file so we don't blow up memory on the
    multi-GB full dataset during the hackathon.
    """
    files = list_raw_csvs()
    if not files:
        raise FileNotFoundError(
            f"No CSVs in {C.raw}. Download CICIDS 2017 and unzip the .csv files there.\n"
            "https://www.unb.ca/cic/datasets/ids-2017.html"
        )

    per_file = None if sample_rows is None else max(1, sample_rows // len(files))
    frames = []
    for fp in files:
        df = pd.read_csv(fp, low_memory=False, encoding="latin-1")
        if per_file is not None and len(df) > per_file:
            df = df.sample(per_file, random_state=C.random_seed)
        frames.append(df)
        print(f"  loaded {len(df):,} rows from {fp.split('/')[-1]}")

    out = pd.concat(frames, ignore_index=True)
    print(f"Total raw rows: {len(out):,}  |  columns: {out.shape[1]}")
    return out


if __name__ == "__main__":
    df = load_raw()
    print(df.head())
