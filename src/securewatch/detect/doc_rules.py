"""Behavioural scoring for document events (Layer 2).

A transparent, explainable rule engine — exactly what judges want to see for
insider-threat detection, and it gives the alert feed human-readable reasons.
The security analyst (Member 4) tunes these thresholds.

Run:
    python -m securewatch.detect.doc_rules
Output: data/processed/document_scored.parquet (adds schemas.DOC_SCORE_COLUMNS)
"""
from __future__ import annotations

import pandas as pd

from securewatch.config import C
from securewatch.schemas import SEVERITY_ORDER


def _severity(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def score(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    risk = pd.Series(0.0, index=df.index)
    reasons = [[] for _ in range(len(df))]

    def bump(mask: pd.Series, points: int, why: str) -> None:
        risk[mask] += points
        for i in df.index[mask]:
            reasons[df.index.get_loc(i)].append(why)

    # 1. off-hours access (before 7am / after 8pm)
    bump((df["hour"] < 7) | (df["hour"] >= 20), 30, "off-hours access")

    # 2. accessing files outside own department
    out_scope = df["file_path"].str.split("/").str[1].str.lower() != df["department"].str.lower()
    bump(out_scope, 20, "file outside user's department")

    # 3. touching restricted/confidential files
    bump(df["file_sensitivity"].isin(["restricted", "confidential"]), 15,
         "sensitive file accessed")

    # 4. large transfer (top 2% of bytes)
    big = df["bytes"] > df["bytes"].quantile(0.98)
    bump(big, 25, "unusually large transfer")

    # 5. bulk activity: many downloads by same user in a short window
    downloads = df[df["action"] == "download"].copy()
    if len(downloads):
        downloads["bucket"] = downloads["timestamp"].dt.floor("10min")
        burst = (downloads.groupby(["user_id", "bucket"]).size()
                 .rename("cnt").reset_index())
        hot = burst[burst["cnt"] >= 20][["user_id", "bucket"]]
        if len(hot):
            dl = df["action"].eq("download")
            buckets = df["timestamp"].dt.floor("10min")
            key = pd.MultiIndex.from_arrays([df["user_id"], buckets])
            hot_key = pd.MultiIndex.from_frame(hot)
            bump(dl & key.isin(hot_key), 35, "bulk download burst")

    risk = risk.clip(0, 100)
    df["risk_score"] = risk
    df["is_flagged"] = (risk >= 35).astype(int)
    df["severity"] = risk.map(_severity)
    df["reason"] = ["; ".join(r) if r else "normal" for r in reasons]
    return df


def main() -> None:
    src = C.processed / "document_events.parquet"
    df = pd.read_parquet(src)
    scored = score(df)
    out = C.processed / "document_scored.parquet"
    scored.to_parquet(out, index=False)
    flagged = scored[scored["is_flagged"] == 1]
    print(f"Wrote {len(scored):,} scored doc events -> {out}")
    print(f"  flagged: {len(flagged):,}")
    # quick quality check against ground truth
    if "is_anomaly" in scored:
        tp = ((scored["is_flagged"] == 1) & (scored["is_anomaly"] == 1)).sum()
        fn = ((scored["is_flagged"] == 0) & (scored["is_anomaly"] == 1)).sum()
        recall = tp / (tp + fn) if (tp + fn) else 0
        print(f"  recall on injected anomalies: {recall:.1%}")
    print(scored["severity"].value_counts().reindex(SEVERITY_ORDER).to_string())


if __name__ == "__main__":
    main()
