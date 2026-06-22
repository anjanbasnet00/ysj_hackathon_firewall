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


def score(
    df: pd.DataFrame,
    *,
    check_department: bool = True,
    check_sensitivity: bool = True,
    large_bytes: float | None = None,
    bulk_threshold: int = 20,
    bulk_window: str = "10min",
    bulk_actions: tuple[str, ...] | None = ("download",),
) -> pd.DataFrame:
    """Behavioural risk scoring for document/Drive events.

    The defaults match the original batch behaviour. The live Google Drive layer
    passes tuned values (see config.C.live_*) and disables the department /
    sensitivity rules, since a personal Drive account has no such metadata:

        check_department/check_sensitivity : skip rules that need that metadata
        large_bytes      : absolute byte threshold for "large transfer"
                           (None -> top-2% quantile, the batch default)
        bulk_threshold   : N actions by a user within bulk_window -> burst
        bulk_window      : pandas offset alias for the burst window
        bulk_actions     : which actions count toward a burst (None -> all)
    """
    df = df.copy()
    risk = pd.Series(0.0, index=df.index)
    reasons = [[] for _ in range(len(df))]

    def bump(mask: pd.Series, points: int, why: str) -> None:
        risk[mask] += points
        for i in df.index[mask]:
            reasons[df.index.get_loc(i)].append(why)

    # 1. off-hours access (before 7am / after 8pm)
    bump((df["hour"] < 7) | (df["hour"] >= 20), 30, "off-hours access")

    # 2. accessing files outside own department (needs department metadata)
    if check_department:
        out_scope = df["file_path"].str.split("/").str[1].str.lower() != df["department"].str.lower()
        bump(out_scope.fillna(False), 20, "file outside user's department")

    # 3. touching restricted/confidential files (needs sensitivity metadata)
    if check_sensitivity:
        bump(df["file_sensitivity"].isin(["restricted", "confidential"]), 15,
             "sensitive file accessed")

    # 4. large transfer (absolute threshold if given, else top 2% of bytes)
    threshold = large_bytes if large_bytes is not None else df["bytes"].quantile(0.98)
    bump(df["bytes"] > threshold, 25, "unusually large transfer")

    # 5. bulk activity: many qualifying actions by same user in a short window
    acts = df if bulk_actions is None else df[df["action"].isin(bulk_actions)]
    acts = acts.copy()
    if len(acts):
        acts["bucket"] = acts["timestamp"].dt.floor(bulk_window)
        burst = (acts.groupby(["user_id", "bucket"]).size()
                 .rename("cnt").reset_index())
        hot = burst[burst["cnt"] >= bulk_threshold][["user_id", "bucket"]]
        if len(hot):
            in_scope = (pd.Series(True, index=df.index) if bulk_actions is None
                        else df["action"].isin(bulk_actions))
            buckets = df["timestamp"].dt.floor(bulk_window)
            key = pd.MultiIndex.from_arrays([df["user_id"], buckets])
            hot_key = pd.MultiIndex.from_frame(hot)
            bump(in_scope & key.isin(hot_key), 35, "bulk activity burst")

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
