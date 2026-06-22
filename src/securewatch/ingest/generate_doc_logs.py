"""Synthetic document-access log generator (Layer 2).

No real document data exists, so we simulate a realistic enterprise file-access
log and INJECT known insider-threat / exfiltration patterns. The injected events
carry ground-truth labels (is_anomaly, anomaly_type) so the team can demo and
measure detection — but the detector itself never sees those labels.

Run:
    python -m securewatch.ingest.generate_doc_logs

Output: data/processed/document_events.parquet  (matches schemas.DOC_EVENT_COLUMNS)
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta

import numpy as np
import pandas as pd

from securewatch.config import C
from securewatch.schemas import DOC_EVENT_COLUMNS

# faker is nice-to-have; degrade gracefully so this runs with only pandas/numpy.
try:
    from faker import Faker

    _fake = Faker()
    Faker.seed(C.random_seed)
except Exception:  # pragma: no cover
    _fake = None

rng = np.random.default_rng(C.random_seed)
random.seed(C.random_seed)

DEPARTMENTS = ["Finance", "Engineering", "HR", "Sales", "Legal", "Operations"]
ROLES = ["analyst", "engineer", "manager", "admin", "contractor"]
SENSITIVITIES = ["public", "internal", "confidential", "restricted"]
ACTIONS = ["view", "view", "view", "download", "edit", "delete"]  # weighted toward view


def _build_users() -> pd.DataFrame:
    rows = []
    for i in range(C.n_users):
        rows.append(
            {
                "user_id": f"u{i:03d}",
                "user_name": _fake.name() if _fake else f"User {i:03d}",
                "department": random.choice(DEPARTMENTS),
                "role": random.choices(ROLES, weights=[5, 5, 3, 1, 2])[0],
            }
        )
    return pd.DataFrame(rows)


def _build_files() -> pd.DataFrame:
    rows = []
    for i in range(C.n_files):
        dept = random.choice(DEPARTMENTS)
        sens = random.choices(SENSITIVITIES, weights=[3, 5, 3, 1])[0]
        name = _fake.file_name() if _fake else f"doc_{i:04d}.pdf"
        rows.append(
            {
                "file_id": f"f{i:04d}",
                "file_path": f"/{dept.lower()}/{name}",
                "owner_department": dept,
                "file_sensitivity": sens,
            }
        )
    return pd.DataFrame(rows)


def _rand_ip() -> str:
    return f"10.0.{rng.integers(0, 255)}.{rng.integers(1, 254)}"


def _business_hour_timestamp(day: datetime) -> datetime:
    """Most legitimate activity falls in 08:00–18:00."""
    hour = int(np.clip(rng.normal(13, 2.5), 8, 18))
    return day.replace(hour=hour, minute=int(rng.integers(0, 60)),
                       second=int(rng.integers(0, 60)))


def generate() -> pd.DataFrame:
    users = _build_users()
    files = _build_files()
    user_ip = {u: _rand_ip() for u in users["user_id"]}  # each user's "home" IP

    start = datetime.now() - timedelta(days=C.doc_log_days)
    events: list[dict] = []

    # ---- 1. NORMAL baseline activity -------------------------------------
    for d in range(C.doc_log_days):
        day = (start + timedelta(days=d)).replace(hour=0, minute=0, second=0, microsecond=0)
        is_weekend = day.weekday() >= 5
        n = int(C.doc_events_per_day * (0.2 if is_weekend else 1.0))
        for _ in range(n):
            u = users.sample(1, random_state=int(rng.integers(0, 1e9))).iloc[0]
            # normal users mostly touch files in their own department
            same_dept = files[files["owner_department"] == u["department"]]
            f = (same_dept if len(same_dept) and rng.random() < 0.85 else files).sample(
                1, random_state=int(rng.integers(0, 1e9))
            ).iloc[0]
            action = random.choice(ACTIONS)
            events.append(
                _event(u, f, action, _business_hour_timestamp(day),
                       user_ip[u["user_id"]], bytes_=_normal_bytes(action),
                       is_anomaly=0, anomaly_type="none")
            )

    # ---- 2. INJECTED anomalies -------------------------------------------
    # Budget by NUMBER OF EVENTS (not incidents) so the overall anomaly rate
    # stays realistic (~doc_anomaly_rate). Bulk bursts are rare but multi-event.
    n_normal = len(events)
    event_budget = int(n_normal * C.doc_anomaly_rate / (1 - C.doc_anomaly_rate))
    injected = 0
    while injected < event_budget:
        # bulk is intentionally rare — most incidents are single events
        kind = random.choices(
            ["off_hours", "out_of_scope", "exfiltration", "bulk_download"],
            weights=[35, 35, 20, 10],
        )[0]
        u = users.sample(1, random_state=int(rng.integers(0, 1e9))).iloc[0]
        day = (start + timedelta(days=int(rng.integers(0, C.doc_log_days)))).replace(
            hour=0, minute=0, second=0, microsecond=0
        )

        if kind == "off_hours":
            ts = day.replace(hour=int(rng.choice([1, 2, 3, 23])),
                             minute=int(rng.integers(0, 60)))
            f = files.sample(1).iloc[0]
            events.append(_event(u, f, "download", ts, user_ip[u["user_id"]],
                                 _normal_bytes("download"), 1, "off_hours"))
            injected += 1

        elif kind == "bulk_download":
            ts = _business_hour_timestamp(day)
            burst = files.sample(int(rng.integers(15, 35)))  # rare multi-event burst
            for _, f in burst.iterrows():
                events.append(_event(u, f, "download", ts + timedelta(seconds=int(rng.integers(0, 300))),
                                     user_ip[u["user_id"]], _normal_bytes("download") * 3,
                                     1, "bulk_download"))
            injected += len(burst)

        elif kind == "out_of_scope":
            other = files[files["owner_department"] != u["department"]]
            f = other.sample(1).iloc[0]
            ts = _business_hour_timestamp(day)
            events.append(_event(u, f, "view", ts, user_ip[u["user_id"]],
                                 _normal_bytes("view"), 1, "out_of_scope"))
            injected += 1

        else:  # exfiltration: restricted files, large bytes, unknown IP
            restricted = files[files["file_sensitivity"] == "restricted"]
            f = (restricted if len(restricted) else files).sample(1).iloc[0]
            ts = day.replace(hour=int(rng.choice([0, 2, 22, 23])))
            events.append(_event(u, f, "download", ts, _rand_ip(),  # NOT their home IP
                                 _normal_bytes("download") * 10, 1, "exfiltration"))
            injected += 1

    df = pd.DataFrame(events)
    df = df.sort_values("timestamp").reset_index(drop=True)
    df["hour"] = df["timestamp"].dt.hour
    return df[DOC_EVENT_COLUMNS]


def _normal_bytes(action: str) -> int:
    base = {"view": 5_000, "download": 500_000, "edit": 50_000, "delete": 1_000}
    return int(max(1, rng.normal(base[action], base[action] * 0.4)))


def _event(u, f, action, ts, ip, bytes_, is_anomaly, anomaly_type) -> dict:
    return {
        "timestamp": ts,
        "user_id": u["user_id"],
        "user_name": u["user_name"],
        "department": u["department"],
        "role": u["role"],
        "file_id": f["file_id"],
        "file_path": f["file_path"],
        "file_sensitivity": f["file_sensitivity"],
        "action": action,
        "bytes": bytes_,
        "ip_address": ip,
        "hour": ts.hour,
        "is_anomaly": is_anomaly,
        "anomaly_type": anomaly_type,
    }


def main() -> None:
    df = generate()
    out = C.processed / "document_events.parquet"
    df.to_parquet(out, index=False)
    print(f"Wrote {len(df):,} document events -> {out}")
    print(f"  injected anomalies: {df['is_anomaly'].sum():,} "
          f"({df['is_anomaly'].mean():.1%})")
    print(df["anomaly_type"].value_counts().to_string())


if __name__ == "__main__":
    main()
