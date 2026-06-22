"""THE DATA CONTRACT.

This is the single most important file for parallel teamwork. The ML engineer,
the frontend lead, and the security analyst all build against THESE column names.
If a column name changes, change it here once and tell the team.

Everything your pipeline writes to data/processed/ must match these schemas.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Layer 1 — Network events (derived from CICIDS 2017 after cleaning)
# Written to: data/processed/network_events.parquet
# ---------------------------------------------------------------------------
NETWORK_EVENT_COLUMNS = [
    "timestamp",        # datetime — synthetic if dataset lacks one
    "src_ip",           # str
    "dst_ip",           # str
    "protocol",         # str
    "flow_duration",    # float
    "flow_bytes_s",     # float  (cleaned: no inf/nan)
    "flow_packets_s",   # float
    "label",            # str   — original CICIDS label e.g. BENIGN / DDoS / PortScan
    "is_attack",        # int   — ground truth: 0 benign, 1 attack (for eval only)
]

# After Isolation Forest scoring (ML engineer appends these):
NETWORK_SCORE_COLUMNS = [
    "anomaly_score",    # float — lower = more anomalous (sklearn convention)
    "is_anomaly",       # int   — 1 if model flags as anomaly
    "severity",         # str   — LOW / MEDIUM / HIGH / CRITICAL
]

# ---------------------------------------------------------------------------
# Layer 2 — Document access events (LIVE Google Drive activity feed)
# Produced in-memory by securewatch.ingest.gdrive; the dashboard's Live Drive
# tab scores it in real time. department/file_sensitivity are placeholders on a
# personal account, so detection is behaviour-only (off-hours / bulk / large).
# ---------------------------------------------------------------------------
DOC_EVENT_COLUMNS = [
    "timestamp",         # datetime — when the Drive activity happened
    "user_id",           # str   acting account email
    "user_name",         # str   acting account display name
    "department",        # str   placeholder ("Drive") on a personal account
    "role",              # str   placeholder ("user")
    "file_id",           # str   Drive file id
    "file_path",         # str   Drive file name/path
    "file_sensitivity",  # str   placeholder ("unknown") on a personal account
    "action",            # str   create / edit / move / rename / delete / comment
    "bytes",             # int   file size (0 for native Docs/Sheets)
    "ip_address",        # str   unavailable from Drive Activity API ("")
    "hour",              # int   0-23 (handy for off-hours rules)
]

# After behavioural scoring (security analyst rules + optional model):
DOC_SCORE_COLUMNS = [
    "risk_score",        # float 0-100
    "is_flagged",        # int
    "severity",          # str  LOW / MEDIUM / HIGH / CRITICAL
    "reason",            # str  human-readable why it fired (for the alert feed)
]

# ---------------------------------------------------------------------------
# Unified alert feed — what the dashboard's live feed + timeline render
# Written to: data/processed/alerts.parquet
# ---------------------------------------------------------------------------
ALERT_COLUMNS = [
    "timestamp",
    "layer",        # "network" | "document"
    "severity",     # LOW / MEDIUM / HIGH / CRITICAL
    "entity",       # the IP or user_id involved
    "summary",      # one-line description for the feed
    "score",        # numeric severity score for ranking
]

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
