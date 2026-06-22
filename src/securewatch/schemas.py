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
# Layer 2 — Document access events (fully synthetic — you generate these)
# Written to: data/processed/document_events.parquet
# ---------------------------------------------------------------------------
DOC_EVENT_COLUMNS = [
    "timestamp",         # datetime
    "user_id",           # str   e.g. "u023"
    "user_name",         # str
    "department",        # str   e.g. Finance / Engineering / HR
    "role",              # str   e.g. analyst / manager / admin
    "file_id",           # str
    "file_path",         # str
    "file_sensitivity",  # str   public / internal / confidential / restricted
    "action",            # str   view / download / edit / delete
    "bytes",             # int   size moved
    "ip_address",        # str
    "hour",              # int   0-23 (handy for off-hours rules)
    # ground-truth labels — for demo/eval, NOT used by unsupervised detection
    "is_anomaly",        # int   1 if this event was injected as malicious
    "anomaly_type",      # str   none / off_hours / bulk_download / out_of_scope / exfiltration
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
