"""SecureWatch dashboard (Streamlit) — LIVE replay + Overview + Upload.

    streamlit run dashboard/app.py

🔴 LIVE     : streams the alert feed in real time (auto-refresh replay) so the
              demo looks like attacks arriving live. This is the showpiece.
📊 OVERVIEW : the full static picture (all alerts at once).
⬆️ UPLOAD   : drop a CSV -> analysed live via securewatch.service (same code as
              the batch pipeline).

OWNER: Member 3 (Frontend Lead). Plumbing is done; extend the Plotly visuals.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from securewatch import service  # noqa: E402
from securewatch.config import C  # noqa: E402
from securewatch.schemas import SEVERITY_ORDER  # noqa: E402

st.set_page_config(page_title="SecureWatch", page_icon="🛡️", layout="wide")
SEV_COLOR = {"LOW": "#3b82f6", "MEDIUM": "#f59e0b", "HIGH": "#f97316", "CRITICAL": "#ef4444"}
LAYER_ICON = {"network": "🌐", "document": "📄"}

st.markdown(
    """
    <style>
    .pulse{height:12px;width:12px;background:#ef4444;border-radius:50%;
        display:inline-block;margin-right:8px;box-shadow:0 0 0 rgba(239,68,68,.6);
        animation:pulse 1.4s infinite;}
    @keyframes pulse{0%{box-shadow:0 0 0 0 rgba(239,68,68,.7)}
        70%{box-shadow:0 0 0 12px rgba(239,68,68,0)}100%{box-shadow:0 0 0 0 rgba(239,68,68,0)}}
    .alert{padding:8px 12px;margin:4px 0;border-radius:6px;border-left:5px solid #888;
        background:rgba(127,127,127,.08);font-size:.9rem;}
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_data
def load_alerts() -> pd.DataFrame:
    """Load the prebuilt alert feed and add a synthetic 'arrival' clock that
    compresses the whole feed into a watchable ~3-minute live window."""
    p = C.processed / "alerts.parquet"
    if not p.exists():
        return pd.DataFrame()
    df = pd.read_parquet(p)
    if df.empty:
        return df
    df = df.sort_values("timestamp")
    # Interleave layers: spread each layer evenly across the stream so network
    # AND document alerts both appear throughout the replay (not clustered).
    sizes = df.groupby("layer")["layer"].transform("size").clip(lower=1)
    df["frac"] = df.groupby("layer").cumcount() / sizes
    df = df.sort_values("frac", kind="stable").reset_index(drop=True)
    now = pd.Timestamp.now().floor("s")
    window_s = 180  # replay the entire feed across 3 virtual minutes
    df["arrival"] = now - pd.to_timedelta((1 - df["frac"]) * window_s, unit="s")
    df["seq"] = df.index
    return df


def _alert_html(r: pd.Series) -> str:
    color = SEV_COLOR.get(r["severity"], "#888")
    icon = LAYER_ICON.get(r["layer"], "•")
    t = pd.to_datetime(r["arrival"]).strftime("%H:%M:%S")
    return (
        f"<div class='alert' style='border-left-color:{color}'>"
        f"<b style='color:{color}'>{r['severity']}</b> {icon} "
        f"<code>{t}</code> &nbsp; {r['summary']}</div>"
    )


def kpis(df: pd.DataFrame) -> None:
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Alerts", f"{len(df):,}")
    c2.metric("🔴 Critical", int((df["severity"] == "CRITICAL").sum()))
    c3.metric("🌐 Network", int((df["layer"] == "network").sum()))
    c4.metric("📄 Document", int((df["layer"] == "document").sum()))


def timeline(df: pd.DataFrame) -> None:
    if df.empty:
        return
    t = df.copy()
    t["bucket"] = pd.to_datetime(t["arrival"]).dt.floor("5s")
    chart = t.pivot_table(index="bucket", columns="layer", values="score",
                          aggfunc="count", fill_value=0)
    st.area_chart(chart, height=240)


# ===========================================================================
st.title("🛡️ SecureWatch — Unified Cyber Defence Dashboard")

with st.expander("ℹ️ What is this dashboard tracking?"):
    st.markdown(
        "- **🌐 Network layer** — anomalous traffic *flows* (port scans, DDoS, "
        "brute force) detected by an Isolation Forest on CICIDS-2017-style data.\n"
        "- **📄 Document layer** — suspicious *file-access behaviour* (off-hours "
        "access, bulk downloads, out-of-department access, exfiltration) from "
        "access **logs** — we watch behaviour, never file contents.\n"
        "- Both feed **one correlated, severity-ranked alert timeline.**"
    )

live_tab, overview_tab, upload_tab = st.tabs(["🔴 LIVE", "📊 Overview", "⬆️ Upload"])

# ---- LIVE MODE (the showpiece) ---------------------------------------------
with live_tab:
    alerts = load_alerts()
    if alerts.empty:
        st.warning("No alert feed yet. Run:  `make sample && make pipeline`  (or `make docs`).")
    else:
        st.session_state.setdefault("cursor", 0)
        st.session_state.setdefault("playing", False)

        b1, b2, b3, b4 = st.columns([1, 1, 1, 4])
        if b1.button("▶ Start", use_container_width=True):
            st.session_state.playing = True
        if b2.button("⏸ Pause", use_container_width=True):
            st.session_state.playing = False
        if b3.button("↻ Restart", use_container_width=True):
            st.session_state.cursor = 0
            st.session_state.playing = True
        speed = b4.slider("Stream speed (alerts/tick)", 5, 200,
                          max(5, len(alerts) // 40), step=5)

        @st.fragment(run_every="1.2s")
        def live() -> None:
            ss = st.session_state
            n = len(alerts)
            if ss.playing and ss.cursor < n:
                ss.cursor = min(n, ss.cursor + speed)
            shown = alerts.iloc[: ss.cursor]

            status = "🔴 LIVE" if (ss.playing and ss.cursor < n) else "⏸ PAUSED"
            if ss.cursor >= n:
                status = "✅ REPLAY COMPLETE"
            st.markdown(
                f"<h4><span class='pulse'></span>{status} "
                f"&nbsp;<small>{ss.cursor:,} / {n:,} events</small></h4>",
                unsafe_allow_html=True,
            )
            st.progress(ss.cursor / n if n else 0)

            if shown.empty:
                st.info("Press ▶ Start to stream the threat feed.")
                return

            kpis(shown)

            # latest high-severity attack banner
            hot = shown[shown["severity"].isin(["HIGH", "CRITICAL"])]
            if len(hot):
                last = hot.iloc[-1]
                st.error(f"⚠️ {last['severity']} — {LAYER_ICON.get(last['layer'],'')} "
                         f"{last['summary']}")

            left, right = st.columns([3, 2])
            with left:
                st.caption("Incoming alerts")
                feed = shown.sort_values("seq", ascending=False).head(12)
                st.markdown("".join(_alert_html(r) for _, r in feed.iterrows()),
                            unsafe_allow_html=True)
            with right:
                st.caption("Alerts over time")
                timeline(shown)
                sev = (shown["severity"].value_counts()
                       .reindex(SEVERITY_ORDER).fillna(0).astype(int))
                st.bar_chart(sev, height=180)

        live()

# ---- OVERVIEW (static, all-at-once) ----------------------------------------
with overview_tab:
    alerts = load_alerts()
    if alerts.empty:
        st.warning("No alert feed yet. Run:  `make sample && make pipeline`.")
    else:
        kpis(alerts)
        timeline(alerts)
        st.subheader("All alerts (severity-ranked)")
        feed = alerts.copy()
        feed["rank"] = feed["severity"].map({s: i for i, s in enumerate(SEVERITY_ORDER)})
        feed = feed.sort_values(["rank", "timestamp"], ascending=[False, False])
        st.dataframe(feed[["timestamp", "layer", "severity", "entity", "summary"]].head(300),
                     use_container_width=True, hide_index=True)

# ---- UPLOAD ----------------------------------------------------------------
with upload_tab:
    st.markdown("Upload a **network flow CSV** and/or **document access CSV** — "
                "analysed live, nothing is saved.")
    coln, cold = st.columns(2)
    net_file = coln.file_uploader("Network flow CSV", type=["csv"], key="net")
    doc_file = cold.file_uploader("Document access CSV", type=["csv"], key="doc")

    if st.button("Analyse", type="primary", disabled=not (net_file or doc_file)):
        net_scored = doc_scored = None
        with st.spinner("Running detection…"):
            if net_file is not None:
                try:
                    net_scored = service.analyze_network_csv(net_file)
                    st.success(f"Network: {len(net_scored):,} flows, "
                               f"{int(net_scored['is_anomaly'].sum()):,} anomalies")
                except Exception as e:
                    st.error(f"Network file error: {e}")
            if doc_file is not None:
                try:
                    doc_scored = service.analyze_document_csv(doc_file)
                    st.success(f"Documents: {len(doc_scored):,} events, "
                               f"{int(doc_scored['is_flagged'].sum()):,} flagged")
                except Exception as e:
                    st.error(f"Document file error: {e}")
        st.session_state["uploaded_alerts"] = service.build_alerts(net_scored, doc_scored)

    if "uploaded_alerts" in st.session_state and len(st.session_state["uploaded_alerts"]):
        st.divider()
        ua = st.session_state["uploaded_alerts"]
        kpis(ua)
        st.dataframe(ua[["timestamp", "layer", "severity", "entity", "summary"]].head(200),
                     use_container_width=True, hide_index=True)
