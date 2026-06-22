"""SecureWatch dashboard (Streamlit) — Live replay + Overview + Live Drive + Upload + Ask.

    streamlit run dashboard/app.py

LIVE      : streams the alert feed in real time (auto-refresh replay).
OVERVIEW  : the full static picture (all alerts at once).
LIVE DRIVE: scans a connected Google Drive and scores file behaviour live.
UPLOAD    : drop a CSV -> analysed live via securewatch.service (same code as
            the batch pipeline).
ASK       : light RAG over the alert feed, answered by a local LLM.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from securewatch import assistant, service  # noqa: E402
from securewatch.config import C  # noqa: E402
from securewatch.detect import doc_rules  # noqa: E402
from securewatch.ingest import gdrive  # noqa: E402
from securewatch.schemas import DOC_EVENT_COLUMNS, SEVERITY_ORDER  # noqa: E402

st.set_page_config(page_title="SecureWatch", layout="wide")
SEV_COLOR = {"LOW": "#3b82f6", "MEDIUM": "#f59e0b", "HIGH": "#f97316", "CRITICAL": "#ef4444"}

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
    layer = str(r["layer"]).upper()
    t = pd.to_datetime(r["arrival"]).strftime("%H:%M:%S")
    return (
        f"<div class='alert' style='border-left-color:{color}'>"
        f"<b style='color:{color}'>{r['severity']}</b> "
        f"<span style='color:#888'>{layer}</span> "
        f"<code>{t}</code> &nbsp; {r['summary']}</div>"
    )


def kpis(df: pd.DataFrame) -> None:
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Alerts", f"{len(df):,}")
    c2.metric("Critical", int((df["severity"] == "CRITICAL").sum()))
    c3.metric("Network", int((df["layer"] == "network").sum()))
    c4.metric("Document", int((df["layer"] == "document").sum()))


def timeline(df: pd.DataFrame) -> None:
    if df.empty:
        return
    t = df.copy()
    t["bucket"] = pd.to_datetime(t["arrival"]).dt.floor("5s")
    chart = t.pivot_table(index="bucket", columns="layer", values="score",
                          aggfunc="count", fill_value=0)
    st.area_chart(chart, height=240)


st.title("SecureWatch — Unified Cyber Defence Dashboard")

with st.expander("What is this dashboard tracking?"):
    st.markdown(
        "- **Network layer** — anomalous traffic *flows* (port scans, DDoS, "
        "brute force) detected by an Isolation Forest on CICIDS 2017 data.\n"
        "- **Document layer** — suspicious *file-access behaviour* (off-hours "
        "access, bulk activity, large transfers) from a connected Google Drive "
        "— we watch behaviour, never file contents.\n"
        "- Both feed **one correlated, severity-ranked alert timeline.**"
    )

# AI summary panel (local LLM, on top of the dashboard)
with st.expander("AI summary — analyst briefing (local LLM)", expanded=False):
    if not assistant.available():
        st.caption(f"LM Studio not reachable at `{C.lm_base_url}`. Start LM Studio "
                   f"and load `{C.lm_model}`, then reload.")
    else:
        st.caption(f"Local model `{C.lm_model}` — runs offline, no data leaves this machine.")
        if st.button("Generate briefing", type="primary", key="gen_briefing"):
            _a = load_alerts()
            with st.spinner("Summarising the alert feed locally..."):
                try:
                    st.session_state["ai_summary"] = assistant.summarize(_a)
                except Exception as e:  # noqa: BLE001
                    st.session_state["ai_summary"] = f"LLM error: {e}"
        if st.session_state.get("ai_summary"):
            st.markdown(st.session_state["ai_summary"])

live_tab, overview_tab, drive_tab, upload_tab, ask_tab = st.tabs(
    ["Live", "Overview", "Live Drive", "Upload", "Ask"])

# ---- LIVE MODE (the showpiece) ---------------------------------------------
with live_tab:
    alerts = load_alerts()
    if alerts.empty:
        st.warning("No alert feed yet. Run:  `make pipeline`.")
    else:
        st.session_state.setdefault("cursor", 0)
        st.session_state.setdefault("playing", False)

        b1, b2, b3, b4 = st.columns([1, 1, 1, 4])
        if b1.button("Start", use_container_width=True, key="live_start"):
            st.session_state.playing = True
        if b2.button("Pause", use_container_width=True, key="live_pause"):
            st.session_state.playing = False
        if b3.button("Restart", use_container_width=True, key="live_restart"):
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

            status = "LIVE" if (ss.playing and ss.cursor < n) else "PAUSED"
            if ss.cursor >= n:
                status = "REPLAY COMPLETE"
            st.markdown(
                f"<h4><span class='pulse'></span>{status} "
                f"&nbsp;<small>{ss.cursor:,} / {n:,} events</small></h4>",
                unsafe_allow_html=True,
            )
            st.progress(ss.cursor / n if n else 0)

            if shown.empty:
                st.info("Press Start to stream the threat feed.")
                return

            kpis(shown)

            # latest high-severity attack banner
            hot = shown[shown["severity"].isin(["HIGH", "CRITICAL"])]
            if len(hot):
                last = hot.iloc[-1]
                st.error(f"{last['severity']} — {last['summary']}")

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
        st.warning("No alert feed yet. Run:  `make pipeline`.")
    else:
        kpis(alerts)
        timeline(alerts)
        st.subheader("All alerts (severity-ranked)")
        feed = alerts.copy()
        feed["rank"] = feed["severity"].map({s: i for i, s in enumerate(SEVERITY_ORDER)})
        feed = feed.sort_values(["rank", "timestamp"], ascending=[False, False])
        st.dataframe(feed[["timestamp", "layer", "severity", "entity", "summary"]].head(300),
                     use_container_width=True, hide_index=True)

# ---- LIVE DRIVE (real Google Drive activity, scored live) ------------------
# Live-activity verbs (from the Drive Activity API). The bulk-burst rule only
# counts these, so a batch of discovered files sharing an upload time isn't
# mistaken for a live exfiltration burst.
LIVE_ACTIONS = ("create", "edit", "move", "rename", "delete", "restore")


def _score_drive(events: list[dict]) -> pd.DataFrame:
    """Score accumulated Drive events with behaviour-only, demo-tuned rules.

    Discovered files flag on large-transfer + off-hours; the bulk-burst rule
    fires only on live actions you perform during the demo."""
    df = pd.DataFrame(events, columns=DOC_EVENT_COLUMNS)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return doc_rules.score(
        df,
        check_department=False,      # personal Drive has no department metadata
        check_sensitivity=False,     # and no sensitivity labels
        large_bytes=C.live_large_bytes,
        bulk_threshold=C.live_bulk_threshold,
        bulk_window=C.live_bulk_window,
        bulk_actions=LIVE_ACTIONS,   # only live edits/deletes count as a burst
    )


def _seed_drive_scan() -> None:
    """Discover the files currently in the Drive and load them as the initial
    scan. Live polling then continues from 'now' on top of this baseline."""
    ss = st.session_state
    try:
        files = gdrive.scan_files()
        ss.drive_events = files
        ss.drive_seen = {(e["file_id"], e["action"], str(e["timestamp"])) for e in files}
        ss.drive_error = ""
    except Exception as e:  # noqa: BLE001
        ss.drive_error = str(e)
    ss.drive_cursor = datetime.now(timezone.utc)   # live activity continues from here


with drive_tab:
    st.markdown(
        "Scans a connected **Google Drive** and flags suspicious *behaviour* "
        "— off-hours access, bulk bursts, and large transfers — using the same "
        "rule engine as the batch pipeline. We watch what happens to files, "
        "never their contents."
    )

    if not gdrive.credentials_present():
        st.warning(
            "**Google Drive not configured.** One-time setup:\n"
            "1. Google Cloud Console: enable Drive API + Drive Activity API\n"
            "2. Create an OAuth client ID (Web app, redirect `http://localhost:8501`)\n"
            "3. Save the downloaded JSON as **`credentials.json`** in the repo root\n"
            "4. Add your Gmail as a Test user on the consent screen\n\n"
            "Then reload this tab. (See the README for details.)"
        )
    else:
        ss = st.session_state
        ss.setdefault("drive_events", [])
        ss.setdefault("drive_seen", set())
        ss.setdefault("drive_cursor", None)
        ss.setdefault("drive_watching", False)
        ss.setdefault("drive_error", "")

        # Reconnect silently if we already have a cached token this session/run.
        gdrive.try_connect_cached()

        # Step 2 of the web OAuth flow: Google redirected back here with ?code=
        if not gdrive.is_connected() and "code" in st.query_params:
            try:
                with st.spinner("Finishing Google sign-in..."):
                    gdrive.exchange_code(st.query_params["code"])
                ss.drive_watching = True
                st.query_params.clear()
                st.rerun()
            except Exception as e:  # noqa: BLE001
                st.error(f"Sign-in failed: {e}")
                st.query_params.clear()

        if not gdrive.is_connected():
            # Step 1: send the user to Google's consent screen.
            st.link_button("Connect Google Drive", gdrive.auth_url(), type="primary")
            st.caption("Opens Google sign-in, then returns you here and starts the scan.")
        else:
            # First time connected this session: scan the files in the Drive.
            if ss.drive_cursor is None:
                with st.spinner("Scanning your Google Drive files..."):
                    _seed_drive_scan()
                ss.drive_watching = True
            # Show WHICH account is connected: name + email (+ avatar).
            info = gdrive.account_info()
            who = info.get("name") or "Google account"
            email = info.get("email") or "unknown"
            # avatar via HTML so a blocked photo URL hides cleanly (no broken icon)
            avatar = (f"<img src='{info['photo']}' width='34' "
                      f"style='border-radius:50%;vertical-align:middle;margin-right:10px'"
                      f" onerror=\"this.style.display='none'\"/>"
                      if info.get("photo") else "")
            st.markdown(
                f"<div style='padding:6px 0'>{avatar}"
                f"<span style='color:#22c55e'><b>Connected as {who}</b></span> "
                f"&nbsp;<code>{email}</code> — "
                f"{len(ss.drive_events):,} files discovered + live changes.</div>",
                unsafe_allow_html=True)

            c1, c2, c3, c4 = st.columns([1.2, 1, 1.5, 1])
            label = "Pause" if ss.drive_watching else "Resume"
            if c1.button(label, key="drive_playpause", use_container_width=True):
                ss.drive_watching = not ss.drive_watching
            if c2.button("Rescan", key="drive_rescan", use_container_width=True):
                with st.spinner("Rescanning your Google Drive files..."):
                    _seed_drive_scan()
            if c3.button("Disconnect / switch", key="drive_disconnect",
                         use_container_width=True):
                gdrive.disconnect()
                ss.drive_events, ss.drive_seen = [], set()
                ss.drive_cursor, ss.drive_watching = None, False
                st.query_params.clear()
                st.rerun()
            c4.metric("Poll", f"{C.live_poll_seconds}s")

        if gdrive.is_connected():
            @st.fragment(run_every=f"{C.live_poll_seconds}s")
            def drive_live() -> None:
                s = st.session_state
                if s.drive_watching:
                    try:
                        new, cursor = gdrive.poll_activity(s.drive_cursor)
                        s.drive_cursor = cursor
                        s.drive_error = ""
                        for ev in new:
                            key = (ev["file_id"], ev["action"], str(ev["timestamp"]))
                            if key not in s.drive_seen:
                                s.drive_seen.add(key)
                                s.drive_events.append(ev)
                    except Exception as e:  # noqa: BLE001
                        s.drive_error = str(e)

                dot = "WATCHING" if s.drive_watching else "PAUSED"
                st.markdown(
                    f"<h4><span class='pulse' style='background:#22c55e'></span>{dot} "
                    f"&nbsp;<small>{len(s.drive_events):,} activity events</small></h4>",
                    unsafe_allow_html=True,
                )
                if s.drive_error:
                    st.caption(f"Error: {s.drive_error}")
                if not s.drive_events:
                    st.info("Watching your Drive. Upload, edit, or delete a file "
                            "to see a behavioural alert appear.")
                    return

                scored = _score_drive(s.drive_events)
                alerts = service.build_alerts(doc_scored=scored)
                kpis(alerts) if len(alerts) else st.caption("No alerts yet — "
                    "activity seen, but nothing has crossed a risk threshold.")

                hot = alerts[alerts["severity"].isin(["HIGH", "CRITICAL"])] if len(alerts) else alerts
                if len(hot):
                    last = hot.iloc[-1]
                    st.error(f"{last['severity']} — {last['summary']}")

                left, right = st.columns([3, 2])
                with left:
                    st.caption("Recent Drive activity")
                    recent = scored.sort_values("timestamp", ascending=False).head(12)
                    for _, r in recent.iterrows():
                        color = SEV_COLOR.get(r["severity"], "#888") if r["is_flagged"] else "#888"
                        t = pd.to_datetime(r["timestamp"]).strftime("%H:%M:%S")
                        st.markdown(
                            f"<div class='alert' style='border-left-color:{color}'>"
                            f"<code>{t}</code> <b>{r['action']}</b> {r['file_path']} "
                            f"&nbsp;<small>{r['reason']}</small></div>",
                            unsafe_allow_html=True)
                with right:
                    st.caption("Risk severity")
                    if len(alerts):
                        sev = (alerts["severity"].value_counts()
                               .reindex(SEVERITY_ORDER).fillna(0).astype(int))
                        st.bar_chart(sev, height=200)

            drive_live()


# ---- UPLOAD ----------------------------------------------------------------
with upload_tab:
    st.markdown("Upload a **network flow CSV** and/or **document access CSV** — "
                "analysed live, nothing is saved.")
    coln, cold = st.columns(2)
    net_file = coln.file_uploader("Network flow CSV", type=["csv"], key="net")
    doc_file = cold.file_uploader("Document access CSV", type=["csv"], key="doc")

    if st.button("Analyse", type="primary", disabled=not (net_file or doc_file), key="upload_analyse"):
        net_scored = doc_scored = None
        with st.spinner("Running detection..."):
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


# ---- ASK (light RAG over the alert feed, local LLM) ------------------------
with ask_tab:
    st.subheader("Ask SecureWatch")
    st.caption("Light RAG over the live alert feed, answered by a local LLM "
               f"(`{C.lm_model}` via LM Studio). Your data never leaves this machine.")

    feed = load_alerts()
    if feed.empty:
        st.warning("No alert feed yet. Run `make pipeline` first.")
    elif not assistant.available():
        st.error(f"LM Studio not reachable at `{C.lm_base_url}`. "
                 f"Start it and load `{C.lm_model}`, then reload this tab.")
    else:
        st.session_state.setdefault("chat", [])

        # one-click example questions for judges
        examples = [
            "What are the top 3 threats right now?",
            "Which source IPs are most dangerous and why?",
            "How many critical alerts are there and what are they?",
            "Is there any sign of data exfiltration or insider activity?",
        ]
        st.write("Try:")
        ecols = st.columns(2)
        pending = None
        for i, ex in enumerate(examples):
            if ecols[i % 2].button(ex, key=f"ex{i}", use_container_width=True):
                pending = ex

        # render history
        for m in st.session_state["chat"]:
            with st.chat_message(m["role"]):
                st.markdown(m["content"])

        # free-text input (form so Enter submits cleanly inside the tab)
        with st.form("ask_form", clear_on_submit=True):
            typed = st.text_input("Ask a question about the alerts",
                                  label_visibility="collapsed",
                                  placeholder="e.g. which users triggered bulk-download alerts?")
            submitted = st.form_submit_button("Ask", type="primary")
        question = pending or (typed if submitted and typed else None)

        if question:
            st.session_state["chat"].append({"role": "user", "content": question})
            with st.chat_message("user"):
                st.markdown(question)
            with st.chat_message("assistant"):
                with st.spinner("Thinking locally..."):
                    try:
                        ans = assistant.answer(question, feed)
                    except Exception as e:  # noqa: BLE001
                        ans = f"LLM error: {e}"
                st.markdown(ans)
            st.session_state["chat"].append({"role": "assistant", "content": ans})

        if st.session_state["chat"] and st.button("Clear chat", key="clear_chat"):
            st.session_state["chat"] = []
            st.rerun()
