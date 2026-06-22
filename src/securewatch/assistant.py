"""Light RAG assistant over the SecureWatch alert feed, powered by a LOCAL LLM.

Talks to LM Studio's OpenAI-compatible API (default qwen2.5-coder-7b-instruct-mlx
at http://127.0.0.1:1234). Everything runs offline — no alert data leaves the
machine, which is exactly what you want for a security tool.

"Light RAG" = retrieve the relevant slice of the alert feed (aggregate stats +
keyword-matched alerts), stuff it into the prompt, and let the model answer.
No vector DB needed for a structured feed of a few thousand rows.

    from securewatch import assistant
    assistant.available()                 # is LM Studio up?
    assistant.summarize(alerts_df)        # exec summary of the whole feed
    assistant.answer("which IPs are worst?", alerts_df)
"""
from __future__ import annotations

import json
import re
import urllib.request

import pandas as pd

from securewatch.config import C

_SYSTEM = (
    "You are SecureWatch, a concise SOC (security operations) analyst assistant. "
    "Answer ONLY from the CONTEXT provided about the current alert feed. "
    "Be specific and quote numbers, severities, IPs, users or attack types when "
    "they appear. If the context does not contain the answer, say so plainly. "
    "Keep answers short and skimmable. Never invent data."
)


# ---------------------------------------------------------------------------
# LM Studio transport (stdlib only)
# ---------------------------------------------------------------------------
def available() -> bool:
    """True if LM Studio is reachable."""
    try:
        req = urllib.request.Request(f"{C.lm_base_url}/v1/models")
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.status == 200
    except Exception:
        return False


def chat(messages: list[dict], temperature: float = 0.2,
         max_tokens: int = 600) -> str:
    payload = {
        "model": C.lm_model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": False,
    }
    req = urllib.request.Request(
        f"{C.lm_base_url}/v1/chat/completions",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=C.lm_timeout_s) as r:
        data = json.loads(r.read())
    return data["choices"][0]["message"]["content"].strip()


# ---------------------------------------------------------------------------
# Retrieval / context building over the alert feed
# ---------------------------------------------------------------------------
def _attack_types(alerts: pd.DataFrame) -> pd.Series:
    """Pull '(DDoS)' style attack labels out of network alert summaries."""
    found = alerts["summary"].str.extract(r"\(([^)]+)\)$")[0].dropna()
    return found.value_counts()


def stats_block(alerts: pd.DataFrame) -> str:
    """Always-included aggregate facts — the backbone of every answer."""
    if alerts.empty:
        return "The alert feed is currently empty."
    lines = [f"Total alerts: {len(alerts):,}"]

    sev = alerts["severity"].value_counts()
    lines.append("By severity: " + ", ".join(f"{k}={v}" for k, v in sev.items()))

    layer = alerts["layer"].value_counts()
    lines.append("By layer: " + ", ".join(f"{k}={v}" for k, v in layer.items()))

    atk = _attack_types(alerts)
    if len(atk):
        lines.append("Network attack types: "
                     + ", ".join(f"{k}={v}" for k, v in atk.head(8).items()))

    top_ent = alerts["entity"].value_counts().head(5)
    lines.append("Most-alerting entities (IP/user): "
                 + ", ".join(f"{k}({v})" for k, v in top_ent.items()))

    ts = pd.to_datetime(alerts["timestamp"])
    lines.append(f"Time range: {ts.min()} to {ts.max()}")
    return "\n".join(lines)


def retrieve(alerts: pd.DataFrame, question: str, k: int | None = None) -> pd.DataFrame:
    """Keyword retrieval: rank alerts by token overlap with the question, then
    by severity score. Falls back to the highest-severity alerts."""
    k = k or C.lm_max_context_alerts
    if alerts.empty:
        return alerts
    q = set(re.findall(r"\w+", question.lower()))
    text = (alerts["layer"].astype(str) + " " + alerts["severity"].astype(str) + " "
            + alerts["entity"].astype(str) + " " + alerts["summary"].astype(str)).str.lower()
    rel = text.apply(lambda t: len(q & set(re.findall(r"\w+", t))))
    out = alerts.assign(_rel=rel)
    if rel.max() == 0:  # no keyword hit -> just give the worst alerts
        return out.sort_values("score", ascending=False).head(k)
    return out.sort_values(["_rel", "score"], ascending=False).head(k)


def _alert_lines(df: pd.DataFrame) -> str:
    rows = []
    for _, r in df.iterrows():
        t = pd.to_datetime(r["timestamp"]).strftime("%Y-%m-%d %H:%M")
        rows.append(f"- [{r['severity']}|{r['layer']}] {t} {r['entity']}: {r['summary']}")
    return "\n".join(rows)


# ---------------------------------------------------------------------------
# Public: summarize + answer
# ---------------------------------------------------------------------------
def summarize(alerts: pd.DataFrame) -> str:
    if alerts.empty:
        return "No alerts to summarise yet."
    worst = alerts.sort_values("score", ascending=False).head(C.lm_max_context_alerts)
    context = f"STATS\n{stats_block(alerts)}\n\nTOP ALERTS\n{_alert_lines(worst)}"
    msg = [
        {"role": "system", "content": _SYSTEM},
        {"role": "user", "content":
            f"CONTEXT:\n{context}\n\n"
            "Write a 4-6 sentence executive summary of the current security "
            "posture: overall threat level, the dominant attack types, the most "
            "at-risk entities, and one recommended next action."},
    ]
    return chat(msg, temperature=0.2, max_tokens=400)


def answer(question: str, alerts: pd.DataFrame) -> str:
    if alerts.empty:
        return "There are no alerts loaded, so I have nothing to analyse yet."
    hits = retrieve(alerts, question)
    context = f"STATS\n{stats_block(alerts)}\n\nRELEVANT ALERTS\n{_alert_lines(hits)}"
    msg = [
        {"role": "system", "content": _SYSTEM},
        {"role": "user", "content": f"CONTEXT:\n{context}\n\nQUESTION: {question}"},
    ]
    return chat(msg, temperature=0.1, max_tokens=600)
