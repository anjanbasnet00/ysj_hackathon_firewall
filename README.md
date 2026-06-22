# SecureWatch

**Unified Cyber-Defence Dashboard**
Cyber Defence Innovation Hackathon | **Team Firewall**

## Contest Details

| Item | Details |
|---|---|
| Event | Cyber Defence Innovation Hackathon |
| Team | Team Firewall |
| Project | SecureWatch |
| Category | Cybersecurity monitoring and threat detection |
| Main goal | Combine network and document-security monitoring in one dashboard |
| Network source | CICIDS 2017 |
| Document source | Live Google Drive activity |
| Interface | Streamlit dashboard |

## Team Members

| Name | GitHub |
|---|---|
| Daniel Kofi Frempong | [@Gig2341](https://github.com/Gig2341) |
| Anjan Basnet | [@anjanbasnet00](https://github.com/anjanbasnet00) |
| Joy Ometo | [@emetojoyc12-debug](https://github.com/emetojoyc12-debug) |

## Overview

SecureWatch is a dual-layer cybersecurity monitoring platform that detects
network attacks and suspicious document activity in one place.

It combines:

- Network-flow anomaly detection using an Isolation Forest model.
- Live Google Drive activity monitoring using explainable rules.
- A unified severity-ranked alert format.
- CSV upload and immediate analysis.
- A local AI assistant for alert summaries and investigation questions.

The dashboard helps an analyst answer three simple questions:

1. What suspicious activity has occurred?
2. How serious is it?
3. Which user, file, or IP address is involved?

SecureWatch monitors document behaviour and metadata. It does not read the
contents of Google Drive files.

## Problem / Challenge Addressed

Security teams often monitor network traffic and document systems in separate
tools. This creates blind spots and makes investigations slower.

For example:

- A network tool may detect unusual traffic but provide no document context.
- A document tool may detect risky file activity but provide no network view.
- Analysts may need to manually compare alerts from several systems.

SecureWatch reduces this separation by:

- Detecting unusual network flows such as DDoS and port-scan behaviour.
- Monitoring real Google Drive actions.
- Detecting off-hours, large-file, and bulk activity.
- Converting both sources into a common alert format.
- Presenting findings through one dashboard.
- Explaining why document activity was flagged.

## Objectives

- Build a clear cybersecurity dashboard suitable for live demonstrations.
- Detect network anomalies without requiring labelled production traffic.
- Connect securely to Google Drive using read-only OAuth permissions.
- Detect suspicious document behaviour without reading file contents.
- Rank alerts as `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.
- Support uploaded network and document CSV files.
- Keep alert analysis private by running the optional LLM locally.
- Provide a reliable fallback when Google or the local LLM is unavailable.

---

## System Architecture

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                              DATA SOURCES                                   │
├─────────────────────────┬─────────────────────────┬─────────────────────────┤
│ CICIDS 2017 network CSV │ Live Google Drive      │ User-uploaded CSV       │
│ files in data/raw/      │ activity and metadata │ network or document     │
└────────────┬────────────┴────────────┬────────────┴────────────┬────────────┘
             │                         │                         │
             ▼                         ▼                         ▼
┌──────────────────────┐  ┌────────────────────────┐  ┌──────────────────────┐
│ NETWORK INGESTION    │  │ GOOGLE OAUTH 2.0       │  │ UPLOAD SERVICE       │
│                      │  │                        │  │                      │
│ Load and sample CSVs │  │ Read-only scopes       │  │ Validate CSV columns │
│ Normalize columns    │  │ Cached local token     │  │ Select correct path  │
└──────────┬───────────┘  └────────────┬───────────┘  └──────────┬───────────┘
           │                           │                         │
           ▼                           ▼                         │
┌──────────────────────┐  ┌────────────────────────┐             │
│ NETWORK PREPROCESSOR │  │ DRIVE ACTIVITY ADAPTER │             │
│                      │  │                        │             │
│ Clean invalid values │  │ Poll activity API      │             │
│ Build ML features    │  │ Read file metadata     │             │
│ Preserve test labels │  │ Map to document schema │             │
└──────────┬───────────┘  └────────────┬───────────┘             │
           │                           │                         │
           ▼                           ▼                         ▼
┌──────────────────────┐  ┌────────────────────────┐  ┌──────────────────────┐
│ ISOLATION FOREST     │  │ BEHAVIOURAL RULES      │  │ SHARED ANALYSIS API  │
│                      │  │                        │  │                      │
│ Learn normal traffic │  │ Off-hours activity     │  │ Uses the same network│
│ Calculate anomalies  │  │ Large-file activity    │  │ and document engines │
│ Assign severity      │  │ Bulk activity bursts   │  │ as the main pipeline │
└──────────┬───────────┘  └────────────┬───────────┘  └──────────┬───────────┘
           │                           │                         │
           └───────────────────┬───────┴─────────────────────────┘
                               │
                               ▼
                  ┌─────────────────────────┐
                  │ UNIFIED ALERT BUILDER   │
                  │                         │
                  │ Timestamp               │
                  │ Network/document layer  │
                  │ Severity                │
                  │ User or source IP       │
                  │ Explanation and score   │
                  └────────────┬────────────┘
                               │
               ┌───────────────┴────────────────┐
               │                                │
               ▼                                ▼
┌────────────────────────────┐    ┌────────────────────────────┐
│ STREAMLIT DASHBOARD        │    │ LOCAL AI ASSISTANT         │
│                            │    │                            │
│ LIVE replay                │    │ Alert statistics           │
│ Overview                   │    │ Keyword retrieval          │
│ Live Drive                 │    │ LM Studio local model      │
│ Upload analysis            │    │ Summary and Q&A            │
│ Metrics and charts         │    │ No external LLM required   │
└────────────────────────────┘    └────────────────────────────┘
```

### Important architecture boundary

The main `LIVE` tab replays alerts stored in `alerts.parquet`.

The `Live Drive` tab polls real Google Drive activity and keeps those events in
the current Streamlit session. Live Drive alerts are not yet persisted or merged
into the main replay and AI context.

## Detection Layers

### 1. Network Monitor

The network layer processes CICIDS 2017-compatible CSV files.

```text
Raw flows
  → clean invalid and infinite values
  → create numerical features
  → train or load Isolation Forest
  → calculate anomaly scores
  → assign severity
  → create network alerts
```

The model uses an Isolation Forest contamination value of `0.08`.

CICIDS attack labels are retained for evaluation and display. They are not used
as model input.

Generated network files:

```text
data/processed/network_events.parquet
data/processed/network_features.parquet
data/processed/network_scored.parquet
data/processed/alerts.parquet
models/isolation_forest.pkl
```

### 2. Google Drive Monitor

The Drive layer uses:

- Google OAuth 2.0
- Google Drive Activity API
- Google Drive metadata API
- Read-only permissions

It polls every 5 seconds and loads the previous 7 days of activity when a
connection begins.

Mapped Drive actions include:

- Create
- Edit
- Move
- Rename
- Delete and restore
- Permission change
- Comment
- Label, settings, and DLP changes

Live events are normalized into the shared document-event schema before the
rules are applied.

## Behavioural Rules

### Document CSV rules

| Signal | Risk points |
|---|---:|
| Activity before 07:00 or after 20:00 | 30 |
| File outside the user's department | 20 |
| Restricted or confidential file | 15 |
| Unusually large transfer | 25 |
| At least 20 downloads within 10 minutes | 35 |

### Live Google Drive rules

| Signal | Current setting | Risk points |
|---|---|---:|
| Off-hours activity | Before 07:00 or after 20:00 | 30 |
| Large-file activity | File larger than 10 MB | 25 |
| Bulk activity | At least 5 actions within 2 minutes | 35 |

Personal Drive does not provide department or sensitivity metadata, so those
checks are disabled in the live Drive flow.

### Severity levels

| Score | Result |
|---:|---|
| 0–34 | `LOW`, not flagged |
| 35–59 | `MEDIUM` |
| 60–79 | `HIGH` |
| 80–100 | `CRITICAL` |

Off-hours activity alone scores 30 and does not trigger an alert. Signals can
combine; for example, off-hours plus bulk activity becomes `HIGH`.

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.10+ |
| ML | scikit-learn Isolation Forest |
| Data processing | Pandas, NumPy, SciPy |
| Storage | PyArrow and Parquet |
| Dashboard | Streamlit |
| Network dataset | CICIDS 2017 |
| Drive integration | Google OAuth, Drive API, Drive Activity API |
| Local AI | LM Studio OpenAI-compatible API |
| Default local model | `qwen2.5-coder-7b-instruct-mlx` |
| Automation | GNU Make and shell |
| Validation | Python compile checks and manual flow verification |

## Dashboard Views

| View | Purpose |
|---|---|
| `LIVE` | Replays persisted alerts over a compressed three-minute window |
| `Overview` | Shows the complete severity-ranked alert feed |
| `Live Drive` | Displays real Drive activity and behavioural alerts |
| `Upload` | Analyzes network and document CSV files in memory |
| `Ask` | Answers questions about persisted alerts using the local LLM |

The `LIVE` view is processed-data replay, not live packet capture.

## Setup & Run Instructions

### Prerequisites

- Python 3.10 or newer
- GNU Make
- CICIDS 2017 CSV files for a fresh network pipeline run
- Google account and Cloud project for Drive monitoring
- LM Studio only if AI features are required

### 1. Clone the repository

```bash
git clone https://github.com/anjanbasnet00/ysj_hackathon_firewall.git
cd ysj_hackathon_firewall
```

### 2. Install dependencies

```bash
make setup
source .venv/bin/activate
```

Or run the commands directly:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Add CICIDS 2017

1. Download `MachineLearningCSV.zip` from the
   [official CICIDS page](https://www.unb.ca/cic/datasets/ids-2017.html).
2. Extract the CSV files into `data/raw/`.
3. Run:

```bash
make pipeline
make dashboard
```

Open `http://localhost:8501`.

### 4. Configure Google Drive

1. Create a project in [Google Cloud Console](https://console.cloud.google.com/).
2. Enable **Google Drive API**.
3. Enable **Google Drive Activity API**.
4. Configure the OAuth consent screen.
5. Add each demo Google account as a test user.
6. Create a **Web application** OAuth client.
7. Add `http://localhost:8501` as an authorized redirect URI.
8. Download the client JSON and rename it `credentials.json`.
9. Place it in the repository root.
10. Open `Live Drive` and select **Connect Google Drive**.

The first connection creates `token.json` for later reconnection.

Never commit:

```text
credentials.json
token.json
.env
```

### 5. Configure the local AI assistant

1. Open LM Studio.
2. Load `qwen2.5-coder-7b-instruct-mlx`, or update `config.py`.
3. Start the local OpenAI-compatible server on port `1234`.
4. Reload SecureWatch.

AI features are optional. The remaining dashboard works without LM Studio.

### 6. Clean generated pipeline files

```bash
make clean
```

## Recommended Demo Flow

Use a dedicated Google account and non-sensitive files:

```text
SecureWatch Demo/
├── Finance_Budget.xlsx
├── Payroll_Restricted.pdf
├── Employee_Records.pdf
├── Architecture_Diagram.png
└── Large_Demo_Archive.zip
```

Suggested presentation:

1. Open `Overview` and explain both detection layers.
2. Start the network replay in `LIVE`.
3. Show DDoS or port-scan alerts and their severity.
4. Open `Live Drive` and show the connected read-only account.
5. Perform 6–7 creates, edits, moves, or renames within 2 minutes.
6. Show the resulting bulk-activity alert.
7. Generate the local AI briefing.
8. Ask which IP addresses or attack types are most dangerous.
9. Finish with the privacy and read-only design.

Use a regular uploaded file larger than 10 MB for the large-file scenario.
Native Google Docs and Sheets may report a size of zero.

Complete Google OAuth before the presentation. Drive activity may be delayed or
grouped, so keep a short backup recording and the network replay ready.

## Usage Notes

- Run `make pipeline` before using replay, overview, or AI features.
- Uploaded CSV files are analyzed in memory.
- Live Drive events remain in the current Streamlit session.
- Tune thresholds in `src/securewatch/config.py`.
- Tune document scoring in `src/securewatch/detect/doc_rules.py`.
- Treat `src/securewatch/schemas.py` as the shared data contract.
- Run `git status --short` before committing.

## Limitations

- CICIDS 2017 may not represent every production network.
- Personal Drive has no department or file-sensitivity metadata.
- The Drive connector does not receive source IP addresses.
- File size is not the same as bytes transferred.
- Native Google files may report a size of zero.
- Personal Drive does not provide dependable download audit events.
- Drive activity may be delayed or grouped.
- Permission changes do not yet have a dedicated risk rule.
- Live Drive events are not persisted or merged into the main replay.
- The AI assistant does not analyze in-memory Drive events.
- No dashboard authentication or access control is implemented.
- Automated test coverage is not yet complete.

## Next Steps

- [ ] Persist live Drive events and alerts
- [ ] Merge network and Drive alerts into one real-time timeline
- [ ] Include live Drive alerts in the AI context
- [ ] Add external-sharing and permission-change rules
- [ ] Add controlled file classifications
- [ ] Add automated tests
- [ ] Add dashboard authentication
- [ ] Add Google Workspace audit-log support
- [ ] Add email or Slack notifications
- [ ] Package the application with Docker

## Demo-Ready Checklist

- [ ] `make pipeline` completes successfully
- [ ] Dashboard starts without errors
- [ ] Network alerts appear in `LIVE` and `Overview`
- [ ] Google OAuth reconnects with `token.json`
- [ ] Drive activity appears in `Live Drive`
- [ ] Rapid Drive actions trigger the bulk rule
- [ ] LM Studio answers one example question
- [ ] Backup recording and hotspot are ready
- [ ] Demo works without Drive or AI
- [ ] No secrets, datasets, or personal files are staged in Git
