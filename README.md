# 🛡️ SecureWatch

Unified cyber-defence dashboard for the Cyber Defence Innovation Hackathon
(Team Apex Cybernetics). Two correlated detection layers in one Streamlit view:

| Layer | What it watches | Tech |
|-------|-----------------|------|
| **1. Network Monitor** | Port scans, DDoS, brute force — anomaly detection on CICIDS 2017 | Isolation Forest (scikit-learn) |
| **2. Document Monitor** | Off-hours access, bulk downloads, exfiltration | Synthetic logs + behavioural rules |

## Quickstart

```bash
make setup                 # create venv + install deps  (once)
source .venv/bin/activate

# Fastest path — works with ZERO downloads (uses a CICIDS-shaped sample):
make sample                # generate realistic sample network data in data/raw/
make pipeline              # clean + train + score both layers, build alert feed
make dashboard             # open the Streamlit dashboard

# Document layer only (no network data at all):
make docs
```

## Two ways data enters the dashboard
1. **Demo tab** — reads the pre-built parquet in `data/processed/`. Fast and
   reliable; use this for the live judged demo.
2. **Upload tab** — drop a network-flow CSV and/or a document-access CSV in the
   browser; it's analysed live via `securewatch/service.py` (the *same* cleaning
   and scoring code as the batch pipeline). Great "try it yourself" moment for judges.

## Getting the REAL network dataset (CICIDS 2017)
The full pipeline already runs on the generated sample. To use the real data:
1. Download "MachineLearningCSV.zip" from https://www.unb.ca/cic/datasets/ids-2017.html
   (the site requires a short form — see `scripts/download_cicids.sh` for a Kaggle alternative)
2. Unzip the `.csv` files into `data/raw/`  (you can delete `sample_cicids2017.csv`)
3. `make pipeline` — same command, no code changes needed

## Architecture / data flow

```
                ┌─────────────────────────────────────────────┐
 data/raw/  ──► │ ingest.load_network → preprocess.clean_network│
 (CICIDS)       │              ↓ network_events.parquet          │
                │ detect.train_network (Isolation Forest)        │──┐
                └─────────────────────────────────────────────┘  │
                ┌─────────────────────────────────────────────┐  │  pipeline.build_alerts
 (synthetic) ──►│ ingest.generate_doc_logs → detect.doc_rules   │──┤  correlates both layers
                │              ↓ document_scored.parquet         │  │        ↓
                └─────────────────────────────────────────────┘  │  alerts.parquet
                                                                  │        ↓
                                                          dashboard/app.py (Streamlit + Plotly)
```

Everything passes between stages as **parquet files in `data/processed/`**, whose
columns are defined ONCE in [`src/securewatch/schemas.py`](src/securewatch/schemas.py)
— the **data contract**. Agree on that file and the whole team works in parallel.

## Repo layout
```
src/securewatch/
  config.py        # all paths + tunables
  schemas.py       # THE DATA CONTRACT — column definitions
  ingest/          # load_network.py, generate_doc_logs.py
  preprocess/      # clean_network.py
  detect/          # train_network.py (Isolation Forest), doc_rules.py
  pipeline.py      # run everything + correlate
dashboard/app.py   # Streamlit UI
notebooks/         # exploration only
data/              # raw / interim / processed  (gitignored)
models/            # saved .pkl
```

## Who owns what (maps to the team brief)
- **M1 ML Engineer** → `detect/train_network.py`, `preprocess/clean_network.py` features
- **M2 Data Engineer (you)** → `ingest/generate_doc_logs.py`, `detect/doc_rules.py`, `pipeline.py`, schemas
- **M3 Frontend** → `dashboard/app.py`
- **M4 Security Analyst** → tune thresholds in `doc_rules.py` + severity bands
- **M5 Presenter/Docs** → this README, slides, demo script
