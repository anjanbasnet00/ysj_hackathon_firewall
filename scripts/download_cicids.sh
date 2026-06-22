#!/usr/bin/env bash
# Helper for getting the REAL CICIDS 2017 dataset into data/raw/.
#
# The official UNB site (https://www.unb.ca/cic/datasets/ids-2017.html) now
# requires filling a short form before it gives you the download link, so it
# can't be fully automated. Two reliable options:
#
#   OPTION A — Official (recommended for credibility with judges)
#     1. Open: https://www.unb.ca/cic/datasets/ids-2017.html
#     2. Fill the form -> you get a download page
#     3. Download "MachineLearningCSV.zip" (~225 MB)
#     4. Unzip and move the *.csv files into data/raw/
#
#   OPTION B — Kaggle mirror (needs a free Kaggle account + API token)
#     pip install kaggle
#     # put kaggle.json in ~/.kaggle/  (from Kaggle > Account > Create API Token)
#     kaggle datasets download -d cicdataset/cicids2017 -p data/raw --unzip
#
# Until then, you can develop & demo against the realistic sample:
#     python scripts/make_sample_cicids.py
set -euo pipefail
echo "See the comments in this script — CICIDS 2017 requires a manual form/download."
echo "For now, generating the realistic sample so you're unblocked:"
cd "$(dirname "$0")/.."
python scripts/make_sample_cicids.py
