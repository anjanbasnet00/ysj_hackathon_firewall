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
# Once the *.csv files are in data/raw/, run:  make pipeline
set -euo pipefail
echo "CICIDS 2017 requires a manual form/download — see the comments in this script."
echo "Drop the unzipped *.csv files into data/raw/, then run: make pipeline"
