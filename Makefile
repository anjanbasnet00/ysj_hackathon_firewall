.PHONY: setup pipeline dashboard clean

# one-time: create venv and install deps
setup:
	python3 -m venv .venv
	. .venv/bin/activate && pip install -U pip && pip install -r requirements.txt
	@echo "Activate with: source .venv/bin/activate"

# network layer: clean + train + score real CICIDS 2017 CSVs in data/raw/,
# then build the alert feed for the LIVE replay + Overview tabs.
pipeline:
	PYTHONPATH=src python -m securewatch.pipeline

# launch the dashboard (network replay + live Google Drive document layer)
dashboard:
	PYTHONPATH=src streamlit run dashboard/app.py

clean:
	rm -f data/processed/*.parquet data/interim/* models/*.pkl
