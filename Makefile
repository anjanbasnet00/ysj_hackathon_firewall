.PHONY: setup sample docs pipeline dashboard clean

# generate a realistic CICIDS-shaped sample so the network layer works
# without the 225MB download (swap in real CSVs in data/raw/ any time)
sample:
	PYTHONPATH=src python scripts/make_sample_cicids.py

# one-time: create venv and install deps
setup:
	python3 -m venv .venv
	. .venv/bin/activate && pip install -U pip && pip install -r requirements.txt
	@echo "Activate with: source .venv/bin/activate"

# generate + score document logs only (NO dataset download needed)
docs:
	PYTHONPATH=src python -m securewatch.pipeline --docs-only

# full pipeline (needs CICIDS 2017 CSVs in data/raw/)
pipeline:
	PYTHONPATH=src python -m securewatch.pipeline

# launch the dashboard
dashboard:
	PYTHONPATH=src streamlit run dashboard/app.py

clean:
	rm -f data/processed/*.parquet data/interim/* models/*.pkl
