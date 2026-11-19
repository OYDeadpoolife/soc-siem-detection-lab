# Convenience targets. Every target only runs commands shown here.
.PHONY: datasets detections test bulk lint

datasets:    ## re-create the synthetic datasets (identical every time)
	python3 tools/generate_synthetic_logs.py --out-dir datasets

detections:  ## run the Python reference detections on the datasets
	python3 detections/reference_detections.py --datasets datasets

test:        ## run the whole test suite
	python3 -m pytest -v

bulk:        ## build Elasticsearch _bulk files in build/bulk (nothing is sent)
	python3 tools/make_bulk_files.py

lint:        ## ShellCheck and shfmt for the loader script
	shellcheck -x scripts/load_to_elasticsearch.sh
	shfmt -d -i 4 -ci scripts/load_to_elasticsearch.sh
