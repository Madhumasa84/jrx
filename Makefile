PYTHON ?= $(shell which .venv/bin/python 2>/dev/null || which python3 2>/dev/null || which python)

.PHONY: test policy-test lint format bench-deterministic

test: policy-test
	$(PYTHON) -m pytest

policy-test:
	$(PYTHON) -m jev_reflex policy test --config reflex.example.yaml

lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .

format:
	$(PYTHON) -m ruff format .

bench-deterministic:
	$(PYTHON) -B benchmarks/run.py --backend deterministic --verify-hashes --skip-latency --baseline benchmarks/results/v0.2.0-deterministic.json --fail-on-regression
