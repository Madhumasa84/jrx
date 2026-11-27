PYTHON ?= $(shell which .venv/bin/python 2>/dev/null || which python3 2>/dev/null || which python)

.PHONY: test policy-test eval-test lint format bench-deterministic

test: policy-test eval-test
	$(PYTHON) -m pytest

# JRX-01 lives outside tests/ (normal discovery omits it) and is run explicitly.
eval-test:
	$(PYTHON) -m pytest eval/jrx-01
	$(PYTHON) -B -m benchmarks.workloads --self-test

policy-test:
	$(PYTHON) -m jev_reflex policy test --config reflex.example.yaml

lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .

format:
	$(PYTHON) -m ruff format .

bench-deterministic:
	$(PYTHON) -B benchmarks/run.py --backend deterministic --verify-hashes --skip-latency --baseline benchmarks/results/v0.2.0-step3-deterministic.json --fail-on-regression
