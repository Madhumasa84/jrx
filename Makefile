PYTHON ?= $(shell which .venv/bin/python 2>/dev/null || which python3 2>/dev/null || which python)

.PHONY: test policy-test lint format

test: policy-test
	$(PYTHON) -m pytest

policy-test:
	$(PYTHON) -m jev_reflex policy test --config reflex.example.yaml

lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .

format:
	$(PYTHON) -m ruff format .
