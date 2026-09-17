PYTHON ?= $(shell which .venv/bin/python 2>/dev/null || which python3 2>/dev/null || which python)

.PHONY: test lint format

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .

format:
	$(PYTHON) -m ruff format .
