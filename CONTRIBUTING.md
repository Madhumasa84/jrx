# Contributing to JEV Reflex

Thank you for contributing to JEV Reflex.

## Development Workflow

1. Setup development environment:
   ```console
   python -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

2. Run tests and linting:
   ```console
   make test
   make lint
   ```

## Policy Changes & Regression Suite

JEV Reflex enforces strict stability and determinism over policy decisions.

A golden fixture regression suite lives in `tests/fixtures/policy_golden/` and is validated via `jrx policy test` (or `make policy-test`, run automatically during `make test`).

### Required Policy PR Invariant

**Any PR touching `reflex.example.yaml` or the policy engine (`src/jev_reflex/policy.py`) must include a fixture update in `tests/fixtures/policy_golden/` explaining the intended behavior change.**

If an intentional policy modification alters verdicts on known fixtures:
1. Update existing fixtures or add new ones reflecting the new intended verdict.
2. In the fixture's `notes` field and the PR description, explain why the verdict flipped and why this behavior change is intended.
3. Verify that `make test` passes with 0 failures before opening the PR.
