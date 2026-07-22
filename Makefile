.PHONY: help install dev test lint fmt check agent-check clean sample docs

help:
	@echo "Targets: install dev test lint fmt check agent-check sample docs clean"

install:
	pip install -e .

dev:
	pip install -e '.[dev]'

test:
	pytest -q

lint:
	ruff check .
	black --check .

fmt:
	ruff check --fix .
	black .

agent-check:
	find src/vantage/agent -name '*.js' -print0 | xargs -0 -n1 node --check && echo "agent JS OK"

check: lint agent-check test

sample:
	PYTHONPATH=src python3 -m vantage protocol synth sample-data/synthetic-session --label login

docs:
	@echo "Docs live in docs/ (Markdown + Mermaid). The KB can also auto-generate docs:"
	@echo "  vantage kb --db vantage_data/protocol.db docs"

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache vantage_data
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
