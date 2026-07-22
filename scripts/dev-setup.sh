#!/usr/bin/env bash
# One-shot developer environment setup.
set -euo pipefail
python -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -U pip
pip install -e '.[dev]'
pre-commit install || true
echo "[*] ready. Try: vantage version && make check"
