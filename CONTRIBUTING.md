# Contributing to Vantage

Thank you for your interest! Vantage is an **observation-only** framework, and the
single most important contribution rule is that it stays that way.

## The observation-only contract (non-negotiable)

Contributions **must not** add the ability to *act on* a target. Specifically, no:

- `Interceptor.replace` or trampolines that alter target behaviour;
- `Memory.write*`, RWX patching, or byte patching of target code/data;
- network packet injection, replay, delay, drop, or modification;
- request/traffic generation aimed at the target;
- gameplay automation, bots, or cheats;
- anti-cheat / anti-tamper / packing / integrity / pinning bypass;
- cryptographic key extraction or decryption of data the runtime has not already
  decrypted for its own use.

CI and code review reject PRs that introduce any of the above. If you're unsure
whether something crosses the line, open a discussion first.

## Development setup

```bash
git clone https://github.com/emon5122/vantage
cd vantage
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pre-commit install
```

## Workflow

1. Fork and branch from `main` (`feat/…`, `fix/…`, `docs/…`).
2. Keep changes focused; add/extend tests under `tests/`.
3. Run the checks locally:
   ```bash
   make lint      # ruff + black --check
   make test      # pytest
   make check     # both
   ```
4. Update docs and `CHANGELOG.md` (Unreleased section) as needed.
5. Open a PR using the template; describe the observation-only impact.

## Coding standards

- **Python**: 3.9+, formatted with **black** (line length 120), linted with
  **ruff**. No third-party runtime deps in the offline core; put runtime deps
  behind optional extras.
- **JavaScript (agent)**: each hook is an independent IIFE registering into the
  `KS` namespace; must pass `node --check`. Read-only interceptors only.
- **SQL**: parameterised queries only; never string-format user input into SQL.
- Prefer clear evidence grading over cleverness; never emit a protocol detail you
  didn't observe.

## Tests

- Offline tests must not require a device or Frida.
- Use `vantage.protocol.synthetic` for spec-conformant test input; never commit
  captured data from a real target.

## Reporting security issues

See [SECURITY.md](SECURITY.md) — do not file security problems as public issues.

## License

By contributing, you agree that your contributions are licensed under the
[Apache-2.0](LICENSE) license.
