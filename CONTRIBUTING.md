# Contributing

Issues and pull requests are welcome. Security problems: [SECURITY.md](SECURITY.md), not a public issue.

## Development setup

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m domin import path/to/reports     # optional: old domin's *_YYMMDD_results.csv files
.venv/bin/uvicorn --factory domin.web:create_app --port 8000
.venv/bin/python -m domin worker                     # runs queued scans
```

- Windows: `.venv\Scripts\python` instead of `.venv/bin/python`.
- Local settings through the environment ([docs/CONFIGURATION.md](docs/CONFIGURATION.md)), e.g. `DOMIN_DB`.
- First user: `python -m domin user-add you --role admin --own`.
- Scans need nmap and amass on the PATH for the posture and amass stages; everything else works without them.
- Screenshots with made-up data: `python scripts/screenshots.py`.

## Tests and lint
- Full suite (no network or API key needed): `python -m pytest`
- Lint: `ruff check domin tests scripts`
- Run both before a pull request; add or update tests for the change. Tests use documentation addresses and names
  (192.0.2.0/24, 2001:db8::/32, example.com) and harmless inputs.

## Commits and changes
- One topic per commit; the subject says what changed, in the imperative or as a short title (no prefix scheme
  required).
- Every user-visible change gets an entry at the top of [CHANGES.md](CHANGES.md): a `## YYYY-MM-DD: title` heading,
  the facts as bullets, and a `Rollback:` line.
- New dependencies: pin the exact version in `deploy/requirements.txt` and run `python scripts/hash_requirements.py`;
  `pyproject.toml` keeps the minimum versions.
- Keep the security properties of [docs/HARDENING.md](docs/HARDENING.md): no inline script, no third-party assets,
  every scan target checked, no privileged commands from the app.

## License
By contributing you agree that your contributions are licensed under the MIT License ([LICENSE](LICENSE)).
