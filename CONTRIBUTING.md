# Contributing to LazyEASM

Thanks for your interest in improving LazyEASM. Bug reports, fixes, documentation and new detections are all welcome.

## Development setup

```bash
git clone https://github.com/Kae-Desu/LazyEASM.git
cd LazyEASM
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m playwright install chromium     # web screenshots (optional)
python main.py                            # web app and worker in one process
```

Python 3.11 or newer and Nmap are required. `python main.py` creates `.env` with fresh secrets on first start and prints a one-time setup code; open the printed address and create your account with it. [TECHNICAL.md](TECHNICAL.md) explains the architecture, the scanning pipeline and every setting.

To work on the dashboard without scanning anything, use the fictional demo data:

```bash
python scripts/demo_seed.py --serve       # http://127.0.0.1:10009, sign-in printed
```

## Tests

```bash
python -m tests          # the whole suite; add -v for test names
```

The tests use temporary databases and log folders, so running them on a live install leaves its data alone. Every change should keep the suite passing, and new behavior should come with tests (see the existing `tests/*_tests.py` files for the patterns: a temporary database, the Flask test client, mocked network calls).

## Code style

- Follow the style of the surrounding code: PEP 8 naming, lines up to about 120 characters, docstrings on public functions.
- Comments explain *why*, not what the next line does.
- Close every `get_db_connection()` in a `finally` block (the test suite checks the code base for this).
- Store timestamps in UTC with `utils/timeutil.py`.
- Keep authorization checks inside `token_required` in `main.py`, and protect every data-changing route with `csrf_protected`.
- Every operational setting should be changeable from the dashboard, so an install never needs editing files after setup.
- Never commit secrets, real scan results or data about hosts you do not own. Use reserved domains (`example.com`) and documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) in tests and examples.

## Proposing changes

1. For anything bigger than a small fix, open an issue first to discuss the idea.
2. Fork the repository and create a branch from `main`.
3. Make focused commits with clear messages: a short summary line, then what changed and why.
4. Run `python -m tests` and, for user-facing changes, try it in the dashboard (the demo data is enough for most UI work).
5. Update `README.md`, `TECHNICAL.md` and the `Unreleased` section of `CHANGELOG.md` when behavior or settings change.
6. Open a pull request and fill in the template.

Report security vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not in issues or pull requests.

## License

By contributing, you agree that your contributions are licensed under the [GNU Affero General Public License v3.0](LICENSE), like the rest of LazyEASM.
