# Bundled data

## takeover_fingerprints.json

Subdomain takeover fingerprints from [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)
by EdOverflow and contributors, licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

The file is included unmodified (fetched 2026-10-11). `utils/takeover_checker.py` uses only the
entries marked `"vulnerable": true` that have at least one CNAME pattern.

To update, replace the file with the latest `fingerprints.json` from the upstream repository and
run `tests/takeover_tests.py`.
