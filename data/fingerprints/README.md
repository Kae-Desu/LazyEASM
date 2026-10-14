# Bundled fingerprint data

Snapshot used when no newer download exists in `db/fingerprints/`
(LazyEASM refreshes that copy weekly; see `utils/fingerprints.py`).

| File | Source | License |
|------|--------|---------|
| `technologies.json`, `categories.json` | [enthec/webappanalyzer](https://github.com/enthec/webappanalyzer) (`src/technologies/*.json`, `src/categories.json`), the community-maintained continuation of the Wappalyzer fingerprints. Only the fields used for detection are kept | GPL-3.0 |
| `jsrepository.json` | [RetireJS/retire.js](https://github.com/RetireJS/retire.js) (`repository/jsrepository.json`) | Apache-2.0 |

Snapshot taken 2026-10-14 from webappanalyzer `eea872af449e207e055398f7369d11ee48c8ea03`
and retire.js `0b660fba06adebbcba027f2eb621cdb4fd6c2583`.

Regenerate with `python -m utils.fingerprints --bundle data/fingerprints`.
