# Changelog

All notable changes to LazyEASM are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Versions before 1.0.0 were not tagged; their dates and contents come from the commit history.

## [Unreleased]

## [1.0.0] - 2026-10-25

First stable release.

### Added

- **Prioritization by real-world exploitation**: every CVE gets a priority from P1 to P4 based on the CISA Known Exploited Vulnerabilities catalog and FIRST EPSS, refreshed daily.
- **CPE-based CVE matching** against NVD for exact technology versions, with a finding lifecycle (open, fixed, accepted, false positive) and automatic closing when an issue is no longer detected.
- **Security findings**: subdomain takeover and dangling CNAME detection, exposed files (`.git`, `.env`, `.htpasswd` and others), weak or invalid TLS, missing security headers, directory listings, internet-exposed databases and admin services, and hostnames pointing at servers that no longer serve them.
- **Technology detection** with the maintained Wappalyzer-format fingerprints (enthec/webappanalyzer, 7,600+ technologies, refreshed weekly) and JavaScript library detection with Retire.js version ranges.
- **Broader subdomain discovery**: CertSpotter and crt.sh certificate transparency, HackerTarget, the Wayback Machine, AlienVault OTX, SecurityTrails and optional DNS brute force.
- **Web screenshots** of every web service in a headless browser with request filtering, with visual change detection.
- **Change history** per host (new assets, up/down, ports, technologies, certificates, page appearance, findings) and served-certificate tracking with expiry alerts.
- **Dashboard pages**: Overview, Assets, asset detail, Findings (one triage list across all assets with bulk status changes), Changes and Scans.
- **Notifications** to Slack, any webhook and email in addition to Discord; CSV and JSON export.
- **AI explanations** of CVEs with Gemini, Anthropic, OpenAI or any OpenAI-compatible endpoint, including local models.
- **HTTPS out of the box** with a self-signed certificate generated and renewed by LazyEASM, or your own certificate.
- **Backups**: daily and pre-upgrade database snapshots, on-demand download, and a command-line restore.
- **System alerts** when the background worker stops or the disk fills up, also shown as a dashboard banner.
- **First-run setup in the browser**: the account is created with a one-time setup code printed at startup.
- **`sudo ./start.sh --service`** installs the native version as a systemd service that starts at boot and restarts on failure.
- `scripts/demo_seed.py` (fictional demo data, served without scanning) and `scripts/demo_capture.py` (README screenshots and GIF).
- Documentation: `TECHNICAL.md`, `SECURITY.md`, `CONTRIBUTING.md`, issue and pull request templates.

### Changed

- **License changed from MIT to the GNU Affero General Public License v3.0 (AGPL-3.0) in October 2026.** Copies obtained before the change remain licensed under the MIT License.
- Scoped scanning: a submitted subdomain or IP is scanned on its own and is no longer expanded to its whole domain; *Expand* explores the domain on request.
- The web app is served by a production WSGI server, and background work runs in a separate worker process with a heartbeat and crash recovery.
- Check intervals, minimum CVSS, DNS brute force, screenshots, backups and alert thresholds are dashboard settings applied without a restart.
- All timestamps are stored in UTC and shown in the viewer's time zone.
- Docker: `start.sh` uses Docker Compose v2 (falling back to v1), rebuilds the image on start, and keeps the HTTPS certificate fingerprint across container recreates.
- Dependencies are pinned to tested versions (Python 3.11 and 3.14).
- The interface is fully in English.

### Fixed

- Database connections are closed when a query fails; previously a full disk exhausted the worker's file descriptors and it did not recover after space was freed.
- Missed certificate expiry alerts, duplicate HTTP/HTTPS screenshots, false host-down results from Nmap host discovery, and checks re-running after every restart.
- Web screenshots on native installs not running as root (Chromium was never downloaded) and on Ubuntu 23.10+ (AppArmor).
- `start.sh` failing with "Permission denied" after a fresh clone, and on Ubuntu releases without Docker Compose v1.

### Security

- The admin password is stored as a scrypt hash; changing it signs out every session, and refresh-token reuse revokes all sessions.
- CSRF protection on every data-changing route; login rate limiting; debug mode off by default.
- No generated password is written anywhere at install time: the account is created in the browser with a one-time setup code.
- A warning is shown when the dashboard is opened over plain HTTP from another machine.

### Removed

- Keyword-based CVE search (replaced by CPE matching) and the unused `Parser.py`.
- The unmaintained python-Wappalyzer dependency.

## [0.2.0] - 2026-06-30

### Added

- Technologies and CVEs for standalone IP assets in the dashboard.
- Phase 2 directory discovery on every HTTP port, including for IP assets.

### Fixed

- Certificate expiry counts: expired certificates separated from expiring ones, counted per hostname, limited to known assets.
- Phase 2 port scans for IP assets and shared IPs.
- `.env` persistence across Docker rebuilds, and `.env` becoming a directory on fresh Docker installs.
- CVE matching returned to strict version matching.

## [0.1.0] - 2026-05-15

Initial version, released under the MIT License.

### Added

- Asset discovery from submitted domains, subdomains, IPs and CIDRs.
- Phase 1 scanning (ports with Nmap, technologies with Wappalyzer, CVE lookup), Phase 2 deep scans (all ports, directory discovery) and Phase 3 continuous monitoring (liveness, certificate transparency, technology re-scans).
- Dashboard with login, Discord notifications and AI explanations of CVEs.
- Docker and native installation with `start.sh`.

[Unreleased]: https://github.com/Kae-Desu/LazyEASM/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Kae-Desu/LazyEASM/releases/tag/v1.0.0
