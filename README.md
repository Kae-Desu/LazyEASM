# LazyEASM

External Attack Surface Management (EASM): discover what you expose on the internet, find what is vulnerable or misconfigured, and keep watching it.

## Highlights

- **Discovery** - Subdomains from certificate transparency, passive DNS sources and DNS brute force; IPs and CIDRs. A submitted domain is explored fully; a submitted subdomain is scanned on its own, so access to one host never turns into scanning a whole organization
- **Scanning** - Open ports and services (Nmap), 7,600+ web technologies with versions, JavaScript libraries (Retire.js), directory discovery on demand
- **Vulnerabilities, prioritized** - CVEs matched to exact versions, ranked by real-world exploitation (CISA Known Exploited Vulnerabilities, EPSS) instead of CVSS alone
- **Security findings** - Exposed `.git`/`.env` and similar files, weak TLS, missing security headers, internet-exposed databases and admin services, subdomain takeovers, and hostnames pointing at servers that no longer serve them
- **Continuous monitoring** - Up/down, new subdomains, certificate expiry and replacement, technology changes, page appearance changes (screenshots), all recorded in a change history
- **Web screenshots** - Every web service captured in an isolated headless browser, so login portals, default pages and parked domains stand out
- **Triage** - One findings list across all assets, most urgent first; mark findings fixed, accepted or false positive in bulk; resolved findings close themselves on rescan
- **Alerts and export** - Discord, Slack, email or any webhook, including when LazyEASM itself stops scanning or its disk fills up; CSV/JSON export; optional AI explanation of each CVE (Gemini, Claude, OpenAI or a local model)
- **Install once and forget** - Configured from the dashboard, encrypted (HTTPS) out of the box, self-updating detection data, daily backups

## Quick start

### Docker (recommended)

```bash
git clone https://github.com/Kae-Desu/LazyEASM.git
cd LazyEASM
./start.sh                    # installs Docker if missing (Debian/Ubuntu, run with sudo)
```

Open **https://&lt;server&gt;:10002** (or `https://localhost:10002`). The image includes a headless browser for screenshots (about 400 MB).

### Native (Linux)

```bash
git clone https://github.com/Kae-Desu/LazyEASM.git
cd LazyEASM
sudo ./start.sh --service     # installs dependencies, runs LazyEASM as a systemd service
```

Open the address it prints (**https://&lt;server&gt;:10001**). The service starts at boot, restarts if it fails, and runs as the user who owns the LazyEASM folder (clone it as a normal user, not as root). It also sets up what web screenshots need, including the AppArmor rule Ubuntu 23.10+ requires for Chromium's sandbox. To upgrade: `git pull && sudo ./start.sh --service`.

`./start.sh --native` runs LazyEASM in the foreground instead (until you stop it), e.g. to try it out.

<details>
<summary>Ubuntu 23.10+ with --native or a manual install: allow Chromium's sandbox</summary>

Ubuntu blocks the sandbox Chromium uses, so web screenshots fail. Run once as root, replacing `lazyeasm` with the user LazyEASM runs as (`--service` does this for you):

```bash
cat > /etc/apparmor.d/lazyeasm-chromium <<'EOF'
abi <abi/5.0>,
include <tunables/global>
profile lazyeasm-chromium /home/lazyeasm/.cache/ms-playwright/chromium_headless_shell-*/chrome-headless-shell-linux64/chrome-headless-shell flags=(unconfined) {
  userns,
}
EOF
apparmor_parser -r /etc/apparmor.d/lazyeasm-chromium
```

This allows only that program; the rest of the system keeps the restriction. Docker installs do not need it.
</details>

### First login

1. On first start LazyEASM prints a **one-time setup code** (in the `./start.sh` output; later also in `./start.sh --logs`, or `journalctl -u lazyeasm` for the service).
2. The dashboard uses a self-signed HTTPS certificate, so the browser warns once. In the warning's certificate details, check that the SHA-256 fingerprint matches the one printed when LazyEASM starts, then accept it.
3. The browser opens **Create your account**: enter the setup code, choose a username and password (12+ characters). The code only works once; whoever reaches a fresh install without it cannot claim it.
4. Add targets on the **Scans** page.

Lost your password? Put `ADMIN_PASS=<new password>` in `.env` and restart LazyEASM (`sudo systemctl restart lazyeasm`, or `./start.sh` for Docker); it is stored hashed and removed from the file.

| `start.sh` | |
|---|---|
| `./start.sh` | Start with Docker (default) |
| `sudo ./start.sh --service` | Install or upgrade the native systemd service (`--remove-service` removes it, keeping your data) |
| `./start.sh --native` | Start without Docker, in the foreground |
| `./start.sh --stop` | Stop the Docker containers |
| `./start.sh --logs` | Follow the Docker logs |
| `./start.sh --clean` | Remove the Docker containers, images and volumes |

<details>
<summary>Manual installation</summary>

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m playwright install --with-deps chromium   # screenshots (optional)
sudo apt install nmap                                # or: brew install nmap
cp .env.example .env    # secrets are generated on first start; TLS_MODE=self-signed is preset
python run.py
```
</details>

## Using LazyEASM

| Page | What it is for |
|---|---|
| **Overview** | Headline numbers (open findings by severity, known-exploited CVEs, assets, certificates), riskiest assets, most widespread issues, recent changes |
| **Assets** | Every asset with a screenshot thumbnail; search, filter (type, status, risk, certificate, technology) and sort. Each asset has its own page: findings and CVEs, technologies, ports, screenshots, directories, history; deep scan and delete |
| **Findings** | Every CVE and security finding across assets, most urgent first. Filter, open an issue on every host it affects, and set status (fixed, accepted, false positive) for many at once |
| **Changes** | Everything that changed, by day: new assets, up/down, ports, technologies, certificates, page appearance, findings |
| **Scans** | Add targets, see the worker and every queued or running job, switch monitoring on/off, run any check now |
| **Settings** | API keys, AI provider, notifications, discovery and screenshots, check intervals and thresholds, system alerts, backups, password and HTTPS status. Changes apply without a restart |

**What gets scanned**: a domain you submit (`example.com`) is explored: its subdomains are found, scanned and monitored. A subdomain or IP you submit is scanned on its own; to explore its whole domain, use *Expand* on its page or submit the domain. Only scan what you are authorized to test.

**Priorities**: P1 = known to be exploited in the wild (CISA KEV), P2 = likely to be exploited soon (EPSS >= 10%), P3 = high CVSS (>= 7.0) without an exploitation signal, P4 = everything else.

## HTTPS

New installs serve the dashboard over HTTPS with a certificate LazyEASM generates and renews itself (like Wazuh or Proxmox). Set `TLS_MODE` in `.env`:

| `TLS_MODE` | |
|---|---|
| `self-signed` | Default for new installs. The browser warns once; compare the fingerprint (shown at startup and in Settings > Account). Add names or IPs with `TLS_HOSTNAMES` (Docker: `PUBLIC_IP`) |
| `custom` | Your own certificate (`TLS_CERT_FILE`, `TLS_KEY_FILE`), e.g. Let's Encrypt or a company CA. No warning |
| `off` | Plain HTTP, for use behind a reverse proxy. Installs from before this setting stay on HTTP until it is set |

**Behind a reverse proxy** (nginx, Caddy, Traefik...): set `TLS_MODE=off`, make LazyEASM reachable only from the proxy (`HOST=127.0.0.1`; Docker: publish `"127.0.0.1:10002:10001"`), have the proxy send `X-Forwarded-For/Proto/Host`, and set `TRUST_PROXY=true` and `FORCE_HTTPS=true`.

If the dashboard is ever opened over plain HTTP from another machine, it shows a "Not encrypted" warning.

## Backups

- **Automatic**: a copy of the database every day in `db/backups/` (newest 7 kept), and one before an upgrade changes the database. Settings > Backup to change it.
- **On demand**: Settings > Backup > *Back up now*, or *Download backup* (a zip; optionally with screenshots and the `.env` secrets; asks for your password again).
- **Copy `db/backups/` off the server** as well (rsync, your backup tool): a lost disk takes local backups with it.
- **Restore** with LazyEASM stopped (Docker: `docker compose run --rm lazyeasm python -m utils.backup ...`). The current database is kept as a `pre-restore` copy first.

```bash
python -m utils.backup list
python -m utils.backup restore db/backups/<file>.db
python -m utils.backup restore lazyeasm-backup.zip --with-env    # also restore .env
```

## Configuration

`.env` is created by the installer with random secrets; [.env.example](.env.example) documents every key. Most settings (API keys, AI provider, notifications, discovery, check intervals, minimum CVSS, backups) are changed in the dashboard. Optional keys that improve results:

| Key | Effect |
|---|---|
| `NVD_API_KEY` | Faster CVE lookups (higher NVD rate limit) |
| `SECURITYTRAILS_API_KEY`, `OTX_API_KEY`, `CERTSPOTTER_API_KEY` | More subdomain sources / higher quota |
| `GEMINI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` (`AI_PROVIDER`) | AI explanation of CVEs (`openai_compatible` + `AI_BASE_URL` for a local model) |
| `DISCORD_WEBHOOK_URL`, `SLACK_WEBHOOK_URL`, `NOTIFY_WEBHOOK_URL`, `SMTP_*` | Alerts; every configured channel gets every alert |

Full reference: [TECHNICAL.md > Configuration reference](TECHNICAL.md#configuration-reference).

## Good to know

- One instance per database (SQLite, one background worker); see TECHNICAL.md for the architecture.
- CVE matching needs a detected version. Detection reads the HTTP response; fingerprints that need a running browser (JavaScript, DOM) are not evaluated yet.
- CDN addresses (e.g. Cloudflare) are not port-scanned; their websites are still checked.
- Certificate transparency lookups use CertSpotter's free quota (set `CERTSPOTTER_API_KEY` for more) and crt.sh as a fallback, which is often overloaded; discovery continues with the other sources.
- Times are stored in UTC and shown in your browser's time zone.
- After logout a session token stays valid for up to 15 minutes; changing the password ends every session at once.

## Documentation

- [TECHNICAL.md](TECHNICAL.md) - architecture, scanning pipeline, detection details, data and retention, security design, configuration and API reference, development and testing
- Tests: `python -m tests`

## License

Copyright (c) 2026 楓

LazyEASM is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See [LICENSE](LICENSE) for the full text.

In short: you can use, modify and self-host LazyEASM freely. If you modify it and let other people use it over a network (for example, as a hosted service), you must make your modified source code available to those users under the same license.

Releases published before this change remain available under the MIT License.

## Acknowledgments

- [enthec/webappanalyzer](https://github.com/enthec/webappanalyzer), the community-maintained continuation of the Wappalyzer fingerprints (GPL-3.0), and [Retire.js](https://github.com/RetireJS/retire.js) (Apache-2.0); see [data/fingerprints/README.md](data/fingerprints/README.md)
- [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) by EdOverflow and contributors for subdomain takeover fingerprints (CC BY 4.0, see [data/README.md](data/README.md))
- [NVD](https://nvd.nist.gov/), the [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [FIRST EPSS](https://www.first.org/epss/)
- CertSpotter (SSLMate), crt.sh, SecurityTrails, HackerTarget, the Wayback Machine and AlienVault OTX for discovery data
- [Nmap](https://nmap.org/), [Dirsearch](https://github.com/maurosoria/dirsearch) and [Playwright](https://playwright.dev/)
