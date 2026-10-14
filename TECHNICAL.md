# LazyEASM technical reference

How LazyEASM works inside: architecture, the scanning pipeline, detection
details, data and retention, security design, configuration, API and
development notes. For installing and using LazyEASM, see [README.md](README.md).

- [Architecture](#architecture)
- [Scanning pipeline](#scanning-pipeline)
- [Continuous monitoring](#continuous-monitoring)
- [Detection details](#detection-details)
- [Findings and prioritization](#findings-and-prioritization)
- [Data, storage and retention](#data-storage-and-retention)
- [Security design](#security-design)
- [HTTPS internals](#https-internals)
- [Backups internals](#backups-internals)
- [Configuration reference](#configuration-reference)
- [API reference](#api-reference)
- [Project structure](#project-structure)
- [Development and testing](#development-and-testing)
- [Platform notes](#platform-notes)
- [Data sources and licenses](#data-sources-and-licenses)

---

## Architecture

`run.py` (used by Docker and `start.sh`) prepares the database and starts two processes:

| Process | Command | Does |
|---|---|---|
| Web | `main.py` with `LAZYEASM_ROLE=web` | Dashboard and API. HTTPS via [cheroot](https://github.com/cherrypy/cheroot) when `TLS_MODE` is on, plain HTTP via [waitress](https://docs.pylonsproject.org/projects/waitress/) otherwise |
| Worker | `worker.py` | Every queue (input discovery, Phase 0/1/2, manual check runs) and the Phase 3 monitors |

Before starting them, `run.py`:

1. Backs up the database if the database setup code changed since the last start (`pre-upgrade` snapshot, see [Backups](#backups-internals))
2. Runs the schema setup and migrations (`modules/InitDB.py`), then records the schema signature
3. Hashes `ADMIN_PASS` from `.env` into the database if present, and removes it from the file
4. Prepares the HTTPS certificate when `TLS_MODE` is on and prints its fingerprint; refuses to start if HTTPS is enabled but cannot be set up

Runtime behaviour:

- Both processes share the SQLite database (WAL mode, busy timeout). Submitting assets inserts a job in `scan_queue`; the worker claims it atomically. Restarting the web process never interrupts a scan.
- Jobs a crash left in `processing` are re-queued when the worker starts.
- If either process exits, `run.py` stops the other and exits non-zero, so Docker's restart policy or systemd restarts LazyEASM.
- The worker writes a heartbeat (`worker_heartbeat` setting) every 15 seconds; it counts as down after 60 seconds without one. A clean stop clears it immediately. `/health` reports the database, the worker and each component (`phase0_worker`, `discovery_worker`, `phase1_worker`, `phase2_worker`, `phase3_worker`).
- Run exactly one worker per database.
- `python main.py` (no `LAZYEASM_ROLE`) runs web and worker in one process for local development.

### Scheduler

Each Phase 3 check has its own thread in the worker. Every few seconds it re-reads the enabled flag (`phase3_enabled`) and its interval from the settings table, so dashboard changes apply without a restart. A check runs when its interval has passed since it last **started**; that start time is stored (`monitor_last_run_<name>`), so restarting the worker does not re-run every check, and a manual run counts as a run. A per-check lock keeps a manual run from overlapping the scheduled one.

`POST /api/phase3/<name>/check` queues a manual run (`202` with a `job_id`; an already queued run of the same check is reused); `GET /api/jobs/<id>` reports `pending` / `processing` / `completed` / `failed` with the error.

---

## Scanning pipeline

```
submit targets ──► input_discovery job ──► Phase 0: discovery ──► Phase 1 queue ──► Phase 1 scan
   (web)              (scan_queue)            (worker)              (scan_queue)      (worker, 4 slots)
                                                                                         │
                         Phase 2 deep scan (on demand) ◄── asset page / API ─────────────┘
```

### Input and scope

`utils/parsing.py` sorts input into domains, subdomains, IPs and CIDRs (CIDRs are capped in size). Scope rules (`modules/ExpandAsset.py`):

- A **domain** (`example.com`) is expanded: subdomain discovery, then every result is scanned and the domain is monitored (CT logs, discovery).
- A **subdomain** is scanned on its own (also when typed in the domain field). Its parent is stored with `domain_asset.expand = 0`: a container that is not listed as an asset, not scanned, not liveness- or takeover-checked and not used for discovery. The subdomain page offers *Expand*, which queues the domain like a submitted one (`POST /api/domains/<id>/expand`, with a confirmation about authorization).
- **IPs and CIDRs** are scanned as given.

### Phase 0: discovery (expanded domains)

- Sources (`utils/subdomain_discovery.py`), each isolated so a failing or rate-limited source never stops the others:
  - Certificate transparency: CertSpotter first (optional `CERTSPOTTER_API_KEY`); crt.sh only when CertSpotter fails, one query per domain (`exclude=expired`), and a 30-minute cooldown after a crt.sh error (`crtsh_cooldown_until`)
  - SecurityTrails (`SECURITYTRAILS_API_KEY`), HackerTarget, Wayback Machine, AlienVault OTX (`OTX_API_KEY`)
  - DNS brute force with `data/subdomain_wordlist.txt` plus permutations of known names (`api` -> `api-dev`, `dev-api`, `api2`...), skipped on wildcard DNS; `DNS_BRUTEFORCE` toggles it
- Names are normalized and kept only on a label boundary (`notexample.com` is not a subdomain of `example.com`).
- DNS resolution and ping run in parallel; shared hosting / CDN addresses (Cloudflare and others) are flagged.

### Phase 1: scan (every new asset)

`modules/phase1_runner.py`, per asset:

1. **Ports** - Nmap top 100 with `-sV -T3` on non-CDN IPs (CDN addresses are skipped). If host discovery reports a live host down (unprivileged Nmap only probes TCP 80/443; rate-limited hosts drop probes), the scan is retried once with `-Pn` instead of recording "no open ports".
2. **Web technologies and CVEs** - every HTTP(S) service, see [Detection details](#detection-details)
3. **Exploit intelligence** - CISA KEV and EPSS for new CVEs
4. **Misconfiguration checks** for the asset
5. **Screenshot** of its web services
6. **Served certificates** of its HTTPS services

### Phase 2: deep scan (on demand)

`utils/phase2_worker.py` / `modules/phase2_dirsearch.py`: Nmap on all 65535 ports (`-T3`; skipped for CDN addresses) and Dirsearch (25 threads, non-recursive) on the hostname. Queued from the asset page; pending scans can be cancelled. A deep-scan phase lock older than 24 hours is treated as left behind by a crash and cleared.

---

## Continuous monitoring

| Check | Default interval | Does |
|---|---|---|
| `liveness` | 5 min | ICMP ping, then TCP 80/443/22; up/down transitions recorded and notified (first check is not a transition). Covers expanded domains, subdomains and IPs submitted directly |
| `ctlogs` (Certificates & CT logs) | 6 h | New subdomains of expanded domains from CT logs (queued for discovery); the certificate every HTTPS service presents; expiry alerts |
| `wappalyzer` (technology re-scan) | 24 h | Re-detects technologies and CVEs on every up web service (including IPs submitted directly) |
| `takeover` | 24 h | Follows CNAME chains; flags services known to allow takeover (NXDOMAIN or unclaimed-page fingerprint) and dangling CNAMEs |
| `intel` | 24 h | Refreshes CISA KEV and EPSS for every CVE (CVE IDs only); alerts when an open CVE becomes known exploited |
| `misconfig` | 24 h | Web, TLS, header and risky-port checks; unserved hostnames |
| `discovery` | 24 h | All discovery sources for every expanded domain; new subdomains are queued |
| `screenshots` | 24 h | Captures every web service |
| `maintenance` | 24 h | Prunes change history (365 days) and finished queue items (90 days), refreshes fingerprint data (weekly), daily backup |

Intervals and the minimum CVSS are edited in Settings > Schedule & Thresholds (`*_interval_*` and `cve_min_cvss` in the settings table, validated ranges). Installs still on the old hourly CT default were moved to 6 hours once.

---

## Detection details

### Technologies (`utils/techdetect.py`)

- Fingerprints: [enthec/webappanalyzer](https://github.com/enthec/webappanalyzer), the community-maintained continuation of the Wappalyzer fingerprints (7,600+ technologies, 466 with a CPE).
- The page is fetched once (redirects followed, certificate not verified: the misconfiguration check reports invalid certificates; up to 2 MB) and parsed with the standard library HTML parser.
- Matched fields: response headers, cookies, meta tags, script URLs, inline scripts, HTML, visible text and the URL. Fingerprints that need a running browser (`js`, `dom`, `xhr`) or other lookups (`dns`, `css`, `robots`, `certIssuer`) are not evaluated.
- Pattern syntax: regex (case-insensitive) with `\;version:` templates (`\1` back-references and `\1?a:b` ternaries) and `\;confidence:`. JavaScript-only regex syntax is converted (`(?<name>` -> `(?P<name>`); patterns Python cannot compile are skipped individually.
- `implies`, `excludes`, `requires` and `requiresCategory` follow Wappalyzer's semantics. Versions are collected from every match; the most specific one wins.
- Fingerprint data (`utils/fingerprints.py`): a snapshot ships in `data/fingerprints/`; maintenance downloads a fresh copy into `db/fingerprints/` once a week (validated: minimum technology and library counts, expected format; written atomically). The snapshot is used when no valid download exists. 21 technologies renamed since the previously bundled data (e.g. "Apache" -> "Apache HTTP Server") were renamed in the database once, so rescans do not log false changes.

### JavaScript libraries (`utils/jslibs.py`)

- [Retire.js](https://github.com/RetireJS/retire.js) repository: libraries are found by script URL and file name, then by the content of inline scripts and of up to 8 script files the page loads (1.5 MB each), and by SHA-1 hash. Script files are fetched through the screenshot request filter (public addresses or the asset's own IPs only).
- Versions from the file content win over versions from the URL. The loose version pattern's file suffixes are removed (`1.12.4.min` -> `1.12.4`); comparison follows Retire.js (numeric parts above text parts, so `1.9.0b1` < `1.9.0`).

### CVE matching

- **JavaScript libraries Retire.js tracks** use its exact affected version ranges instead of NVD. CVSS and description are looked up in NVD by CVE ID (cached a week); when unavailable, the Retire.js severity maps to a score (critical 9.0, high 7.5, medium 5.0, low 3.0). Advisories without a CVE use their GitHub advisory ID (linked to GitHub; not sent to EPSS/KEV).
- **Everything else**: NVD API 2.0 with a versioned CPE match string, keeping only CVEs whose configuration covers the exact version (`modules/CVEmatch.py`). Cached 24 hours. Products NVD lists under two vendor names (nginx: `nginx` / `f5`; IIS) are queried under both.
- `NVD_API_KEY` raises the NVD rate limit. A failed lookup never closes existing findings.

### Misconfiguration checks (`utils/misconfig_checker.py`)

- Exposed `.git`, `.env`, `.htpasswd` (high), Apache `server-status`, `phpinfo.php`, directory listing (medium), `.DS_Store` (low). Every file check needs a content signature, not only HTTP 200, and redirects are not followed, so soft-404 and login pages do not trigger findings.
- Invalid TLS certificate (expired, self-signed, wrong name) and TLS 1.0/1.1 still enabled (medium).
- HTTP served without redirect to HTTPS, missing HSTS / X-Content-Type-Options / frame protection (low) - only where HTTPS exists.
- Internet-exposed Docker API, Redis, MongoDB, Elasticsearch, Memcached, etcd, Kubelet, CouchDB, RDP, SMB, VNC, Telnet (high/critical), databases or FTP (medium); ports recorded by Nmap are re-confirmed with a live TCP connect.
- **Unserved hostnames** (low): a hostname resolving only to non-CDN addresses, with no recorded web service, whose server rejects TLS for the name or redirects to HTTPS that is not running. If the address is reassigned, the name serves the new owner's content (like a takeover, but through an A record). Reported after two checks in a row agree (`unserved_hostname_strikes`); closed when the site is configured or the record removed. Hosts with no web server at all are not reported.
- Timeouts leave a check inconclusive, so a slow host never closes or reopens findings.

### Screenshots (`utils/screenshots.py`)

- Headless Chromium (Playwright), 1280x800, JPEG; one browser per run, a fresh context per page with downloads and service workers disabled. Chromium's sandbox stays on unless running as root (Docker).
- Request filter: every request (navigation, redirects, page resources) to loopback, private, link-local (cloud metadata) and other internal addresses is blocked unless it is the asset's own resolved IP; non-HTTP schemes are refused.
- A 16x16 average hash compares each capture with the previous one; more than 64 differing bits records `appearance_changed`.
- An HTTP service that ends on the same page as the host's HTTPS capture in the same run is not stored twice.
- The last 5 captures per service are kept in `db/screenshots/`; files are served only by id with a validated name.

### Certificates (`utils/tls_certs.py`, `utils/ct_monitor.py`)

- The certificate each HTTPS service presents is read directly (after a scan and on every `ctlogs` run): issuer, validity, serial, SHA-256 fingerprint. A different fingerprint on the same host and port is a `certificate_changed` event (an issuer change is called out).
- CT logs are used for discovery only: they keep listing certificates a renewal already replaced, which would raise false expiry alerts.
- Expiry alerts at 7, 5, 3 and 1 days, from served certificates only: each certificate alerts at the tightest threshold it reached that was not notified yet, so a check that did not run on a threshold day catches up with one alert (`cert_notifications`).

---

## Findings and prioritization

- **Lifecycle**: `open`, `fixed`, `accepted`, `false_positive`. Findings no longer seen on a conclusive rescan are closed automatically and reopened if they return; `accepted` and `false_positive` keep their status.
- **CVE priority** (`utils/threat_intel.py`):
  - **P1** - in the CISA KEV catalog (exploited in the wild), with CISA's required action and due date
  - **P2** - EPSS >= 10% (likely exploited within 30 days)
  - **P3** - CVSS >= 7.0 without an exploitation signal
  - **P4** - everything else
- **Findings page order** (`utils/findings_repository.py`): CVEs by priority; security findings by severity (critical 1 ... low 4); ties by severity, EPSS, CVSS. CVEs are grouped per host and CVE (all ports), so one row is one decision.
- **Change history** (`asset_changes`): new assets, up/down, ports opened/closed (closed only from full-range deep scans), technologies added/removed/changed, certificates replaced, page appearance, CVEs and findings opened/fixed/reopened, and status changes made in the dashboard.

---

## Data, storage and retention

SQLite in `db/lazyeasm.db` (WAL mode, file mode 0600). Main tables:

| Table | Holds |
|---|---|
| `domain_asset`, `subdomain_asset`, `ip_asset` | Assets; `domain_asset.expand` marks containers of single subdomains (0) |
| `domain_ip`, `subdomain_ip` | Resolution links |
| `ports`, `http_services`, `directories` | Scan results |
| `technologies` (`removed_at`), `vulnerabilities` (`match_method` cpe/retirejs, status, notes) | Technologies and CVEs |
| `cve_cache`, `cve_intel` | NVD responses (24 h; CVE-ID lookups a week), EPSS/KEV per CVE |
| `findings` | Non-CVE findings (takeover, misconfiguration, unserved hostname) with evidence JSON |
| `certificates`, `cert_notifications` | Served certificates (`source = 'tls'`, `port`, `replaced_at`), alerts sent |
| `screenshots` | Captures (files in `db/screenshots/`) |
| `asset_changes` | Change history |
| `scan_queue`, `scan_history`, `scan_progress`, `phase_status`, `scan_hints` | Jobs and scan bookkeeping |
| `settings` | Dashboard settings, check intervals, last runs, heartbeat, migration markers |
| `admin_user`, `token_blacklist` | Admin account (scrypt hash, token version), revoked refresh tokens |

- **Timestamps** are UTC (`YYYY-MM-DD HH:MM:SS`, `utils/timeutil.py`); the browser shows them in local time (`<time>` elements via the `localtime` template filter and `static/js/app.js`). Installs that stored local time were converted once by the server's UTC offset (marker `timestamps_in_utc`).
- **Retention**: change history 365 days; finished queue items 90 days; screenshots 5 per service; replaced certificates expired more than 90 days; backups per [Backups](#backups-internals); expired blacklisted tokens are removed as new ones are added.
- Other folders: `db/screenshots/`, `db/fingerprints/` (downloaded fingerprint data), `db/tls/` (generated certificate and key), `db/backups/`, `logs/` (`LAZYEASM_LOG_DIR` overrides).

---

## Security design

- **Authentication**: single admin account. Password stored as a scrypt hash in `admin_user`; `ADMIN_PASS` in `.env` is a one-time bootstrap/recovery handoff, removed after hashing. Login stays disabled until a password exists.
- **Sessions**: access token (JWT, 15 minutes, HttpOnly cookie, stateless) and refresh token (7 days, checked against `token_blacklist`), rotated every 14 minutes by the page. A reused refresh token revokes every session. Tokens carry the admin's token version; changing the password bumps it, revoking every session at once. After logout an access token stays valid for up to 15 minutes (stateless by design).
- **Login rate limit**: 5 failed attempts block the client IP for 60 seconds (also applied to password changes and backup downloads). In-process; behind a reverse proxy the client IP comes from `X-Forwarded-For` only with `TRUST_PROXY=true`.
- **CSRF**: every POST/DELETE route except login and token refresh checks an HMAC token tied to the login session (survives access-token rotation), from a form field, JSON field or `X-CSRF-Token` header; pages expose it in `<meta name="csrf-token">`. A test fails if a new data-changing route lacks the check. Cookies are `SameSite=Lax`.
- **Headers**: CSP, X-Frame-Options DENY, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, HSTS on HTTPS; authenticated pages are not cached (screenshots: private cache).
- **Output encoding**: Jinja autoescaping; client-side rendering escapes every value; actions use data attributes instead of inline JavaScript built from data.
- **SQL**: parameterized queries throughout.
- **Outbound requests to scanned hosts**: the screenshot browser and script fetching only reach public addresses or the asset's own IPs (no cloud metadata or internal network).
- **Scope**: a single subdomain never expands to its organization without an explicit, confirmed action.
- **Secrets**: `.env` and the database are 0600; the TLS key and backups too. Backups with `.env` are opt-in and password-protected to download.

---

## HTTPS internals

`utils/tls.py`, `TLS_MODE`:

- `self-signed`: EC P-256 certificate (825 days) with SANs for `localhost`, the host name, `127.0.0.1`, `::1`, the outbound interface address, `HOST`, `PUBLIC_IP` and `TLS_HOSTNAMES`. Stored in `db/tls/` (key 0600, written atomically). Regenerated 30 days before expiry and when it no longer covers the server's current names. Fingerprint (SHA-256 of the DER certificate) printed by `run.py`, logged by the web process and shown in Settings > Account.
- `custom`: `TLS_CERT_FILE` / `TLS_KEY_FILE` (PEM). Setting `TLS_CERT_FILE` without `TLS_MODE` implies `custom`.
- `off` (or unset): plain HTTP with waitress. Unset is the default for installs that predate the setting; `install.sh` writes `self-signed` for new ones.
- Served by cheroot with a TLS 1.2+ context. If HTTPS is enabled but cannot start, the web process exits instead of falling back to plain HTTP.
- Plain-HTTP warning: shown on every page when a request arrives over plain HTTP under a host name other than localhost (`plain_http_exposed()`); logged at startup when bound beyond localhost without HTTPS, `FORCE_HTTPS` or `TRUST_PROXY`.
- Behind a proxy: `TRUST_PROXY=true` wraps the app in Werkzeug's `ProxyFix` (one hop: `X-Forwarded-For/Proto/Host`); `FORCE_HTTPS=true` marks cookies Secure and sends HSTS regardless of the request scheme.

---

## Backups internals

`utils/backup.py`:

- Snapshots use SQLite's online backup API (consistent while the worker writes), named `lazyeasm-<UTC timestamp>-<kind>.db`, mode 0600, in `db/backups/`.
- Kinds and retention: `daily` (setting `backup_keep`, default 7, 1-60), `pre-upgrade` (3), `manual` (5), `pre-restore` (3).
- Daily: from the maintenance check when enabled (`backup_enabled`) and the last one (`last_backup_at`) is older than 20 hours.
- Pre-upgrade: `run.py` compares a hash of `modules/InitDB.py` with the stored `schema_signature`; a mismatch on an existing database snapshots it before migrations run.
- Download (`POST /backup/download`): admin password required (rate limited), zip with `lazyeasm.db`, `manifest.json`, optional `screenshots/` and `.env`; logged; the temporary file is deleted after the response.
- Restore (`python -m utils.backup restore`): refuses while the worker heartbeat is fresh (unless `--force`), checks `PRAGMA integrity_check` and the required tables, saves the current database as `pre-restore`, removes stale WAL files, replaces the database atomically; from a zip only `lazyeasm.db`, `screenshots/<valid name>` and (with `--with-env`) `.env` are read, so a crafted archive cannot write elsewhere; the previous `.env` is kept as `.env.pre-restore`.

---

## Configuration reference

`.env` holds secrets and server settings; everything else is edited in the dashboard (Settings) and stored in the database or written to `.env` by the dashboard. `.env.example` lists every key with comments.

| Variable | Required | Description |
|---|---|---|
| `FLASK_SECRET_KEY`, `JWT_SECRET` | Yes | Session and token signing secrets (generated by `install.sh`) |
| `ADMIN_USER` | Yes | Admin username |
| `ADMIN_PASS` | First start / reset | Initial admin password; hashed into the database and removed from `.env` at startup. Set it again and restart to reset a lost password |
| `HOST`, `PORT`, `WEB_THREADS` | No | Web server bind address, port and threads (default `0.0.0.0`, `10001`, `8`) |
| `TLS_MODE` | No | `self-signed`, `custom` or `off` (see [HTTPS internals](#https-internals)) |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | With `custom` | Certificate and key (PEM) |
| `TLS_HOSTNAMES` | No | Extra names/IPs for the self-signed certificate (comma separated) |
| `PUBLIC_IP`, `PUBLIC_PORT` | No (Docker) | Shown in the startup address; `PUBLIC_IP` is also added to the self-signed certificate |
| `FORCE_HTTPS` | No | `true`: always Secure cookies and HSTS (TLS terminated at a proxy). `FLASK_ENV=production` is treated the same for older installs |
| `TRUST_PROXY` | No | `true`: trust `X-Forwarded-For/Proto/Host` from one reverse proxy |
| `FLASK_DEBUG` | No | `true` enables the Werkzeug debugger. Development only, never on a reachable host |
| `SECURITYTRAILS_API_KEY`, `OTX_API_KEY`, `CERTSPOTTER_API_KEY` | No | Discovery sources (CertSpotter works without a key; a key raises its quota) |
| `NVD_API_KEY` | No | Higher NVD rate limit for CVE lookups |
| `AI_PROVIDER` | No | `gemini` (default), `anthropic`, `openai`, `openai_compatible` |
| `AI_MODEL`, `AI_BASE_URL` | No | Model override (required for `openai`, `openai_compatible`); endpoint for `openai_compatible` |
| `GEMINI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` | No | AI provider keys |
| `DISCORD_WEBHOOK_URL`, `DISCORD_USER_ID` | No | Discord channel and user to ping |
| `SLACK_WEBHOOK_URL` | No | Slack incoming webhook |
| `NOTIFY_WEBHOOK_URL`, `NOTIFY_WEBHOOK_SECRET` | No | Generic JSON webhook (`source`, `title`, `message`, `markdown`, `sent_at`); body signed with HMAC-SHA256 in `X-LazyEASM-Signature: sha256=<hex>` |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURITY` | No | Email server; security `starttls` (default), `ssl` or `none` |
| `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_TO` | No | Email credentials, sender and comma-separated recipients |
| `DNS_BRUTEFORCE`, `SCREENSHOTS_ENABLED` | No | `false` disables DNS brute force / screenshots (default `true`) |
| `ASSET_API_MAX_PAGE_SIZE` | No | Page size cap of `/api/assets` (default 100) |
| `LAZYEASM_LOG_DIR` | No | Log folder (default `logs/`) |

Every configured notification channel receives every alert.

### AI analysis

| Provider | `AI_PROVIDER` | Default model | Notes |
|---|---|---|---|
| Google Gemini | `gemini` (default) | `gemini-2.5-flash`, falling back to `gemini-2.0-flash`, `gemini-2.5-pro` | `GEMINI_API_KEY` |
| Anthropic Claude | `anthropic` | `claude-opus-5-5` | `ANTHROPIC_API_KEY`; requests Claude's safeguards decline are retried on Anthropic's recommended fallback model |
| OpenAI | `openai` | none, set `AI_MODEL` | `OPENAI_API_KEY` |
| OpenAI-compatible | `openai_compatible` | none, set `AI_MODEL` | `AI_BASE_URL` (e.g. `http://localhost:11434/v1` for Ollama) |

The prompt includes the CVE (ID, CVSS, description), the technology and version, the hostname and port, and the other technologies on that port; use `openai_compatible` with a local model if that data must not leave your network. The answer is in Indonesian: a one-sentence explanation (*APA INI?*), three main risks (*3 RISIKO UTAMA*) and three patch steps (*PANDUAN PATCH*). API errors (quota, unavailable) are shown, not hidden.

---

## API reference

All routes need a logged-in session (JWT cookie) unless noted. "CSRF" routes also need the CSRF token (see [Security design](#security-design)).

### Pages

| Route | Page |
|---|---|
| `/` | Overview |
| `/assets`, `/assets/<type>/<id>` | Asset list and detail |
| `/findings` | Findings |
| `/changes` | Change history (`q`, `category`, `period` 24h/7d/30d, `host`, `page`) |
| `/scans` | Targets, monitoring, queue (`kind`, `status`, `q`, `page`) |
| `/settings` | Settings |
| `/login`, `/logout` | Login (no session needed), logout |

### Authentication and health

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/login` | POST | None | Log in |
| `/refresh-token` | POST | Refresh token | New token pair |
| `/health` | GET | None from localhost, session otherwise | Database, worker and component health (`200` / `503`) |

### Assets and findings

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/api/assets` | GET | Session | Paginated asset summaries (parameters below) |
| `/api/assets/<type>/<id>` | GET | Session | One asset with technologies, ports, CVEs, findings, screenshots, history |
| `/api/findings` | GET | Session | CVEs (one row per host and CVE) and findings, most urgent first. `q`, `kind` (cve/finding), `severity`, `status` (default open; fixed/accepted/false_positive/all), `kev=1`, `identifier`, `host`, `sort` (urgency/newest/last_seen/host), `page`, `page_size` (max 100) |
| `/api/findings/bulk_status` | POST | CSRF | `{"items": [{"kind": "cve"\|"finding", "id": 1}], "status": "accepted", "note": "..."}`; up to 500 items, one transaction |
| `/api/vulnerabilities/<id>/status`, `/api/findings/<id>/status` | POST | CSRF | Status of one CVE (all ports on that host) or finding |
| `/api/domains/<id>/expand` | POST | CSRF | Expand a container domain (queues discovery, `202`) |
| `/process_assets` | POST | CSRF | Submit targets (form field `asset_input`) |
| `/delete_asset/<type>/<id>` | DELETE | CSRF | Delete an asset |
| `/api/changes` | GET | Session | Change history: `host`, `type`, `since`, `limit` (max 500), `offset` |
| `/api/export/<assets\|findings>.<csv\|json>` | GET | Session | Export; findings accept `status`. CSV cells starting with a formula character are neutralized |
| `/screenshots/<id>/<full\|thumb>` | GET | Session | Screenshot image |

`/api/assets` parameters:

| Parameter | Values | Description |
|---|---|---|
| `q` | text | Asset name, root domain or resolved IP |
| `type` / `types` | `domain`, `subdomain`, `ip` | Repeat or comma-separate |
| `status`, `root_domain` | text | Exact status; one root-domain group |
| `technology` | text | Partial, case-insensitive |
| `port` | 1-65535 | Discovered port or HTTP service port |
| `min_cvss`, `kev` | number, `1` | Highest open CVSS; only assets with an open KEV CVE |
| `cert_state` | `none`, `expired`, `expiring`, `valid` | Served certificate state; expiring = within 30 days |
| `scan_state` | `scanned`, `unscanned`, `pending`, `processing` | Initial scan or latest deep-scan state |
| `sort`, `order` | `name`, `type`, `status`, `first_seen`, `last_seen`, `last_scanned`, `max_cvss`, `max_epss`, `kev_count`, `finding_count`; `asc`/`desc` | Sorting |
| `page`, `page_size` | positive integers | Page size capped by `ASSET_API_MAX_PAGE_SIZE` |

The list returns lightweight summaries; technologies, ports, directories and CVEs come from the detail endpoint only. The asset API keeps no state in the process, but the application as a whole runs as one instance (one worker, SQLite).

### Scans and monitoring

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/api/phase2/scan` | POST | CSRF | Queue a deep scan (`asset_id`, `asset_type`, `asset_name`) |
| `/api/phase2/cancel` | POST | CSRF | Cancel a queued deep scan (`asset_name`) |
| `/api/phase2/queue`, `/queue/status` | GET | Session | Deep-scan queue / Phase 1 batch status |
| `/scans/queue` | GET | Session | Queue table partial (Scans page refresh) |
| `/api/phase3/status` | GET | Session | Monitoring status, last checks, intervals, asset and certificate counts |
| `/api/phase3/toggle` | POST | CSRF | `{"enabled": true\|false}` |
| `/api/phase3/<name>/check` | POST | CSRF | Run a check now: `liveness`, `ctlogs`, `wappalyzer`, `takeover`, `intel`, `misconfig`, `discovery`, `screenshots`, `maintenance` (`202`, `job_id`) |
| `/api/jobs/<id>` | GET | Session | Status of a queued job |
| `/phase_status` | GET | Session | Legacy phase status |

### Settings, AI and backups

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/save_config` | POST | CSRF | `.env`-backed settings |
| `/save_scanning_settings` | POST | CSRF | Check intervals and minimum CVSS |
| `/change_password` | POST | CSRF | Change the admin password (signs out other sessions) |
| `/test_webhook` | POST | CSRF | Send a test notification to every configured channel |
| `/generate_ai` | POST | CSRF | `{"vuln_id": 123}` -> `{"success", "vuln_id", "recommendation"}` |
| `/save_backup_settings` | POST | CSRF | Daily backup on/off, how many to keep |
| `/backup/create` | POST | CSRF | Snapshot into `db/backups/` |
| `/backup/download` | POST | CSRF + password | Zip download (`include_screenshots`, `include_env`) |

---

## Project structure

```
LazyEASM/
├── run.py                       # Prepares the database/HTTPS, starts web + worker
├── main.py                      # Flask app and routes (web process)
├── worker.py                    # Background worker process
├── modules/
│   ├── InitDB.py                # Schema, migrations
│   ├── ExpandAsset.py           # Input expansion and Phase 0 discovery (scope rules)
│   ├── phase1_runner.py         # Phase 1 scan of one asset
│   ├── Nmap.py                  # Port scanning
│   ├── Wappalyzer.py            # Web technology scan + CVE matching
│   ├── CVEmatch.py              # NVD lookups (CPE, CVE ID)
│   ├── FindDir.py, phase2_dirsearch.py  # Directory enumeration, deep scan runner
│   ├── AskAI.py                 # AI recommendations
│   └── Notify.py                # Discord, Slack, webhook, email
├── utils/
│   ├── pipeline.py, queue_manager.py, worker_runtime.py   # Jobs, Phase 1 queue, worker lifecycle/heartbeat
│   ├── phase0_worker.py, phase2_worker.py, phase3_worker.py  # Workers and the monitor scheduler
│   ├── subdomain_discovery.py   # Discovery sources, CT logs, DNS brute force
│   ├── techdetect.py, fingerprints.py, jslibs.py  # Technology detection, fingerprint data, Retire.js
│   ├── threat_intel.py          # KEV + EPSS, priorities
│   ├── misconfig_checker.py, takeover_checker.py  # Security findings
│   ├── liveness_checker.py, wappalyzer_monitor.py, ct_monitor.py, tls_certs.py
│   ├── screenshots.py           # Headless Chromium, request filter, perceptual hash
│   ├── asset_repository.py, findings_repository.py, activity_repository.py  # Page/API queries
│   ├── db_utils.py              # Database access
│   ├── auth.py                  # Admin account, password hashing
│   ├── tls.py                   # Built-in HTTPS
│   ├── backup.py                # Backups and restore
│   ├── scan_settings.py, env_manager.py, config.py  # Dashboard settings, .env, config/log folder
│   ├── timeutil.py              # UTC timestamps
│   └── parsing.py, utility.py, export.py, phase_lock.py, process_utils.py
├── templates/                   # base.html, pages, partials (_cards, _changes, _insecure_banner...)
├── static/js/app.js             # Shared front end (dialogs, actions, CSRF, local times)
├── data/                        # Wordlist, takeover fingerprints, data/fingerprints/ snapshot
├── tests/                       # Test suite (python -m tests)
├── utils/installation/          # install.sh (secrets, first .env), entrypoint.sh (Docker)
├── Dockerfile, docker-compose.yml, start.sh, requirements.txt, .env.example
└── db/, logs/                   # Runtime data (gitignored)
```

---

## Development and testing

```bash
python -m tests          # whole suite; add -v for test names
python main.py           # web + worker in one process (development)
```

- Tests use temporary databases and send log files to a temporary folder (`tests/__init__.py` sets `LAZYEASM_LOG_DIR`), so running them on a live install leaves its data and `logs/` untouched. Plain `python -m unittest discover -s tests` works too but skips that setup.
- The real-browser screenshot test is skipped when Chromium cannot start; the HTTPS test starts a real server on a free port.
- `FLASK_DEBUG=true` uses Flask's debug server (never on a reachable host).
- Regenerate the bundled fingerprint snapshot for a release: `python -m utils.fingerprints --bundle data/fingerprints` (records counts; update `data/fingerprints/README.md`). `python -m utils.fingerprints --refresh` downloads into `db/fingerprints/` now.
- Look up CVEs for a technology: `python -m modules.CVEmatch Nginx 1.20.1`. Capture a page: `python -m utils.screenshots URL --out file.jpg`.
- Keep authorization checks inside `token_required` in `main.py`, so a multi-user version can extend them in one place.
- Close every `get_db_connection()` in a `finally` (`tests/connection_tests.py` checks the code base). A connection left open by a failing query is held by a reference cycle until the garbage collector runs; on a full disk every query fails, and such leaks exhausted the worker's file descriptors so it stayed down after space was freed. The worker heartbeat also runs the collector as a backstop.

---

## Platform notes

- **Docker**: the image includes headless Chromium (about 400 MB extra). Chromium runs as root in the container, without its sandbox. `docker-compose.yml` publishes host port 10002 and persists `db/`, `logs/` and `.env`. `start.sh` uses Docker Compose v2 (`docker compose`; Ubuntu package `docker-compose-v2`) and falls back to v1 (`docker-compose`). Docker's published ports bypass ufw rules.
- **Disk space**: a full disk stops every database write (the dashboard shows the worker as down). Keep an eye on other programs' logs on a shared server.
- **Ubuntu 23.10+ native installs**: AppArmor blocks the user namespaces Chromium's sandbox needs; screenshot runs fail with "Chromium sandbox is blocked by the OS" until a profile allows the Playwright binary (README > Quick start).
- **Nmap without root** uses connect scans (`-sV` works; SYN scans and OS detection are not used).
- **Scaling**: one instance (SQLite, one worker). Multiple instances need a shared database and job claiming.

---

## Data sources and licenses

| Source | Used for | License / terms |
|---|---|---|
| [enthec/webappanalyzer](https://github.com/enthec/webappanalyzer) | Technology fingerprints (`data/fingerprints/`) | GPL-3.0 |
| [Retire.js](https://github.com/RetireJS/retire.js) | JavaScript library vulnerabilities | Apache-2.0 |
| [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) | Takeover fingerprints (`data/`) | CC BY 4.0 |
| NVD API 2.0 | CVEs | Public |
| CISA KEV, FIRST EPSS | Exploitation data | Public |
| CertSpotter, crt.sh, HackerTarget, Wayback Machine, SecurityTrails, AlienVault OTX | Discovery | Their terms; some need keys |
