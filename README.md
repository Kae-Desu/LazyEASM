# LazyEASM

External Attack Surface Management (EASM) tool for asset discovery, vulnerability scanning, and continuous security monitoring.

---

> **Thesis Project**
> [Author Name]
> [University Name]
> [Year]
>
> [Thesis Title/Description placeholder]

---

## What's New

### v2.1.0

**Certificate Monitoring Overhaul**
- Per-hostname expiry counting — only counts unique hostnames (deduplicates CT log entries), excludes wildcards and non-asset hostnames
- Separate **expired** and **expiring** categories on dashboard (expired certs shown in red, expiring ≤7d in amber)
- Days remaining uses `int()` (floor) instead of `round()` — `7.9` days shows as 7d, not 8d
- 0-day certs display as **"Expired"** instead of "0d"
- Dashboard labels show explicit thresholds: "expiring ≤7d" instead of ambiguous "expiring soon"
- Active-only cert query filters out already-expired certificates from `_get_cert_expiry()`
- Cert results ordered by `not_after ASC` (soonest expiry shown first)
- Auto-cleanup of certificates expired >90 days (`_cleanup_expired_certs`)
- Cascading cleanup: orphaned `cert_notifications` removed with expired certificates

**Wappalyzer Periodic Re-scanning (Phase 3)**
- Automatic Wappalyzer re-scans on all up hosts with HTTP services (default: every 24 hours)
- New `last_wappalyzer_scan` column on `domain_asset` and `subdomain_asset` tables
- Dashboard "Last Checks" panel now includes "Tech Scan" timestamp
- Asset detail panel shows "Last tech scan" timestamp with fingerprint icon
- Manual trigger: `/api/phase3/wappalyzer/check` endpoint
- New settings: `wappalyzer_interval_hr` (default: 24) and `last_wappalyzer_check`

**Docker Deployment**
- `.env` file mounted as Docker volume to persist configuration across rebuilds
- HTTPS behavior is controlled by `FORCE_HTTPS` / `TRUST_PROXY` (see Environment Variables); debug mode is off unless `FLASK_DEBUG=true`

**Bug Fixes**
- Certificate expiry `days_remaining` uses `int()` (floor) instead of `round()` for accurate thresholds
- Cancel scan bug: `request.form.get() or request.json.get()` had operator precedence issue — replaced with explicit if/else
- Dashboard "expiring soon" count now shows per-hostname count (not per-certificate), excludes wildcards and non-asset hostnames
- Certificate expiry summary now filters by assets only (`domain_asset` + `subdomain_asset`)

### v2.0.0

**SSL Certificate Monitoring**
- Notifications at exactly **7, 5, 3, 1 days** before expiry (deduplicated per threshold)
- Color-coded expiry indicators: 🔴 Red (≤7d), 🟠 Amber (≤30d), 🟢 Green (>30d)
- Dashboard "expiring soon" count aligned with red threshold (≤7 days)
- Certificate change detection (serial/fingerprint monitoring)
- New `cert_notifications` table for tracking sent alerts

**AI-Powered Vulnerability Analysis**
- Personalized CVE recommendations with:
  - CVSS severity score and label (Critical/High/Medium/Low)
  - Affected port and protocol (HTTP/HTTPS)
  - Tech stack context (other technologies on same port)
- Indonesian output format (📋 APA INI? / 🔴 3 RISIKO UTAMA / 🛠️ PANDUAN PATCH)
- Automatic model fallback: `gemini-2.5-flash` → `gemini-2.0-flash` → `gemini-2.5-pro`
- Real error messages on failure (503, quota exceeded, etc.)
- Newline formatting fixed for dashboard display

**Security Enhancements**
- Rate limiting: 5 failed login attempts → IP blocked (configurable duration)
- CSRF token protection on all POST forms
- XSS protection via HTML/JS escaping
- Security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy
- Cache-Control headers on authenticated pages

**Module Organization**
- Renamed modules to consistent PascalCase:
  - `Parser.py` (was `01-parse-input.py`)
  - `Nmap.py` (was `02-port-scanner.py`)
  - `ExpandAsset.py` (was `03-asset-expansion.py`)
  - `FindDir.py` (was `05-dirsearch.py`)

**Bug Fixes**
- Certificate expiry used `int()` (floor) for accurate day thresholds
- Gemini fallback models updated (removed deprecated `gemini-1.5-*`)
- Dashboard "expiring ≤7d" count matches per-hostname expiry (excludes wildcards and non-asset hostnames)
- AI recommendation newlines preserved in dashboard via `whitespace-pre-line`
- Duplicate notifications for certificates fixed (deduplication per threshold)

## Features

### Phase 0: Asset Discovery
- **Domain/Subdomain Discovery** - Passive: crt.sh, Certspotter, HackerTarget, Wayback Machine, SecurityTrails (key) and AlienVault OTX (`OTX_API_KEY`). Active: DNS brute force with a bundled wordlist plus permutations of known subdomains (`api` -> `api-staging`, `dev-api`, `api2`...), skipped on wildcard DNS; toggle it in the dashboard (Configuration > Discovery) or with `DNS_BRUTEFORCE=false`. A failing or rate-limited source never stops the others
- **IP/CIDR Handling** - Automatic expansion and liveness detection
- **DNS Resolution** - Parallel resolution with configurable workers
- **Liveness Detection** - ICMP ping + TCP fallback (ports 80/443)
- **SSL Certificate Tracking** - Extract and store certificates from CT logs with expiry monitoring
- **Shared Hosting Detection** - Auto-detect Cloudflare and other CDNs

### Phase 1: Active Scanning
- **Port Scanning** - Nmap top 100 ports with service detection
- **Technology Fingerprinting** - Wappalyzer integration (100+ technologies)
- **CVE Matching** - NVD CPE + version-range matching with a CVSS filter (minimum 5.0 by default, adjustable in the dashboard)
- **Finding Lifecycle** - Open / fixed / accepted / false positive; findings no longer seen on rescan are closed automatically and reopened if they return
- **Exploit-Based Prioritization** - Each CVE is ranked by real-world exploitation, not just CVSS, using the CISA Known Exploited Vulnerabilities catalog and FIRST EPSS:
  - **P1** - in CISA KEV (exploited in the wild); shows CISA's required action and due date
  - **P2** - EPSS >= 10% (likely to be exploited in the next 30 days)
  - **P3** - CVSS >= 7.0 with no exploitation signal
  - **P4** - everything else
- **AI Recommendations** - Vulnerability analysis with Google Gemini, Anthropic Claude, OpenAI, or any OpenAI-compatible endpoint (e.g. a local Ollama model)
- **Notifications** - Discord, Slack, a generic JSON webhook (optionally HMAC-signed with `NOTIFY_WEBHOOK_SECRET`: header `X-LazyEASM-Signature: sha256=<hex>`), and email over SMTP. Every configured channel receives every alert; configure them in the dashboard and use "Send Test Notification"
- **Export** - Assets and findings (CVEs + security findings with priority, EPSS, KEV, status) as CSV or JSON: `/api/export/assets.csv`, `/api/export/findings.csv?status=open`, `.json` variants. CSV cells that start with a formula character are neutralized

### Phase 2: Deep Scanning
- **On-Demand Queue** - User-initiated deep scans per asset from dashboard
- **Full Port Enumeration** - Nmap all 65535 ports with `-T3` timing
- **Directory Discovery** - Dirsearch (25 threads, non-recursive)
- **CDN-Aware** - Skips nmap for CDN/Cloudflare IPs, still runs dirsearch on hostname
- **Discord Notifications** - Alerts on scan start, completion, and nmap skip
- **Queue Management** - Cancel pending scans, view queue status in real-time

### Phase 3: Continuous Monitoring
- **Liveness Monitoring** - ICMP/TCP checks every 5 minutes
- **CT Logs Monitoring** - Poll for new subdomains every hour
- **Wappalyzer Re-scanning** - Periodic technology re-fingerprinting (default: every 24 hours)
- **Subdomain Takeover Detection** - Follows CNAME chains for every domain/subdomain (default: every 24 hours); flags services known to allow takeover (NXDOMAIN or unclaimed-page fingerprint) and dangling CNAMEs. Findings use the open / fixed / accepted / false positive lifecycle. Manual trigger: `/api/phase3/takeover/check`
- **Exploit Intel Refresh** - Updates CISA KEV and EPSS data for all CVEs (default: every 24 hours) and right after scans that find new CVEs. Sends a Discord alert when a CVE with an open finding is (or becomes) known exploited. Manual trigger: `/api/phase3/intel/check`
- **Change History** - Every change is recorded per host: new assets, up/down transitions, ports opened (and closed, detected by full-range deep scans), technologies added/removed/upgraded, certificate replacements, CVEs and findings opened/fixed/reopened, and status changes made in the dashboard. Shown as "Recent Changes" on the dashboard and per asset; queryable at `GET /api/changes?host=&type=&since=&limit=&offset=`. Entries older than 365 days are pruned daily
- **Subdomain Discovery Monitor** - Re-runs all discovery sources daily for every root domain and queues new subdomains for scanning
- **Misconfiguration Checks** - Runs daily on every HTTP service and on risky ports of public, non-CDN IPs, and right after an asset is scanned. Discord alert for new medium+ findings. Manual trigger: `/api/phase3/misconfig/check`
  - Exposed `.git`, `.env`, `.htpasswd` (high), Apache `server-status`, `phpinfo.php`, directory listing (medium), `.DS_Store` (low). Every file check needs a content signature, not just HTTP 200, and redirects are not followed, so soft-404 and login pages do not trigger findings
  - Invalid TLS certificate (expired, self-signed, wrong hostname) and TLS 1.0/1.1 still enabled (medium)
  - HTTP served without redirect to HTTPS, missing HSTS / X-Content-Type-Options / frame protection headers (low)
  - Internet-exposed Docker API, Redis, MongoDB, Elasticsearch, Memcached, etcd, Kubelet, CouchDB, RDP, SMB, VNC, Telnet (high/critical) and databases or FTP (medium); ports recorded by Nmap are re-confirmed with a live TCP connect so closed ports are auto-closed
  - Timeouts leave a check inconclusive, so a slow host never closes or reopens findings
- **Web Screenshots** - Every HTTP service is captured in headless Chromium (Playwright) right after its first scan and daily afterwards (interval in Schedule & Thresholds). Thumbnails appear in the Assets list and full captures in the asset's Screenshots tab, so login portals, default pages and parked domains stand out at a glance. A perceptual hash compares each capture with the previous one; a visibly different page is recorded as an `appearance_changed` event. The last 5 captures per service are kept in `db/screenshots/`. Toggle under Settings > Discovery & Screenshots or with `SCREENSHOTS_ENABLED=false`. Manual trigger: `/api/phase3/screenshots/check`
  - The browser only talks to the asset itself: requests (including redirects and page resources) to loopback, private, link-local (cloud metadata) and other internal addresses are blocked unless they are the asset's own resolved IPs, and non-HTTP schemes are refused
  - Each page gets a fresh browser context with downloads and service workers disabled; Chromium's sandbox stays on unless running as root
- **Certificate Expiry Alerts** - Notifications at 7, 5, 3, 1 days before expiry
  - Each threshold notified exactly once per certificate
  - Dashboard shows separate "expired" and "expiring ≤7d" counts (per unique hostname)
- **Certificate Storage** - All certificates from CT logs stored in database
- **Expired Certificate Cleanup** - Auto-deletes certificates expired >90 days with cascading notification cleanup
- **Signature Change Detection** - Detects serial/fingerprint changes
- **Stuck Queue Recovery** - Auto-resets items stuck in processing state
- **Duplicate Prevention** - Tracks known subdomains across scan queue
- **New Asset Classification** - Distinguishes new assets from recovered assets in notifications
- **Auto-Discovery** - New subdomains from CT logs queued via Phase 0
- **UI Toggle** - Enable/disable monitoring from dashboard
- **Auto-Refresh** - Dashboard auto-updates every 60 seconds

### AI-Powered Vulnerability Analysis

LazyEASM generates personalized CVE recommendations with the AI provider you choose in the dashboard (or `AI_PROVIDER` in `.env`):

| Provider | `AI_PROVIDER` | Default model | Notes |
|----------|---------------|---------------|-------|
| Google Gemini | `gemini` (default) | `gemini-2.5-flash`, falls back to `gemini-2.0-flash`, `gemini-2.5-pro` | `GEMINI_API_KEY` |
| Anthropic Claude | `anthropic` | `claude-opus-5-5` | `ANTHROPIC_API_KEY`. Requests that Claude's safeguards decline are retried server-side on Anthropic's recommended fallback model |
| OpenAI | `openai` | none, set `AI_MODEL` | `OPENAI_API_KEY` |
| OpenAI-compatible | `openai_compatible` | none, set `AI_MODEL` | `AI_BASE_URL` (e.g. `http://localhost:11434/v1` for Ollama). Keeps findings on infrastructure you control |

`AI_MODEL` overrides the default model for any provider. Findings sent for analysis include the hostname, port, technology versions and CVE details; use `openai_compatible` with a local model if that data must not leave your network.

**Input Context:**
- CVE ID, CVSS score, and description
- Affected technology name and version
- Asset hostname and port (e.g., `example.com:443`)
- Tech stack context (other technologies running on same port)

**Output Format (Indonesian):**

```
📋 APA INI?
[1-sentence non-technical explanation]

🔴 3 RISIKO UTAMA:
1. [Risk 1 - max 20 words]
2. [Risk 2 - max 20 words]
3. [Risk 3 - max 20 words]

🛠️ PANDUAN PATCH (3 LANGKAH):
1. [Update to version X.X.X+ - max 25 words]
2. [Mitigation step - max 25 words]
3. [Monitoring step - max 25 words]

Tech stack: [Other tech]. Pastikan kompatibilitas saat patch.

_Generated by gemini-2.5-flash_
```

**Fallback Chain:**

| Priority | Model | Use Case |
|----------|-------|----------|
| 1 | `gemini-2.5-flash` | Primary - fastest response |
| 2 | `gemini-2.0-flash` | Fallback - when 2.5 is unavailable |
| 3 | `gemini-2.5-pro` | Final fallback - most capable |

**Error Handling:**
- Actual API errors shown (503 unavailable, quota exceeded, etc.)
- Model fallback automatic on failure
- No silent failures

### Dashboard
Separate pages with a sidebar (tabs on small screens), so the UI stays usable with thousands of assets:

- **Overview** - Headline numbers (open findings by severity, known-exploited CVEs, assets up/down/new, certificates expiring), the riskiest assets and the most widespread issues, each linking to the matching filtered list. Below: submit targets, last monitoring checks, recent changes and the deep-scan queue. Optional auto-refresh (5/30/60s)
- **Findings** - Every CVE and security finding across all assets in one paginated list, most urgent first (known exploited / critical, then EPSS, then CVSS). Filter by status, kind, severity, KEV, host or issue ("show this CVE on every host"); select rows and mark them fixed, accepted or false positive in one step, with a note
- **Assets** - Server-side paginated list with a screenshot thumbnail per row, search (name, domain, IP), filters (type, status, KEV / CVSS risk, certificate state, technology) and sorting (most KEV, highest CVSS/EPSS, most findings, recently scanned, newest). Filters live in the URL, so views can be bookmarked and shared
- **Asset detail** (`/assets/<type>/<id>`) - Summary plus tabs for findings and CVEs (status changes, AI analysis), technologies, ports and IPs, screenshots, directories, change history and scan details; deep scan and delete actions
- **Settings** - Tabs for General, AI, Notifications, Discovery & Screenshots, Schedule & Thresholds and Account. Changes apply without a restart
- **Dark/Light Mode** - Persistent theme preference
- **Exports** - Assets as CSV from the Assets page; findings as CSV/JSON from the Findings page

### Security
- **Token Refresh Authentication** - Access token (15 min) + Refresh token (7 days) with rotation
- **Refresh Token Blacklisting** - Revoked tokens stored in database
- **Token Reuse Detection** - Reused refresh tokens trigger full user session revocation
- **Rate Limiting** - 5 failed login attempts blocks IP for configurable duration
- **Hashed Admin Password** - Stored in the database as a scrypt hash, never in plain text. The generated `ADMIN_PASS` in `.env` is hashed on first start and removed from the file; change the password in the dashboard (Configuration > Change Admin Password), which signs out every other session. Lost it? Set `ADMIN_PASS=...` in `.env` and restart. Login stays disabled until a password exists, so an empty `ADMIN_PASS` can never log in
- **CSRF Protection** - Token-based validation for all POST forms
- **Secure Cookies** - HttpOnly, SameSite=Lax, Secure flag (HTTPS only)
- **Security Headers** - X-Content-Type-Options, X-Frame-Options, CSP, HSTS, Permissions-Policy
- **Cache-Control** - Authenticated pages never cached by browser
- **XSS Protection** - HTML/JS escaping for all dynamic content
- **SQL Injection Protection** - Parameterized queries throughout

## Installation

### Docker (Recommended)

```bash
# Clone repository
git clone https://github.com/Kae-Desu/LazyEASM.git
cd LazyEASM

# Start (auto-installs Docker if missing on Linux)
./start.sh

# Access dashboard at http://localhost:10001
```

> **Note:** The `.env` file is mounted as a Docker volume, so configuration persists across container rebuilds.
>
> The image includes headless Chromium for web screenshots (about 400 MB extra). Native installs get it from `start.sh`; for a manual install run `python -m playwright install --with-deps chromium`. Without it, screenshots are skipped and everything else works.

### Native

```bash
# Clone repository
git clone https://github.com/Kae-Desu/LazyEASM.git
cd LazyEASM

# Start (auto-installs dependencies if missing)
./start.sh --native
```

### start.sh Commands

| Command | Description |
|---------|-------------|
| `./start.sh` | Start in Docker mode (default) |
| `./start.sh --native` | Start in native mode (no Docker) |
| `./start.sh --stop` | Stop Docker containers |
| `./start.sh --logs` | Follow Docker container logs |
| `./start.sh --clean` | Remove Docker containers, images, and volumes |
| `./start.sh --help` | Show help message |

On first run (either mode), `start.sh` will:
- **Docker**: Auto-install Docker + docker-compose on Linux if missing
- **Native**: Auto-install Python 3, nmap, openssl, and create a virtual environment
- Generate `.env` with random secrets via `utils/installation/install.sh`

### Manual Installation (Advanced)

If you prefer to set up manually without `start.sh`:

```bash
# Clone repository
git clone https://github.com/Kae-Desu/LazyEASM.git
cd LazyEASM

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
python -m playwright install --with-deps chromium  # web screenshots (optional)

# Install external tools
brew install nmap  # macOS
# apt install nmap  # Linux

# Configure environment
cp .env.example .env
# Edit .env: set ADMIN_PASS (login stays disabled until it is set); API keys can be added later in the dashboard

# Initialize database
python modules/InitDB.py

# Run the application (web app + background worker as separate processes)
python run.py
```

### How LazyEASM Runs

`run.py` (used by Docker and `start.sh`) starts two processes:

| Process | Command | Does |
|---------|---------|------|
| Web | `main.py` with `LAZYEASM_ROLE=web` | Serves the dashboard and API with [waitress](https://docs.pylonsproject.org/projects/waitress/) |
| Worker | `worker.py` | Runs every queue (asset discovery, Phase 0/1/2) and the Phase 3 monitors |

- The two share the SQLite database (WAL mode). Submitting assets queues a job that the worker picks up, so restarting the web app never interrupts a scan, and queued work survives restarts: jobs a crash left half-done are re-queued when the worker starts.
- If either process exits, `run.py` stops the other and exits, so Docker's restart policy restarts LazyEASM.
- The worker writes a heartbeat every 15 seconds; `/health` reports it per component (`phase0_worker`, `discovery_worker`, `phase1_worker`, `phase2_worker`, `phase3_worker`).
- Run exactly one worker per database.
- `POST /api/phase3/<check>/check` (`liveness`, `ctlogs`, `wappalyzer`, `takeover`, `intel`, `misconfig`, `discovery`, `screenshots`, `maintenance`) queues a run in the worker and returns `202` with a `job_id`; `GET /api/jobs/<job_id>` reports `pending` / `processing` / `completed` / `failed`. A manual run never overlaps the scheduled run of the same check.
- A deep-scan phase lock older than 24 hours is treated as left behind by a crash and cleared.
- For local development, `python main.py` runs the web app and the worker in one process. `FLASK_DEBUG=true` switches to Flask's debug server (never on a reachable host).
- `HOST`, `PORT` (default `0.0.0.0:10001`) and `WEB_THREADS` (default `8`) configure the web server.

## Configuration

Create a `.env` file with the following keys:

```env
# Security (auto-generated on first run if empty)
FLASK_SECRET_KEY=your_secret_key
JWT_SECRET=your_jwt_secret
FORCE_HTTPS=false                # true when users reach LazyEASM over HTTPS
TRUST_PROXY=false                # true behind a reverse proxy setting X-Forwarded-*

# Admin credentials
ADMIN_USER=lazymin
ADMIN_PASS=randomly_generated       # Set by install.sh; hashed into the DB and removed from .env on first start

# API Keys (enhances discovery and CVE matching)
SECURITYTRAILS_API_KEY=your_key    # Subdomain enumeration
NVD_API_KEY=your_key               # Optional, raises NVD rate limit
AI_PROVIDER=gemini                 # gemini | anthropic | openai | openai_compatible
GEMINI_API_KEY=your_key            # AI recommendations (gemini)
ANTHROPIC_API_KEY=your_key         # AI recommendations (anthropic)
OPENAI_API_KEY=your_key            # AI recommendations (openai)

# Notifications
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
DISCORD_USER_ID=your_discord_id    # User to ping on alerts
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
NOTIFY_WEBHOOK_URL=https://example.com/hooks/lazyeasm
NOTIFY_WEBHOOK_SECRET=            # Optional HMAC signing secret
SMTP_HOST=smtp.example.com         # Email: also SMTP_PORT, SMTP_SECURITY,
SMTP_TO=secops@example.com         # SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM

# Phase 3 check intervals and the minimum CVSS are set in the dashboard
# (Continuous Monitoring > Schedule & Thresholds), not in .env
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `FLASK_SECRET_KEY` | Yes | Flask session secret |
| `JWT_SECRET` | Yes | JWT signing secret |
| `FORCE_HTTPS` | No | `true` to always send Secure cookies and HSTS (use when served over HTTPS, including TLS terminated at a proxy). `FLASK_ENV=production` is treated the same for older installs |
| `TRUST_PROXY` | No | `true` to trust `X-Forwarded-For/Proto/Host` from one reverse proxy |
| `FLASK_DEBUG` | No | `true` enables the Werkzeug debugger. Development only; never on a reachable host (default: `false`) |
| `ADMIN_USER` | Yes | Admin username |
| `ADMIN_PASS` | First start / reset | Initial admin password. Hashed into the database and removed from `.env` at startup; set it again and restart to reset a lost password |
| `SECURITYTRAILS_API_KEY` | No | SecurityTrails API key |
| `NVD_API_KEY` | No | NVD API key (higher CVE lookup rate limit) |
| `AI_PROVIDER` | No | `gemini` (default), `anthropic`, `openai`, or `openai_compatible` |
| `AI_MODEL` | No | Model override; required for `openai` and `openai_compatible` |
| `AI_BASE_URL` | No | Endpoint for `openai_compatible` |
| `GEMINI_API_KEY` | No | Google Gemini API key |
| `ANTHROPIC_API_KEY` | No | Anthropic API key |
| `OPENAI_API_KEY` | No | OpenAI API key (optional for `openai_compatible`) |
| `DISCORD_WEBHOOK_URL` | No | Discord webhook URL |
| `DISCORD_USER_ID` | No | Discord user ID to ping |
| `SLACK_WEBHOOK_URL` | No | Slack incoming webhook |
| `NOTIFY_WEBHOOK_URL` | No | Generic JSON webhook (`source`, `title`, `message`, `markdown`, `sent_at`) |
| `NOTIFY_WEBHOOK_SECRET` | No | Signs webhook bodies with HMAC-SHA256 |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_SECURITY` | No | Email server; security is `starttls` (default), `ssl` or `none` |
| `SMTP_USERNAME` / `SMTP_PASSWORD` / `SMTP_FROM` / `SMTP_TO` | No | Email credentials, sender and comma-separated recipients |
| `OTX_API_KEY` | No | AlienVault OTX key for passive DNS discovery |
| `DNS_BRUTEFORCE` | No | `false` disables DNS brute force and permutations (default `true`); also editable in the dashboard |
| `SCREENSHOTS_ENABLED` | No | `false` disables web screenshots (default `true`); also editable in the dashboard |

## Authentication

LazyEASM uses a dual-token JWT authentication system:

| Token | Lifetime | Storage | Validation |
|-------|----------|---------|------------|
| **Access Token** | 15 minutes | HttpOnly cookie | Stateless (JWT signature only) |
| **Refresh Token** | 7 days | HttpOnly cookie | Stateful (checked against blacklist) |

- Access tokens are refreshed automatically every 14 minutes via `/refresh-token`
- Each refresh issues a new token pair and blacklists the old refresh token
- If a blacklisted refresh token is reused (possible theft), all user sessions are revoked
- Logout blacklists the refresh token and clears both cookies

## API Reference

All endpoints require authentication via JWT access token (cookie) unless noted.

### Authentication

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/login` | GET, POST | None | Login page and authentication |
| `/logout` | GET | Required | Logout and clear tokens |
| `/refresh-token` | POST | Refresh token | Refresh access token |
| `/health` | GET | None | Health check endpoint |

### Assets & Processing

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/` | GET | Required | Dashboard (main UI) |
| `/api/assets` | GET | Required | Searchable, filtered, paginated asset summaries |
| `/api/assets/<type>/<id>` | GET | Required | Full details for one asset, loaded on demand |
| `/api/findings` | GET | Required | CVEs (one row per host and CVE) and security findings across all assets, most urgent first. Params: `q`, `kind` (cve/finding), `severity`, `status` (open by default, or fixed/accepted/false_positive/all), `kev=1`, `identifier`, `host`, `sort` (urgency/newest/last_seen/host), `page`, `page_size` (max 100) |
| `/api/findings/bulk_status` | POST | Required + CSRF | `{"items": [{"kind": "cve"\|"finding", "id": 1}], "status": "accepted", "note": "..."}`; up to 500 items, applied in one transaction |
| `/api/vulnerabilities/<id>/status`, `/api/findings/<id>/status` | POST | Required + CSRF | Set the status of one CVE (all ports on that host) or finding |
| `/process_assets` | POST | Required | Start Phase 0 processing |
| `/delete_asset/<type>/<id>` | DELETE | Required | Delete an asset |

#### Asset Query API

`GET /api/assets` is the read boundary for the next dashboard UI. It does not
store cursor or pagination state in the Flask process, so requests can be routed
to any application replica.

| Parameter | Values | Description |
|-----------|--------|-------------|
| `q` | text | Search asset name, root domain, or resolved IP |
| `type` / `types` | `domain`, `subdomain`, `ip` | Repeat or provide comma-separated values |
| `status` | text | Exact asset status |
| `root_domain` | hostname | Restrict results to one root-domain group |
| `technology` | text | Partial, case-insensitive technology match |
| `port` | `1`-`65535` | Match discovered ports or HTTP service ports |
| `min_cvss` | number | Minimum highest CVSS score on the asset |
| `kev` | `1` / `true` | Only assets with an open CVE in the CISA KEV catalog |
| `cert_state` | `none`, `expired`, `expiring`, `valid` | Certificate state; expiring means active and due within 30 days |
| `scan_state` | `scanned`, `unscanned`, `pending`, `processing` | Initial scan state or latest Phase 2 queue state |
| `sort` | `name`, `type`, `status`, `first_seen`, `last_seen`, `last_scanned`, `max_cvss`, `max_epss`, `kev_count` | Sort field |
| `order` | `asc`, `desc` | Sort direction |
| `page` | positive integer | One-based page number |
| `page_size` | positive integer | Page size, capped by `ASSET_API_MAX_PAGE_SIZE` |

Example:

```text
/api/assets?q=api&type=subdomain&technology=nginx&min_cvss=7&page=1&page_size=25
```

The list response contains lightweight counts and summaries. Technologies,
ports, directories, and vulnerability records are returned by the detail
endpoint only, preventing collapsed UI rows from loading their entire finding
graph.

> **Kubernetes scaling note:** The asset API itself is stateless, but the full
> application is not yet safe to scale to multiple replicas. SQLite storage and
> the in-process Phase 0/1/2/3 workers must be moved to shared services (for
> example PostgreSQL plus a durable job queue) before enabling horizontal pod
> autoscaling. Until then, use one application replica with persistent storage.

### Phase 2 (Deep Scanning)

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/phase2/scan` | POST | Required | Queue a deep scan for asset |
| `/api/phase2/cancel` | POST | Required | Cancel a queued scan |
| `/api/phase2/queue` | GET | Required | Get current queue status |
| `/update_queue` | GET | Required | Refresh queue table (HTMX) |
| `/queue/status` | GET | Required | Get queue status (JSON) |

### Phase 3 (Continuous Monitoring)

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/phase3/status` | GET | Required | Get monitoring status and stats |
| `/api/phase3/toggle` | POST | Required | Enable/disable Phase 3 |
| `/api/phase3/liveness/check` | POST | Required | Trigger immediate liveness check |
| `/api/phase3/ctlogs/check` | POST | Required | Trigger immediate CT logs poll |
| `/api/phase3/wappalyzer/check` | POST | Required | Trigger immediate Wappalyzer re-scan |
| `/api/phase3/screenshots/check` | POST | Required | Trigger immediate web screenshot run |
| `/screenshots/<id>/full` or `/thumb` | GET | Required | Stored screenshot image (JPEG) |
| `/phase_status` | GET | Required | Get phase status (legacy) |

### AI Analysis

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/generate_ai` | POST | Required | Generate AI recommendation for CVE |

**Request Body:**
```json
{
  "vuln_id": 123
}
```

**Response:**
```json
{
  "success": true,
  "vuln_id": 123,
  "recommendation": "📋 APA INI?\n..."
}
```

### Configuration

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/save_config` | POST | Required | Update configuration values |
| `/test_webhook` | POST | Required | Test Discord webhook |

## Project Structure

```
LazyEASM/
├── run.py                      # Starts the web and worker processes
├── main.py                     # Flask application & routes (web process)
├── worker.py                   # Background worker process
├── modules/
│   ├── InitDB.py              # Database schema & migrations
│   ├── Nmap.py                # Nmap integration
│   ├── ExpandAsset.py         # Phase 0 discovery pipeline
│   ├── FindDir.py             # Directory enumeration
│   ├── phase1_runner.py       # Phase 1 scanning pipeline
│   ├── phase2_dirsearch.py    # Phase 2 deep scan runner
│   ├── Wappalyzer.py          # Technology fingerprinting
│   ├── CVEmatch.py            # CVE lookup via NVD (CPE matching)
│   ├── AskAI.py               # AI recommendations (Gemini / Claude / OpenAI / compatible)
│   └── Notify.py              # Discord notifications
├── utils/
│   ├── config.py              # Environment config loader
│   ├── db_utils.py            # Database CRUD + token blacklist
│   ├── env_manager.py         # .env file management
│   ├── parsing.py             # Input parsing utilities
│   ├── utility.py             # DNS, Ping, shared hosting detection
│   ├── queue_manager.py       # Database-backed Phase 1 queue and worker
│   ├── pipeline.py            # Asset discovery and Phase 1 enqueueing
│   ├── worker_runtime.py      # Starts background components, heartbeat, crash recovery
│   ├── phase0_worker.py       # Background worker for Phase 0 queue
│   ├── phase2_worker.py       # Background worker for Phase 2 queue
│   ├── phase3_worker.py       # Phase 3 monitoring orchestrator
│   ├── liveness_checker.py    # ICMP/TCP liveness checks
│   ├── wappalyzer_monitor.py  # Periodic Wappalyzer re-scanning (Phase 3)
│   ├── takeover_checker.py    # Subdomain takeover / dangling CNAME checks (Phase 3)
│   ├── threat_intel.py        # CISA KEV + EPSS prioritization (Phase 3)
│   ├── misconfig_checker.py   # Exposed files, TLS, headers, risky ports (Phase 3)
│   ├── subdomain_discovery.py # Extra passive sources + DNS brute force / permutations
│   ├── screenshots.py         # Headless Chromium captures, request filtering, perceptual hash
│   ├── asset_repository.py    # Asset list / detail queries (Assets pages, /api/assets)
│   ├── findings_repository.py # Cross-asset findings and Overview numbers
│   ├── process_utils.py       # Process detection utilities
│   └── ct_monitor.py         # CT logs polling + cert tracking
├── templates/
│   ├── base.html              # Layout: header, sidebar, dialogs, toasts
│   ├── dashboard.html         # Overview page
│   ├── assets.html            # Paginated asset list (uses /api/assets)
│   ├── findings.html          # Cross-asset findings triage (uses /api/findings)
│   ├── overview_partial.html  # Overview headline numbers
│   ├── asset_detail.html      # One asset with tabs
│   ├── settings.html          # Settings with tabs
│   ├── _cards.html            # Finding / CVE card macros
│   ├── queue_partial.html     # Phase 2 queue table component
│   └── login.html             # Login page
├── static/
│   ├── images/                # Logo and icons
│   └── js/app.js              # Shared front-end code (dialogs, actions, status updates)
├── db/                        # SQLite database and screenshots/ (gitignored)
├── logs/                      # Application logs (gitignored)
├── requirements.txt
├── .env.example               # Environment template
├── start.sh                    # Main entry point (Docker / Native)
├── utils/installation/
│   ├── install.sh               # Secret generation script
│   └── entrypoint.sh            # Docker entry point
└── README.md
```

## Database Schema

```
domain_asset ─── domain_ip ───┬── ip_asset ─── ports
              │               │              ├── http_services ─── technologies ─── vulnerabilities
              │               │              └── directories
              │               │
subdomain_asset ─┬── subdomain_ip ──┘
                │
                └── certificates ─── cert_notifications
                                  └── (expiry tracking: 7/5/3/1 days)

domain_asset / subdomain_asset ─── last_wappalyzer_scan
                                ├── last_liveness_check
                                ├── last_deep_scan
                                └── last_dirsearch

settings ─── Phase 3 configuration (liveness_interval_min, ctlogs_interval_hr, wappalyzer_interval_hr)
token_blacklist ─── Revoked refresh tokens (auto-cleaned)
scan_queue ─── Pending/processing/completed scan tasks (ports_found, dirs_found, error_message)
phase_status ─── Current phase tracking
```

**Key Tables:**
- `cert_notifications` - Tracks sent certificate expiry notifications (deduplication per threshold)
- `token_blacklist` - Revoked JWT refresh tokens
- `scan_queue` - Background task queue for Phase 1/2 scans (`ports_found`, `dirs_found`, `error_message` columns)

## Usage

1. **Login** - Access dashboard at `http://localhost:10001` (credentials set via `./start.sh`)
2. **Configure** - Add API keys via Settings panel
3. **Add Assets** - Enter domains, IPs, or CIDRs (newline-separated)
4. **Process** - Click "Process Queue" to start Phase 0 discovery
5. **Monitor** - Watch queue progress and Discord for notifications
6. **Review** - Expand assets to see tech stack, ports, CVEs, and AI recommendations
7. **Deep Scan** - Click "Deep Scan" on any asset for full port scan + directory discovery
8. **Enable Monitoring** - Toggle Phase 3 for continuous liveness and CT log monitoring

## Tech Stack

| Component | Technology |
|-----------|------------|
| **Backend** | Python Flask |
| **Database** | SQLite |
| **Frontend** | Tailwind CSS (via CDN) |
| **Authentication** | JWT (access + refresh tokens) |
| **AI** | Google Gemini, Anthropic Claude, OpenAI, or OpenAI-compatible endpoints |
| **Notifications** | Discord Webhooks |
| **Port Scanning** | Nmap |
| **Tech Fingerprinting** | python-Wappalyzer |
| **Directory Discovery** | Dirsearch |
| **CVE Database** | NVD API 2.0 (CPE matching) |

## Known Limitations

- CTLogs API (crt.sh) may return 503 when overloaded
- Shared/CDN IPs skipped for port scanning
- CVE matching requires version detection
- Access tokens remain valid for up to 15 minutes after logout (stateless by design); changing the password revokes every session immediately
- Browser must support cookies for authentication (no API key auth)
- Gemini API free tier has rate limits (may need paid plan for heavy use)
- SSL notifications run hourly with CT logs (not real-time)

## Roadmap

- **Dockerization** ✅ - Dockerfile + docker-compose for containerized deployment
- **Enhanced SSL Monitoring** - Certificate renewal detection, email notifications
- **Improved AI** - CVSS vector breakdown, exploit availability indicator
- **Performance** - Async/await for parallel scanning, Redis task queue
- **Reporting** - CSV/PDF export, scheduled reports, executive summary

## License

Copyright (c) 2026 楓

LazyEASM is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See [LICENSE](LICENSE) for the full text.

In short: you can use, modify and self-host LazyEASM freely. If you modify it and let other people use it over a network (for example, as a hosted service), you must make your modified source code available to those users under the same license.

Releases published before this change remain available under the MIT License.

## Acknowledgments

- SecurityTrails API for subdomain enumeration
- crt.sh (Certificate Transparency Logs) for certificate discovery
- NVD (National Vulnerability Database) for CVE information
- Wappalyzer for technology fingerprinting patterns
- [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) for exploited-in-the-wild CVEs
- [FIRST EPSS](https://www.first.org/epss/) for exploit prediction scores
- [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) by EdOverflow and contributors for subdomain takeover fingerprints (CC BY 4.0, see [data/README.md](data/README.md))
