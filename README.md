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
- Certificate expiry used `.days` truncation → now uses `round()` for accurate thresholds
- Gemini fallback models updated (removed deprecated `gemini-1.5-*`)
- Dashboard "expiring soon" count now matches red color threshold (≤7 days)
- AI recommendation newlines preserved in dashboard via `whitespace-pre-line`
- Duplicate notifications for certificates fixed (deduplication per threshold)

## Features

### Phase 0: Asset Discovery
- **Domain/Subdomain Discovery** - CTLogs (crt.sh) + SecurityTrails integration
- **IP/CIDR Handling** - Automatic expansion and liveness detection
- **DNS Resolution** - Parallel resolution with configurable workers
- **Liveness Detection** - ICMP ping + TCP fallback (ports 80/443)
- **SSL Certificate Tracking** - Extract and store certificates from CT logs with expiry monitoring
- **Shared Hosting Detection** - Auto-detect Cloudflare and other CDNs

### Phase 1: Active Scanning
- **Port Scanning** - Nmap top 100 ports with service detection
- **Technology Fingerprinting** - Wappalyzer integration (100+ technologies)
- **CVE Matching** - Vulners API with CVSS filtering (min 5.0)
- **AI Recommendations** - Google Gemini-powered vulnerability analysis
- **Discord Notifications** - Real-time alerts for completed scans and CVEs

### Phase 2: Deep Scanning
- **On-Demand Queue** - User-initiated deep scans per asset from dashboard
- **Full Port Enumeration** - Nmap all 65535 ports with `-T5` timing
- **Directory Discovery** - Dirsearch (25 threads, non-recursive)
- **CDN-Aware** - Skips nmap for CDN/Cloudflare IPs, still runs dirsearch on hostname
- **Discord Notifications** - Alerts on scan start, completion, and nmap skip
- **Queue Management** - Cancel pending scans, view queue status in real-time

### Phase 3: Continuous Monitoring
- **Liveness Monitoring** - ICMP/TCP checks every 5 minutes
- **CT Logs Monitoring** - Poll for new subdomains every hour
- **Certificate Expiry Alerts** - Notifications at 7, 5, 3, 1 days before expiry
  - Each threshold notified exactly once per certificate
  - Dashboard shows "expiring soon" count (≤7 days)
- **Certificate Storage** - All certificates from CT logs stored in database
- **Signature Change Detection** - Detects serial/fingerprint changes
- **Stuck Queue Recovery** - Auto-resets items stuck in processing state
- **Duplicate Prevention** - Tracks known subdomains across scan queue
- **New Asset Classification** - Distinguishes new assets from recovered assets in notifications
- **Auto-Discovery** - New subdomains from CT logs queued via Phase 0
- **UI Toggle** - Enable/disable monitoring from dashboard
- **Auto-Refresh** - Dashboard auto-updates every 60 seconds

### AI-Powered Vulnerability Analysis

LazyEASM uses Google Gemini AI to provide personalized CVE recommendations:

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

### Dashboard Features
- **Dark/Light Mode** - Toggle with persistent theme preference
- **Real-time Progress** - Live queue status and scan progress
- **SSL Expiry Tracking** - Visual indicators (red ≤7d, amber ≤30d, green >30d)
- **Certificate Summary** - Counts for expired, expiring soon (≤7 days), and total
- **Expandable Tables** - View detailed tech stack, ports, and directories
- **AI Recommendations** - Formatted with newlines, compact layout
- **Configurable Settings** - Edit API keys directly from UI

### Security
- **Token Refresh Authentication** - Access token (15 min) + Refresh token (7 days) with rotation
- **Refresh Token Blacklisting** - Revoked tokens stored in database
- **Token Reuse Detection** - Reused refresh tokens trigger full user session revocation
- **Rate Limiting** - 5 failed login attempts blocks IP for configurable duration
- **CSRF Protection** - Token-based validation for all POST forms
- **Secure Cookies** - HttpOnly, SameSite=Lax, Secure flag (HTTPS only)
- **Security Headers** - X-Content-Type-Options, X-Frame-Options, CSP, HSTS, Permissions-Policy
- **Cache-Control** - Authenticated pages never cached by browser
- **XSS Protection** - HTML/JS escaping for all dynamic content
- **SQL Injection Protection** - Parameterized queries throughout

## Installation

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/LazyEASM.git
cd LazyEASM

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install external tools
brew install nmap  # macOS
# apt install nmap  # Linux

# Configure environment
cp .env.example .env
# Edit .env with your API keys

# Initialize database
python modules/InitDB.py

# Run the application
python main.py
```

## Configuration

Create a `.env` file with the following keys:

```env
# Security (auto-generated on first run if empty)
FLASK_SECRET_KEY=your_secret_key
JWT_SECRET=your_jwt_secret
FLASK_ENV=production             # Set to 'development' for debug mode

# Admin credentials
ADMIN_USER=lazymin
ADMIN_PASS=randomly_generated       # Set by utils/installation/install.sh

# API Keys (enhances discovery and CVE matching)
SECURITYTRAILS_API_KEY=your_key    # Subdomain enumeration
VULNERS_API_KEY=your_key           # CVE lookup
GEMINI_API_KEY=your_key            # AI recommendations

# Notifications
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
DISCORD_USER_ID=your_discord_id    # User to ping on alerts
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `FLASK_SECRET_KEY` | Yes | Flask session secret |
| `JWT_SECRET` | Yes | JWT signing secret |
| `FLASK_ENV` | No | `production` or `development` |
| `ADMIN_USER` | Yes | Admin username |
| `ADMIN_PASS` | Yes | Admin password |
| `SECURITYTRAILS_API_KEY` | No | SecurityTrails API key |
| `VULNERS_API_KEY` | No | Vulners API key for CVE |
| `GEMINI_API_KEY` | No | Google Gemini API key |
| `DISCORD_WEBHOOK_URL` | No | Discord webhook URL |
| `DISCORD_USER_ID` | No | Discord user ID to ping |

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
| `/process_assets` | POST | Required | Start Phase 0 processing |
| `/delete_asset/<type>/<id>` | DELETE | Required | Delete an asset |
| `/update_table` | GET | Required | Refresh asset table (HTMX) |

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
├── main.py                     # Flask application & routes
├── modules/
│   ├── InitDB.py              # Database schema & migrations
│   ├── Parser.py              # Input parsing (domains/IPs/CIDRs)
│   ├── Nmap.py                # Nmap integration
│   ├── ExpandAsset.py         # Phase 0 discovery pipeline
│   ├── FindDir.py             # Directory enumeration
│   ├── phase1_runner.py       # Phase 1 scanning pipeline
│   ├── phase2_dirsearch.py    # Phase 2 deep scan runner
│   ├── Wappalyzer.py          # Technology fingerprinting
│   ├── CVEmatch.py            # CVE lookup via Vulners
│   ├── AskAI.py               # Gemini AI recommendations
│   └── Notify.py              # Discord notifications
├── utils/
│   ├── config.py              # Environment config loader
│   ├── db_utils.py            # Database CRUD + token blacklist
│   ├── env_manager.py         # .env file management
│   ├── parsing.py             # Input parsing utilities
│   ├── utility.py             # DNS, Ping, shared hosting detection
│   ├── queue_manager.py       # Task queue for Phase 1
│   ├── phase0_worker.py       # Background worker for Phase 0 queue
│   ├── phase2_worker.py       # Background worker for Phase 2 queue
│   ├── phase3_worker.py       # Phase 3 monitoring orchestrator
│   ├── liveness_checker.py    # ICMP/TCP liveness checks
│   ├── process_utils.py       # Process detection utilities
│   └── ct_monitor.py         # CT logs polling + cert tracking
├── templates/
│   ├── dashboard.html         # Main dashboard UI
│   ├── table_partial.html     # Asset table component
│   ├── queue_partial.html     # Phase 2 queue table component
│   └── login.html             # Login page
├── static/
│   └── images/                # Logo and icons
├── db/                        # SQLite database (gitignored)
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

settings ─── Phase 3 configuration
token_blacklist ─── Revoked refresh tokens (auto-cleaned)
scan_queue ─── Pending/processing/completed scan tasks
phase_status ─── Current phase tracking
```

**Key Tables:**
- `cert_notifications` - Tracks sent certificate expiry notifications (deduplication per threshold)
- `token_blacklist` - Revoked JWT refresh tokens
- `scan_queue` - Background task queue for Phase 1/2 scans

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
| **AI** | Google Gemini API (2.5-flash, 2.0-flash, 2.5-pro) |
| **Notifications** | Discord Webhooks |
| **Port Scanning** | Nmap |
| **Tech Fingerprinting** | python-Wappalyzer |
| **Directory Discovery** | Dirsearch |
| **CVE Database** | Vulners API + NVD (nvdlib) |

## Known Limitations

- In-memory task queue (state lost on restart)
- CTLogs API (crt.sh) may return 503 when overloaded
- Shared/CDN IPs skipped for port scanning
- CVE matching requires version detection
- Access tokens remain valid for 15 minutes after logout (stateless by design)
- Browser must support cookies for authentication (no API key auth)
- Gemini API free tier has rate limits (may need paid plan for heavy use)
- SSL notifications run hourly with CT logs (not real-time)

## Roadmap

- **Dockerization** - Dockerfile + docker-compose for containerized deployment
- **Enhanced SSL Monitoring** - Certificate renewal detection, email notifications
- **Improved AI** - CVSS vector breakdown, exploit availability indicator
- **Performance** - Async/await for parallel scanning, Redis task queue
- **Reporting** - CSV/PDF export, scheduled reports, executive summary

## License

MIT License - See [LICENSE](LICENSE) for details.

## Acknowledgments

- SecurityTrails API for subdomain enumeration
- crt.sh (Certificate Transparency Logs) for certificate discovery
- Vulners Database for CVE information
- Wappalyzer for technology fingerprinting patterns