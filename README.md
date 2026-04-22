# LazyEASM

External Attack Surface Management (EASM) tool for asset discovery, vulnerability scanning, and continuous security monitoring.

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
- **CT Logs Monitoring** - Poll for new subdomains every 1 hour
- **Certificate Storage** - All certificates from CT logs stored in database
- **Certificate Expiry Warnings** - Alerts for certs expiring within 3/7/30 days
- **Certificate Signature Change Detection** - Detects serial/fingerprint changes
- **Stuck Queue Recovery** - Auto-resets items stuck in processing state
- **Duplicate Notification Prevention** - Tracks known subdomains across scan queue
- **New Asset Classification** - Distinguishes new assets from recovered assets in notifications
- **Auto-Discovery** - New subdomains from CT logs added via Phase 0
- **UI Toggle** - Enable/disable monitoring from dashboard
- **Auto-Refresh** - Dashboard auto-updates every 60 seconds

### Dashboard Features
- **Dark/Light Mode** - Toggle with persistent theme preference
- **Real-time Progress** - Live queue status and scan progress
- **SSL Expiry Tracking** - Visual indicators for certificate expiration
- **Certificate Summary** - Counts for expired, expiring 3/7/30 days
- **Expandable Tables** - View detailed tech stack, ports, and directories
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
ADMIN_USER=admin
ADMIN_PASS=changeme              # Change this!

# API Keys (enhances discovery and CVE matching)
SECURITYTRAILS_API_KEY=your_key    # Subdomain enumeration
VULNERS_API_KEY=your_key           # CVE lookup
GEMINI_API_KEY=your_key            # AI recommendations

# Notifications
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
DISCORD_USER_ID=your_discord_id    # User to ping on alerts
```

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

## Project Structure

```
LazyEASM/
├── main.py                     # Flask application & routes
├── modules/
│   ├── InitDB.py              # Database schema & migrations
│   ├── 01-parse-input.py      # Input parsing (domains/IPs/CIDRs)
│   ├── 02-port-scanner.py     # Nmap integration
│   ├── 03-asset-expansion.py  # Phase 0 discovery pipeline
│   ├── 05-dirsearch.py        # Directory enumeration
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
└── README.md
```

## Database Schema

```
domain_asset ├── domain_ip ──┬── ip_asset ─── ports
             │               │              ├── http_services ─── technologies ─── vulnerabilities
             │               │              └── directories
             │               │
subdomain_asset ─┬── subdomain_ip ──┘
                 │
                 └── certificates

settings ─── Phase 3 configuration
token_blacklist ─── Revoked refresh tokens (auto-cleaned)
scan_queue ─── Pending/processing/completed scan tasks
```

## Usage

1. **Login** - Access dashboard at `http://localhost:10001` (default: admin/changeme)
2. **Configure** - Add API keys via Settings panel
3. **Add Assets** - Enter domains, IPs, or CIDRs (newline-separated)
4. **Process** - Click "Process Queue" to start Phase 0 discovery
5. **Monitor** - Watch queue progress and Discord for notifications
6. **Review** - Expand assets to see tech stack, ports, CVEs, and AI recommendations
7. **Enable Monitoring** - Toggle Phase 3 for continuous liveness and CT log monitoring

## Tech Stack

| Component | Technology |
|-----------|------------|
| **Backend** | Python Flask |
| **Database** | SQLite |
| **Frontend** | Tailwind CSS (via CDN) |
| **Authentication** | JWT (access + refresh tokens) |
| **AI** | Google Gemini API |
| **Notifications** | Discord Webhooks |
| **Port Scanning** | Nmap |
| **Tech Fingerprinting** | python-Wappalyzer |
| **Directory Discovery** | Dirsearch |
| **CVE Database** | Vulners API |

## Known Limitations

- In-memory task queue (state lost on restart)
- CTLogs API (crt.sh) may return 503 when overloaded
- Shared/CDN IPs skipped for port scanning
- CVE matching requires version detection
- Access tokens remain valid for 15 minutes after logout (stateless by design)
- Browser must support cookies for authentication (no API key auth)

## Thesis

This project was developed as part of a Bachelor's thesis on External Attack Surface Management (EASM) tools.

## License

MIT License - See [LICENSE](LICENSE) for details.

## Acknowledgments

- SecurityTrails API for subdomain enumeration
- crt.sh (Certificate Transparency Logs) for certificate discovery
- Vulners Database for CVE information
- Wappalyzer for technology fingerprinting patterns