# LazyEASM

External Attack Surface Management (EASM) tool for asset discovery, vulnerability scanning, and security monitoring.

## Features

### Phase 0: Asset Discovery
- **Domain/Subdomain Discovery** - CTLogs (crt.sh) + SecurityTrails integration
- **IP/CIDR Handling** - Automatic expansion and liveness detection
- **DNS Resolution** - Parallel resolution with configurable workers
- **Liveness Detection** - ICMP ping + TCP fallback (ports 80/443)
- **SSL Certificate Tracking** - Extract expiry dates from CT logs
- **Shared Hosting Detection** - Auto-detect Cloudflare and other CDNs

### Phase 1: Active Scanning
- **Port Scanning** - Nmap top 100 ports with service detection
- **Technology Fingerprinting** - Wappalyzer integration (100+ technologies)
- **CVE Matching** - Vulners API with CVSS filtering (min 5.0)
- **Directory Enumeration** - Dirsearch integration with timeout handling
- **AI Recommendations** - Google Gemini-powered vulnerability analysis
- **Discord Notifications** - Real-time alerts for completed scans and CVEs

### Dashboard Features
- **Dark/Light Mode** - Toggle with persistent theme preference
- **Real-time Progress** - Live queue status and scan progress
- **SSL Expiry Tracking** - Visual indicators for certificate expiration
- **Expandable Tables** - View detailed tech stack, ports, and directories
- **Configurable Settings** - Edit API keys directly from UI

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

# Admin credentials
ADMIN_USER=admin
ADMIN_PASS=changeme

# API Keys (enhances discovery and CVE matching)
SECURITYTRAILS_API_KEY=your_key    # Subdomain enumeration
VULNERS_API_KEY=your_key           # CVE lookup
GEMINI_API_KEY=your_key            # AI recommendations

# Notifications
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
DISCORD_USER_ID=your_discord_id    # User to ping on alerts
```

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
│   ├── Wappalyzer.py          # Technology fingerprinting
│   ├── CVEmatch.py            # CVE lookup via Vulners
│   ├── AskAI.py               # Gemini AI recommendations
│   └── Notify.py              # Discord notifications
├── utils/
│   ├── config.py              # Environment config loader
│   ├── db_utils.py            # Database CRUD operations
│   ├── env_manager.py         # .env file management
│   ├── parsing.py             # Input parsing utilities
│   ├── utility.py             # DNS, Ping, shared hosting detection
│   └── queue_manager.py       # Task queue for Phase 1
├── templates/
│   ├── dashboard.html         # Main dashboard UI
│   ├── table_partial.html     # Asset table component
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
```

## Usage

1. **Login** - Access dashboard at `http://localhost:8080` (default: admin/changeme)
2. **Configure** - Add API keys via Settings panel
3. **Add Assets** - Enter domains, IPs, or CIDRs (newline-separated)
4. **Process** - Click "Process Queue" to start Phase 0 discovery
5. **Monitor** - Watch queue progress and Discord for notifications
6. **Review** - Expand assets to see tech stack, ports, CVEs, and AI recommendations

## Tech Stack

| Component | Technology |
|-----------|------------|
| **Backend** | Python Flask |
| **Database** | SQLite |
| **Frontend** | Tailwind CSS (via CDN) |
| **AI** | Google Gemini API |
| **Notifications** | Discord Webhooks |
| **Port Scanning** | Nmap |
| **Tech Fingerprinting** | python-Wappalyzer |
| **Directory Discovery** | Dirsearch |
| **CVE Database** | Vulners API |

## Known Limitations

- In-memory task queue (state lost on restart)
- CTLogs API may return 503 when overloaded
- Shared/CDN IPs skipped for port scanning
- CVE matching requires version detection

## Thesis

This project was developed as part of a Bachelor's thesis on External Attack Surface Management (EASM) tools.

## License

MIT License - See [LICENSE](LICENSE) for details.

## Acknowledgments

- SecurityTrails API for subdomain enumeration
- crt.sh (Certificate Transparency Logs) for certificate discovery
- Vulners Database for CVE information
- Wappalyzer for technology fingerprinting patterns