# LazyEASM

External Attack Surface Management (EASM) tool for asset discovery, vulnerability scanning, and security monitoring.

## Features

### Phase 0: Asset Discovery ✅
- **Domain/Subdomain Discovery** - CTLogs + SecurityTrails integration
- **IP/CIDR Handling** - Automatic expansion and liveness detection
- **DNS Resolution** - Parallel resolution with 20 workers
- **Liveness Detection** - ICMP ping + TCP fallback (ports 80/443/22/21)
- **SSL Certificate Tracking** - Extract expiry dates from CT logs
- **Discord Notifications** - Phase completion + CVE alerts

### Phase 1: Active Scanning (In Progress)
- **Port Scanning** - Nmap top 100 ports with service detection
- **HTTP Discovery** - Identify web services on open ports
- **Directory Enumeration** - Fast non-recursive directory discovery
- **Technology Fingerprinting** - Wappalyzer integration
- **CVE Matching** - NVD API + Vulners fallback
- **AI Recommendations** - Gemini-powered vulnerability analysis

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
# Required
FLASK_SECRET_KEY=your_secret_key
JWT_SECRET=your_jwt_secret

# Optional (enhances discovery)
SECURITYTRAILS_API_KEY=your_key
VULNERS_API_KEY=your_key
GEMINI_API_KEY=your_key

# Notifications
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
DISCORD_USER_ID=your_discord_id
```

## Project Structure

```
LazyEASM/
├── main.py                    # Flask application
├── modules/
│   ├── 01-parse-input.py      # Input parsing
│   ├── 02-port-scanner.py     # Nmap integration
│   ├── 03-asset-expansion.py  # Phase 0 discovery
│   ├── 05-http-discovery.py   # (TODO)
│   ├── 06-dirsearch.py        # (TODO)
│   ├── Wappalyzer.py          # Tech fingerprinting
│   ├── CVEmatch.py            # CVE lookup
│   ├── AskAI.py               # Gemini recommendations
│   ├── Notify.py              # Discord notifications
│   └── InitDB.py              # Database schema
├── utils/
│   ├── config.py              # Environment config
│   ├── db_utils.py            # Database operations
│   ├── parsing.py             # Input parsing
│   ├── utility.py             # DNS, Ping, shared hosting
│   └── env_manager.py         # .env management
├── templates/                 # HTML templates
├── db/                        # SQLite database
├── logs/                      # Application logs
└── requirements.txt           # Python dependencies
```

## Database Schema

```
domain_asset ├── domain_ip ──┬── ip_asset ─── ports
              │               │              ├── http_services
              │               │              └── technologies ── vulnerabilities
              │               │
subdomain_asset ─┬── subdomain_ip ──┘
                 │
                 └── certificates
```

## Usage

1. **Login** - Access the dashboard at `http://localhost:8080`
2. **Add Assets** - Enter domains, IPs, or CIDRs (newline-separated)
3. **Monitor Progress** - Watch Discord for completion notifications
4. **View Dashboard** - See discovered assets, SSL expiry, CVEs

## Tech Stack

- **Backend**: Python Flask
- **Database**: SQLite
- **Frontend**: HTML templates with Tailwind CSS
- **AI**: Google Gemini API
- **Notifications**: Discord Webhooks
- **Scanning**: Nmap, Dirsearch

## Thesis

This project was developed as part of a Bachelor's thesis on External Attack Surface Management (EASM) tools.

## License

MIT License - See [LICENSE](LICENSE) for details.

## Acknowledgments

- SecurityTrails API for subdomain enumeration
- crt.sh (CT Logs) for certificate transparency
- NVD and Vulners for CVE data
- Wappalyzer for technology fingerprinting