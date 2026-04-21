# LazyEASM - Project Status

## Current App Flow

### Phase 0: Asset Discovery (COMPLETE ✅)

```
USER INPUT
    │
    │  "example.com\napi.test.com\n192.168.1.1\n10.0.0.0/24"
    │
    ▼
┌─────────────────────────────────────────────────────────────────────┐
│  parse_input() - utils/parsing.py                                   │
│  ├─ Domains: ["example.com", "test.com"]                            │
│  ├─ Subdomains: ["api.test.com"]                                    │
│  ├─ IPs: ["192.168.1.1"]                                            │
│  └─ CIDRs: ["10.0.0.0/24"]                                          │
└────────────────────────┬────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Phase1Expander.run_phase1() - modules/03-asset-expansion.py        │
│                                                                      │
│  FOR EACH DOMAIN:                                                    │
│  ├─ Check if root domain exists in DB                               │
│  │   ├─ NEW: Discover subdomains via CTLogs + SecurityTrails        │
│  │   └─ EXISTS: Skip discovery, just add subdomain                  │
│  ├─ DNS resolve (parallel, 20 workers)                              │
│  ├─ Liveness check (ICMP ping + TCP fallback on 80/443/22)         │
│  ├─ Store: domain_asset, subdomain_asset, ip_asset                  │
│  └─ Store: certificates (not_before, not_after, issuer)              │
│                                                                      │
│  FOR EACH IP:                                                        │
│  ├─ Validate IP format                                               │
│  ├─ Liveness check (ICMP + TCP fallback)                            │
│  └─ Store: ip_asset                                                  │
│                                                                      │
│  FOR EACH CIDR:                                                      │
│  ├─ Expand to individual IPs                                         │
│  ├─ Liveness check each IP                                           │
│  └─ Store ALL IPs (mark dead as status='down')                      │
│                                                                      │
│  Discord: "Phase 1 Complete - X domains, Y subdomains, Z IPs"       │
└────────────────────────┬────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  DASHBOARD - templates/dashboard.html                                │
│                                                                      │
│  Display:                                                            │
│  ├─ Assets table (domain/subdomain/IP)                              │
│  │   └─ Columns: Target Name, Status (up/down), SSL Expiry         │
│  ├─ Expandable row: Tech Stack, CVEs, Directories                   │
│  └─ Certificate alerts panel                                         │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Database Schema

```
domain_asset          subdomain_asset        ip_asset
    │                      │                      │
    └──────┬──────────────┴──────────────────────┘
           │
           ▼
    domain_ip           subdomain_ip          ports
    (junction)          (junction)            (from nmap)
           │
           ▼
       certificates (SSL cert expiry tracking)
           │
           ▼
       http_services (Phase 1)
           │
           ▼
       technologies → vulnerabilities (Phase 1)
```

---

## Completed Features ✅

| Feature | File | Description |
|---------|------|-------------|
| Input parsing | `utils/parsing.py` | Parse domains, subdomains, IPs, CIDRs |
| DB utilities | `utils/db_utils.py` | CRUD operations, certificate helpers |
| Batch DNS/Ping | `utils/utility.py` | Parallel DNS resolve + ICMP/TCP liveness |
| CTLogs integration | `modules/03-asset-expansion.py` | Extract subdomains + certificates |
| SecurityTrails | `modules/03-asset-expansion.py` | Alternative subdomain source |
| Certificate tracking | `certificates` table | Store not_before, not_after, issuer |
| SSL expiry alerts | `modules/Notify.py` | Discord notification for expiring certs |
| Dashboard | `templates/` | Asset table with SSL expiry column |
| TCP fallback | `utils/utility.py` | ICMP blocked → try port 80/443/22/21 |

---

## Phase 1: Active Scanning (IMPLEMENTED ✅)

### Architecture

```
Phase 0 Complete (asset discovered)
         │
         ▼
┌────────────────────────────────────┐
│  scan_queue table                  │
│  ├─ target: domain/subdomain/IP    │
│  ├─ status: pending/running/done    │
│  └─ cycle: "phase1"                 │
└────────────┬───────────────────────┘
              │
              ▼
┌────────────────────────────────────────────────────────────────────┐
│  QUEUE PROCESSOR (utils/queue_manager.py)                          │
│                                                                     │
│  ThreadPoolExecutor(max_workers=4)                                  │
│  Sequential processing per asset:                                    │
│                                                                     │
│  while queue.has_pending():                                          │
│      task = queue.get_next()                                         │
│      queue.mark_running(task)                                        │
│      │                                                               │
│      ├─► 1. PORT SCAN (modules/02-port-scanner.py)                   │
│      │     - nmap --top-ports 100 -sV                               │
│      │     - Skip shared hosting/Cloudflare                          │
│      │     - Store in `ports` table                                  │
│      │                                                               │
│      ├─► 2. WAPPALYZER (modules/Wappalyzer.py)                       │
│      │     - Tech fingerprinting                                     │
│      │     - Create http_services entries                            │
│      │     - Store in `technologies` table                           │
│      │                                                               │
│      ├─► 3. DIRSEARCH (modules/05-dirsearch.py)                     │
│      │     - Non-recursive, fast wordlist (dicc.txt)                 │
│      │     - Store in `directories` table                            │
│      │                                                               │
│      ├─► 4. CVE MATCH (modules/Wappalyzer.py internal)              │
│      │     - NVD API + Vulners fallback                              │
│      │     - Store in `vulnerabilities` table                        │
│      │                                                               │
│      └─► 5. Discord: "Phase 1 Complete"                             │
│                                                                     │
│      queue.mark_done(task)                                           │
└────────────────────────────────────────────────────────────────────┘
```

### Implementation Status

| Component | File | Status |
|-----------|------|--------|
| Queue Manager | `utils/queue_manager.py` | ✅ Created |
| Phase 1 Runner | `modules/phase1_runner.py` | ✅ Created |
| Port Scanner | `modules/02-port-scanner.py` | ✅ Exists |
| Wappalyzer | `modules/Wappalyzer.py` | ✅ Exists |
| Dirsearch | `modules/05-dirsearch.py` | ✅ Created |
| CVE Matching | `modules/CVEmatch.py` | ✅ Exists |
| Discord Alerts | `modules/Notify.py` | ✅ Exists |
| Dashboard Button | `templates/dashboard.html` | ✅ Modified |
| Main Integration | `main.py` | ✅ Modified |

### Queue Behavior

- **Max Workers:** 4 assets in parallel
- **In-Memory:** Queue state lost on restart (no persistence)
- **Fail-Fast:** Failed assets are skipped, queue continues
- **UI:** Button disabled when queue active
- **Auto-refresh:** User's existing table refresh shows updates

---

## File Structure

```
LazyEASM/
├── main.py                    # Flask app, routes
├── requirements.txt           # Python dependencies
├── .env                       # Secrets (NOT in git)
├── .env.example               # Template for secrets
├── db/
│   └── lazyeasm.db            # SQLite database (NOT in git)
├── logs/                      # Log files (NOT in git)
├── modules/
│   ├── 01-parse-input.py      # Input parsing
│   ├── 02-port-scanner.py     # Nmap scan (exists)
│   ├── 03-asset-expansion.py # Phase 0 discovery
│   ├── 04-live-checker.py    # (placeholder)
│   ├── 05-http-discovery.py  # (TODO)
│   ├── 06-dirsearch.py       # (TODO)
│   ├── Wappalyzer.py          # Tech fingerprinting
│   ├── CVEmatch.py            # CVE lookup
│   ├── AskAI.py               # Gemini recommendations
│   ├── Notify.py              # Discord webhook
│   └── InitDB.py              # Database schema
├── utils/
│   ├── config.py              # Environment config
│   ├── db_utils.py            # Database helpers
│   ├── env_manager.py         # .env management
│   ├── parsing.py             # Input parsing
│   ├── utility.py             # Ping, DNS, shared hosting
│   └── queue_manager.py       # (TODO)
├── templates/
│   ├── dashboard.html         # Main UI
│   ├── table_partial.html     # Asset table
│   ├── login.html             # Login page
│   └── ...
└── backups/                   # Backup files (NOT in git)
```

---

## Environment Variables (.env)

```
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
DISCORD_USER_ID=123456789
SECURITYTRAILS_API_KEY=your_key_here
VULNERS_API_KEY=your_key_here
GEMINI_API_KEY=your_key_here
FLASK_SECRET_KEY=your_secret_here
JWT_SECRET=your_jwt_secret_here
```

---

## Next Steps

### Phase 3: Monitoring (TODO)

1. [ ] Create `utils/liveness_checker.py` - ICMP/TCP liveness checks
2. [ ] Create `utils/ct_monitor.py` - crt.sh polling for new certs/subdomains
3. [ ] Create `utils/phase3_worker.py` - Background threads (5 min liveness, 1 hr CT)
4. [ ] Add `settings` table for Phase 3 toggle
5. [ ] Add UI toggle for Phase 3 enable/disable
6. [ ] Dashboard updates for liveness status
7. [ ] CT logs events display