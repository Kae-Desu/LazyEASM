"""
Fill a separate demo database with fictional data, to try the dashboard (or
take screenshots of it) without scanning anything.

    python scripts/demo_seed.py            # creates demo/ (database, screenshots)
    python scripts/demo_seed.py --serve    # ...and serves it at http://127.0.0.1:10009

Everything is fictional: reserved domains (example.com, example.org,
example.net) and documentation IP ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24). The CVE IDs are real and the ones marked as known exploited
are in the CISA KEV catalog; CVSS is NVD's score and the EPSS values are an
illustrative snapshot. Page screenshots are rendered from local HTML.

The demo never touches the install it runs in: its database, screenshots and
.env live in demo/ (gitignored), the project's .env is not read, and no
background worker runs, so nothing is scanned.
"""

import argparse
import json
import os
import secrets
import shutil
import sys
import threading
import time
from datetime import timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO_DIR = os.path.join(ROOT, 'demo')
DEMO_PORT = 10009

# Demo .env: no real keys; shows the local-model AI option in Settings
DEMO_ENV = """TLS_MODE=off
AI_PROVIDER=openai_compatible
AI_BASE_URL=http://localhost:11434/v1
AI_MODEL=llama3.1
"""


def use_demo_paths(demo_dir: str = DEMO_DIR):
    """
    Point the app at demo_dir before it is imported: database, screenshots
    and .env. The project's own .env is never loaded.
    """
    sys.path.insert(0, ROOT)
    os.makedirs(demo_dir, exist_ok=True)
    env_file = os.path.join(demo_dir, '.env')
    if not os.path.exists(env_file):
        with open(env_file, 'w', encoding='utf-8') as f:
            f.write(DEMO_ENV)
    os.environ['FLASK_SECRET_KEY'] = secrets.token_hex(32)
    os.environ['JWT_SECRET'] = secrets.token_hex(32)
    os.environ.setdefault('LAZYEASM_LOG_DIR', os.path.join(demo_dir, 'logs'))

    import dotenv
    dotenv.load_dotenv = lambda *args, **kwargs: False        # keep the project's .env out
    from pathlib import Path
    from utils import env_manager
    env_manager.ENV_FILE = Path(env_file)
    from modules import InitDB
    from utils import db_utils, screenshots
    db_path = os.path.join(demo_dir, 'lazyeasm.db')
    InitDB.DB_NAME = db_path
    db_utils.DB_PATH = db_path
    screenshots.SCREENSHOT_DIR = os.path.join(demo_dir, 'screenshots')


# ---------------------------------------------------------------------------
# Fictional data
# ---------------------------------------------------------------------------

DOMAINS = ['example.com', 'example.org']

# subdomain: (domain, ip, status, days since first seen)
SUBDOMAINS = {
    'www.example.com': ('example.com', '203.0.113.10', 'up', 120),
    'shop.example.com': ('example.com', '203.0.113.10', 'up', 120),
    'api.example.com': ('example.com', '203.0.113.11', 'up', 90),
    'mail.example.com': ('example.com', '203.0.113.12', 'up', 120),
    'jenkins.example.com': ('example.com', '203.0.113.20', 'up', 60),
    'dev.example.com': ('example.com', '203.0.113.20', 'up', 30),
    'staging.example.com': ('example.com', '203.0.113.20', 'up', 2),
    'vpn.example.com': ('example.com', '203.0.113.25', 'up', 120),
    'files.example.com': ('example.com', '203.0.113.26', 'up', 75),
    'old.example.com': ('example.com', '192.0.2.50', 'up', 120),
    'beta.example.com': ('example.com', '203.0.113.21', 'down', 45),
    'legacy.example.org': ('example.org', '198.51.100.7', 'up', 120),
    'status.example.org': ('example.org', '198.51.100.23', 'up', 100),
    'assets.example.org': ('example.org', None, 'up', 20),
}

# Submitted directly as IPs
DIRECT_IPS = ['203.0.113.30', '203.0.113.31']
SHARED_IPS = {'198.51.100.23': 'CDN'}

PORTS = {
    '203.0.113.10': [(80, 'http'), (443, 'https')],
    '203.0.113.11': [(443, 'https')],
    '203.0.113.12': [(25, 'smtp'), (587, 'submission'), (993, 'imaps')],
    '203.0.113.20': [(22, 'ssh'), (80, 'http'), (443, 'https'), (8080, 'http-proxy')],
    '203.0.113.25': [(443, 'https')],
    '203.0.113.26': [(22, 'ssh'), (443, 'https')],
    '203.0.113.30': [(22, 'ssh'), (3306, 'mysql')],
    '203.0.113.31': [(27017, 'mongodb')],
    '198.51.100.7': [(21, 'ftp'), (80, 'http'), (443, 'https')],
    '192.0.2.50': [(80, 'http'), (443, 'https')],
}

# Web services: host -> (port, https, web server, page kind, technologies)
WEB = {
    'www.example.com': (443, 1, 'nginx', 'corporate', [('Nginx', '1.20.0'), ('jQuery', '1.12.4'), ('Bootstrap', '3.3.7')]),
    'shop.example.com': (443, 1, 'Apache', 'shop', [('Apache HTTP Server', '2.4.55'), ('PHP', '8.1.2'), ('jQuery', '1.12.4')]),
    'api.example.com': (443, 1, 'nginx', 'api', [('Nginx', '1.25.3')]),
    'jenkins.example.com': (8080, 0, 'Jetty', 'jenkins', [('Jenkins', '2.441'), ('Jetty', '10.0.18'), ('Java', None)]),
    'dev.example.com': (443, 1, 'nginx', 'dev', [('Nginx', '1.24.0'), ('Node.js', None), ('React', '18.2.0')]),
    'staging.example.com': (443, 1, 'nginx', 'staging', [('Nginx', '1.24.0'), ('Laravel', None), ('PHP', '8.2.7')]),
    'vpn.example.com': (443, 1, None, 'vpn', [('Palo Alto Networks GlobalProtect', '10.2.9')]),
    'files.example.com': (443, 1, 'Microsoft-IIS', 'files', [('MOVEit Transfer', '2023.0.1'), ('Microsoft IIS', '10.0')]),
    'legacy.example.org': (443, 1, 'Apache', 'legacy', [('Apache HTTP Server', '2.4.49'), ('PHP', '7.3.10')]),
    'status.example.org': (443, 1, 'cloudflare', 'status', [('Cloudflare', None)]),
}

# (cve, technology, version) -> (cvss, epss, in KEV, KEV date added)
CVES = [
    ('CVE-2024-23897', 'Jenkins', '2.441', 9.8, 0.974, '2024-08-19'),
    ('CVE-2023-34362', 'MOVEit Transfer', '2023.0.1', 9.8, 0.973, '2023-06-02'),
    ('CVE-2024-3400', 'Palo Alto Networks GlobalProtect', '10.2.9', 10.0, 0.957, '2024-04-12'),
    ('CVE-2021-41773', 'Apache HTTP Server', '2.4.49', 7.5, 0.975, '2021-11-03'),
    ('CVE-2021-42013', 'Apache HTTP Server', '2.4.49', 9.8, 0.974, '2021-11-03'),
    ('CVE-2019-11043', 'PHP', '7.3.10', 9.8, 0.972, '2022-03-25'),
    ('CVE-2023-25690', 'Apache HTTP Server', '2.4.55', 9.8, 0.183, None),
    ('CVE-2021-23017', 'Nginx', '1.20.0', 7.7, 0.041, None),
    ('CVE-2020-11022', 'jQuery', '1.12.4', 6.9, 0.021, None),
    ('CVE-2019-11358', 'jQuery', '1.12.4', 6.1, 0.012, None),
]
DESCRIPTIONS = {
    'CVE-2024-23897': 'Jenkins CLI command parser lets attackers read arbitrary files on the controller.',
    'CVE-2023-34362': 'SQL injection in MOVEit Transfer web application allows unauthenticated access.',
    'CVE-2024-3400': 'Command injection in the GlobalProtect feature of PAN-OS allows unauthenticated code execution.',
    'CVE-2021-41773': 'Path traversal in Apache HTTP Server 2.4.49 maps URLs to files outside the document root.',
    'CVE-2021-42013': 'Incomplete fix for CVE-2021-41773 in 2.4.50 allows path traversal and remote code execution.',
    'CVE-2019-11043': 'PHP-FPM with certain nginx configurations allows remote code execution (env_path_info underflow).',
    'CVE-2023-25690': 'HTTP request smuggling in mod_proxy with certain RewriteRule configurations.',
    'CVE-2021-23017': 'Off-by-one in the nginx resolver may allow memory overwrite via forged DNS responses.',
    'CVE-2020-11022': 'Passing HTML from untrusted sources to jQuery DOM methods may execute untrusted code.',
    'CVE-2019-11358': 'jQuery.extend(true, {}, ...) is vulnerable to Object.prototype pollution.',
}
# Triage already done on some issues: (host, cve) -> (status, note)
CVE_TRIAGE = {
    ('www.example.com', 'CVE-2021-23017'): ('accepted', 'Resolver not configured on this host'),
}

# Non-CVE findings: (type, host, title, severity, evidence, status, days ago)
FINDINGS = [
    ('exposed_git', 'dev.example.com', 'Git repository exposed', 'high',
     {'detail': 'The .git directory is downloadable, exposing source code and history.',
      'urls': ['https://dev.example.com/.git/HEAD']}, 'open', 5),
    ('exposed_env', 'staging.example.com', 'Environment file exposed', 'high',
     {'detail': 'The .env file is downloadable and may contain credentials.',
      'urls': ['https://staging.example.com/.env']}, 'open', 1),
    ('exposed_port_27017', '203.0.113.31', 'MongoDB exposed to the internet (port 27017)', 'high',
     {'detail': 'MongoDB on port 27017 is reachable from the internet: often runs without authentication.',
      'urls': ['203.0.113.31:27017'], 'port': 27017, 'service': 'MongoDB'}, 'open', 12),
    ('exposed_port_3306', '203.0.113.30', 'MySQL exposed to the internet (port 3306)', 'medium',
     {'detail': 'MySQL on port 3306 is reachable from the internet: database exposed to the internet.',
      'urls': ['203.0.113.30:3306'], 'port': 3306, 'service': 'MySQL'}, 'open', 40),
    ('dangling_cname', 'assets.example.org', 'Dangling CNAME to landing.example.net', 'medium',
     {'cname_chain': ['assets.example.org', 'landing.example.net'], 'target_missing': True,
      'signal': 'CNAME target does not exist'}, 'open', 3),
    ('tls_legacy_protocol', 'legacy.example.org', 'Legacy TLS versions enabled', 'medium',
     {'detail': 'Server accepts TLS 1.0, TLS 1.1, which are deprecated and insecure.',
      'urls': ['https://legacy.example.org/'], 'versions': ['TLS 1.0', 'TLS 1.1']}, 'open', 60),
    ('directory_listing', 'legacy.example.org', 'Directory listing enabled', 'medium',
     {'detail': 'The web server lists directory contents, exposing file names.',
      'urls': ['https://legacy.example.org/backup/']}, 'open', 60),
    ('missing_security_headers', 'shop.example.com', 'Missing security headers', 'low',
     {'detail': 'Missing: Content-Security-Policy, Strict-Transport-Security.',
      'urls': ['https://shop.example.com/'], 'missing': ['Content-Security-Policy', 'Strict-Transport-Security']},
     'open', 30),
    ('unserved_hostname', 'old.example.com', 'Hostname points to a server that does not serve it', 'low',
     {'detail': 'DNS points old.example.com to 192.0.2.50, but the web server there rejects TLS for this name.',
      'urls': ['https://old.example.com/']}, 'open', 9),
    ('http_no_https_redirect', 'www.example.com', 'HTTP served without redirect to HTTPS', 'low',
     {'detail': 'Content is available over unencrypted HTTP although HTTPS works.',
      'urls': ['http://www.example.com/']}, 'fixed', 20),
    ('missing_security_headers', 'api.example.com', 'Missing security headers', 'low',
     {'detail': 'Missing: X-Content-Type-Options.', 'urls': ['https://api.example.com/'],
      'missing': ['X-Content-Type-Options']}, 'false_positive', 25),
]

# Certificates presented by HTTPS services: host -> days until expiry (negative: expired)
CERT_EXPIRY = {
    'www.example.com': 74, 'shop.example.com': 74, 'api.example.com': 52, 'dev.example.com': 33,
    'staging.example.com': 88, 'vpn.example.com': 9, 'files.example.com': 160, 'legacy.example.org': -3,
    'status.example.org': 61,
}

# Change history: (hours ago, host, type, summary)
CHANGES = [
    (2, 'staging.example.com', 'finding_opened', 'Environment file exposed (high)'),
    (3, 'jenkins.example.com', 'vulnerability_found', 'CVE-2024-23897 in Jenkins 2.441 (known exploited)'),
    (5, 'vpn.example.com', 'certificate_changed', 'Certificate expires in 9 days'),
    (26, 'staging.example.com', 'asset_added', 'New subdomain found in certificate transparency logs'),
    (27, 'staging.example.com', 'port_opened', 'Port 443/tcp opened (https)'),
    (30, 'dev.example.com', 'tech_version_changed', 'React 18.1.0 -> 18.2.0'),
    (49, 'beta.example.com', 'asset_down', 'Host stopped responding'),
    (52, 'shop.example.com', 'appearance_changed', 'Page looks different from the previous screenshot'),
    (73, 'assets.example.org', 'finding_opened', 'Dangling CNAME to landing.example.net (medium)'),
    (98, 'www.example.com', 'finding_fixed', 'HTTP served without redirect to HTTPS: no longer detected'),
    (120, 'dev.example.com', 'finding_opened', 'Git repository exposed (high)'),
    (122, 'www.example.com', 'status_changed', 'CVE-2021-23017 marked accepted'),
    (140, 'api.example.com', 'tech_added', 'Nginx 1.25.3 detected'),
    (150, '203.0.113.31', 'port_opened', 'Port 27017/tcp opened (mongodb)'),
]

# Scan queue history: (type, cycle, target, target type, status, hours ago, minutes taken)
SCANS = [
    ('monitor_run', 'manual', 'misconfig', 'monitor', 'completed', 1, 4),
    ('phase1', 'standard', 'staging.example.com', 'subdomain', 'completed', 26, 6),
    ('input_discovery', 'standard', '{"domains": ["example.org"]}', 'input', 'completed', 480, 3),
    ('phase0_discovery', 'continuous_monitoring', 'staging.example.com', 'subdomain', 'completed', 26, 1),
    ('phase2_deep_scan', 'phase2', 'legacy.example.org', 'subdomain', 'completed', 70, 38),
    ('monitor_run', 'manual', 'screenshots', 'monitor', 'completed', 22, 2),
    ('phase1', 'standard', 'assets.example.org', 'subdomain', 'completed', 73, 3),
]


# ---------------------------------------------------------------------------
# Page images (rendered from local HTML, no network)
# ---------------------------------------------------------------------------

def _page(title, body, accent='#2b59c3', background='#f4f6fb'):
    return f"""<!doctype html><html><head><title>{title}</title><style>
    body {{ margin:0; font-family: Segoe UI, Arial, sans-serif; background:{background}; color:#1d2433; }}
    header {{ background:{accent}; color:white; padding:18px 40px; font-size:22px; font-weight:600; }}
    main {{ padding:40px; }} .card {{ background:white; border-radius:10px; padding:32px; max-width:420px;
    margin:40px auto; box-shadow:0 4px 18px rgba(0,0,0,.08); }} input {{ width:100%; padding:10px; margin:8px 0;
    border:1px solid #ccd; border-radius:6px; box-sizing:border-box; }} button {{ width:100%; padding:11px;
    background:{accent}; color:white; border:0; border-radius:6px; font-size:15px; }}
    .grid {{ display:grid; grid-template-columns:repeat(3,1fr); gap:20px; }} .tile {{ background:white;
    border-radius:8px; height:140px; box-shadow:0 2px 8px rgba(0,0,0,.06); }} pre {{ font-size:15px; }}
    </style></head><body>{body}</body></html>"""


def _login(product, accent):
    return _page(f'Sign in - {product}', f"""<header>{product}</header><div class="card"><h2>Sign in</h2>
        <input placeholder="Username"><input placeholder="Password" type="password"><button>Sign in</button>
        </div>""", accent)


PAGES = {
    'corporate': ('Example Corp', _page('Example Corp', """<header>Example Corp</header><main>
        <h1>Infrastructure for everyone</h1><p>Fictional company used for the LazyEASM demo.</p>
        <div class="grid"><div class="tile"></div><div class="tile"></div><div class="tile"></div></div></main>""")),
    'shop': ('Example Shop', _page('Example Shop', """<header>Example Shop</header><main><h1>Spring sale</h1>
        <div class="grid"><div class="tile"></div><div class="tile"></div><div class="tile"></div>
        <div class="tile"></div><div class="tile"></div><div class="tile"></div></div></main>""", '#c3462b')),
    'api': ('Example API', _page('Example API', """<main><pre>{"service": "example-api", "status": "ok",
  "docs": "/v2/docs"}</pre></main>""", background='#ffffff')),
    'jenkins': ('Sign in [Jenkins]', _login('Jenkins', '#335061')),
    'dev': ('Example Dev Portal', _login('Example Dev Portal', '#6b3fa0')),
    'staging': ('Example (staging)', _page('Example (staging)', """<header>STAGING - Example Corp</header>
        <main><h1>Staging environment</h1><p>Not for production use.</p></main>""", '#d48a00')),
    'vpn': ('GlobalProtect Portal', _login('GlobalProtect Portal', '#1f3f5f')),
    'files': ('Example File Transfer', _login('Example File Transfer', '#00747a')),
    'legacy': ('Index of /', _page('Index of /', """<main><h1>Index of /</h1><pre>
<a>backup/</a>              2019-03-02 11:20    -
<a>old-site/</a>            2018-11-14 09:02    -
<a>phpinfo.php</a>          2019-03-02 11:21   21
</pre></main>""", background='#ffffff')),
    'status': ('Example Status', _page('Example Status', """<header>Example Status</header><main>
        <h2>All systems operational</h2><div class="grid"><div class="tile"></div><div class="tile"></div>
        <div class="tile"></div></div></main>""", '#2e8b57')),
}


def render_pages() -> dict:
    """{page kind: (title, jpeg bytes)} rendered with the headless browser, offline."""
    from playwright.sync_api import sync_playwright
    images = {}
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={'width': 1280, 'height': 800})
        page.route('**/*', lambda route: route.abort())            # no network at all
        for kind, (title, html) in PAGES.items():
            page.set_content(html)
            images[kind] = (title, page.screenshot(type='jpeg', quality=80))
        browser.close()
    return images


# ---------------------------------------------------------------------------
# Seeding
# ---------------------------------------------------------------------------

def seed(demo_dir: str = DEMO_DIR):
    """Create a fresh demo database in demo_dir (an existing one is replaced)."""
    for name in ('lazyeasm.db', 'lazyeasm.db-wal', 'lazyeasm.db-shm'):
        path = os.path.join(demo_dir, name)
        if os.path.exists(path):
            os.remove(path)
    shutil.rmtree(os.path.join(demo_dir, 'screenshots'), ignore_errors=True)

    import contextlib
    import io
    from modules import InitDB
    from utils import screenshots
    from utils.db_utils import get_db_connection
    from utils.timeutil import utc_now

    with contextlib.redirect_stdout(io.StringIO()):
        InitDB.init_db()
    now = utc_now()

    def ago(days=0, hours=0):
        return (now - timedelta(days=days, hours=hours)).strftime('%Y-%m-%d %H:%M:%S')

    def ahead(days):
        return (now + timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')

    images = render_pages()
    os.makedirs(screenshots.SCREENSHOT_DIR, exist_ok=True)

    conn = get_db_connection()
    try:
        c = conn.cursor()
        dom_ids, sub_ids, ip_ids, http_ids = {}, {}, {}, {}

        for domain in DOMAINS:
            c.execute('INSERT INTO domain_asset (domain_name, first_seen, last_seen, last_scanned, status, expand) '
                      'VALUES (?, ?, ?, ?, ?, 1)', (domain, ago(120), ago(hours=1), ago(1), 'up'))
            dom_ids[domain] = c.lastrowid

        all_ips = sorted({ip for _, ip, _, _ in SUBDOMAINS.values() if ip} | set(DIRECT_IPS))
        for ip in all_ips:
            c.execute('INSERT INTO ip_asset (ip_value, is_shared, shared_provider, first_seen, last_seen, '
                      'last_scanned, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
                      (ip, int(ip in SHARED_IPS), SHARED_IPS.get(ip), ago(120), ago(hours=1), ago(1),
                       'down' if ip == '203.0.113.21' else 'up'))
            ip_ids[ip] = c.lastrowid
            for port, service in PORTS.get(ip, []):
                c.execute('INSERT INTO ports (ip_id, port_num, service_name, first_seen) VALUES (?, ?, ?, ?)',
                          (ip_ids[ip], port, service, ago(100)))

        for host, (domain, ip, status, age) in SUBDOMAINS.items():
            c.execute('INSERT INTO subdomain_asset (dom_id, subdomain_name, first_seen, last_seen, last_scanned, '
                      'status) VALUES (?, ?, ?, ?, ?, ?)', (dom_ids[domain], host, ago(age), ago(hours=1), ago(1), status))
            sub_ids[host] = c.lastrowid
            if ip:
                c.execute('INSERT INTO subdomain_ip (sub_id, ip_id) VALUES (?, ?)', (sub_ids[host], ip_ids[ip]))

        tech_ids = {}
        for host, (port, https, server, kind, techs) in WEB.items():
            ip = SUBDOMAINS[host][1]
            title, image = images[kind]
            c.execute('INSERT INTO http_services (host, ip_id, port_num, is_https, title, web_server, first_seen, '
                      'last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                      (host, ip_ids.get(ip), port, https, title, server, ago(SUBDOMAINS[host][3]), ago(hours=1)))
            http_ids[host] = c.lastrowid
            for name, version in techs:
                c.execute('INSERT INTO technologies (http_id, tech_name, tech_version, first_seen) VALUES (?, ?, ?, ?)',
                          (http_ids[host], name, version, ago(min(60, SUBDOMAINS[host][3]))))
                tech_ids[(host, name)] = c.lastrowid
            token = secrets.token_hex(16)
            image_file, thumb_file = f'{token}.jpg', f'{token}_thumb.jpg'
            with open(os.path.join(screenshots.SCREENSHOT_DIR, image_file), 'wb') as f:
                f.write(image)
            with open(os.path.join(screenshots.SCREENSHOT_DIR, thumb_file), 'wb') as f:
                f.write(screenshots.make_thumbnail(image))
            url = f"{'https' if https else 'http'}://{host}{'' if port in (80, 443) else f':{port}'}/"
            c.execute('INSERT INTO screenshots (http_id, host, url, final_url, status_code, title, image_file, '
                      'thumb_file, phash, captured_at) VALUES (?, ?, ?, ?, 200, ?, ?, ?, ?, ?)',
                      (http_ids[host], host, url, url, title, image_file, thumb_file,
                       screenshots.average_hash(image), ago(hours=22)))

        for cve, tech, version, cvss, epss, kev_date in CVES:
            c.execute('INSERT INTO cve_intel (cve_id, epss, epss_percentile, epss_date, in_kev, kev_date_added, '
                      'kev_due_date, kev_required_action, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                      (cve, epss, min(0.999, 0.5 + epss / 2), now.strftime('%Y-%m-%d'), int(bool(kev_date)), kev_date,
                       kev_date, 'Apply mitigations per vendor instructions or discontinue use of the product.'
                       if kev_date else None, ago(hours=3)))
            for host, (_, _, _, _, techs) in WEB.items():
                if (tech, version) not in techs:
                    continue
                status, note = CVE_TRIAGE.get((host, cve), ('open', None))
                c.execute('INSERT INTO vulnerabilities (tech_id, cve_id, cve_score, description, status, first_seen, '
                          'last_seen, status_note, status_updated_at, match_method) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                          (tech_ids[(host, tech)], cve, cvss, DESCRIPTIONS[cve], status,
                           ago(hours=3) if host == 'jenkins.example.com' else ago(min(50, SUBDOMAINS[host][3])),
                           ago(hours=1), note, ago(5) if note else None,
                           'retirejs' if tech == 'jQuery' else 'cpe'))

        for ftype, host, title, severity, evidence, status, days in FINDINGS:
            c.execute('INSERT INTO findings (finding_type, host, title, severity, evidence, status, status_updated_at, '
                      'first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                      (ftype, host, title, severity, json.dumps(evidence, sort_keys=True), status,
                       ago(4) if status != 'open' else None, ago(days), ago(hours=1)))

        for host, days in CERT_EXPIRY.items():
            port = WEB[host][0]
            c.execute('INSERT INTO certificates (sub_id, hostname, issuer, not_before, not_after, serial_number, '
                      'fingerprint, source, port, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                      (sub_ids[host], host, 'Example Issuing CA', ahead(days - 90), ahead(days),
                       secrets.token_hex(8), secrets.token_hex(32), 'tls', port, ago(30), ago(hours=1)))

        for hours, host, change_type, summary in CHANGES:
            c.execute('INSERT INTO asset_changes (host, change_type, summary, details, detected_at) '
                      'VALUES (?, ?, ?, ?, ?)', (host, change_type, summary, None, ago(hours=hours)))

        for scan_type, cycle, target, target_type, status, hours, minutes in SCANS:
            c.execute('INSERT INTO scan_queue (scan_type, cycle, target, target_type, status, queued_at, started_at, '
                      'completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                      (scan_type, cycle, target, target_type, status, ago(hours=hours), ago(hours=hours),
                       ago(hours=hours - minutes / 60)))

        for key, value in (('phase3_enabled', '1'), ('last_screenshot_check', ago(hours=22))):
            c.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, value))
        conn.commit()
    finally:
        conn.close()
    write_heartbeat()


def write_heartbeat():
    """A fresh worker heartbeat, so the dashboard shows the worker as running."""
    from datetime import datetime, timezone
    from utils.db_utils import set_setting
    set_setting('worker_heartbeat', json.dumps({
        'ts': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), 'pid': 0,
        'components': {name: True for name in ('phase0', 'discovery', 'phase1', 'phase2', 'phase3')}}))


def keep_heartbeat():
    def loop():
        while True:
            time.sleep(15)
            write_heartbeat()
    threading.Thread(target=loop, daemon=True).start()


def create_demo_account() -> tuple:
    from utils import auth
    password = secrets.token_urlsafe(12)
    if not auth.create_admin('demo', password):
        auth.set_admin_password('demo', password)
    return 'demo', password


def main():
    parser = argparse.ArgumentParser(description='Fictional demo data for LazyEASM')
    parser.add_argument('--dir', default=DEMO_DIR, help='where to create the demo (default: demo/)')
    parser.add_argument('--serve', action='store_true', help=f'serve the demo at http://127.0.0.1:{DEMO_PORT}')
    args = parser.parse_args()

    use_demo_paths(args.dir)
    seed(args.dir)
    print(f"Demo data written to {args.dir}", flush=True)
    if not args.serve:
        return

    user, password = create_demo_account()
    keep_heartbeat()
    import main as app_main
    from waitress import serve
    print(f"Serving the demo at http://127.0.0.1:{DEMO_PORT}  (sign in as {user} / {password}; Ctrl+C to stop)", flush=True)
    serve(app_main.app, host='127.0.0.1', port=DEMO_PORT, threads=4)


if __name__ == '__main__':
    main()
