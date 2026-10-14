"""
Module: InitDB.py
Purpose: Initialize LazyEASM database with asset-centric schema

Tables:
    - domain_asset: Root domains (example.com)
    - subdomain_asset: Subdomains (blog.example.com)
    - ip_asset: IP addresses (1.2.3.4)
    - domain_ip: Junction table (domain -> IP)
    - subdomain_ip: Junction table (subdomain -> IP)
    - ports: Open ports on IPs (from nmap)
    - http_services: HTTP services per (host + port) - virtual hosting support
    - technologies: Tech stack per http_service (from Wappalyzer)
    - vulnerabilities: CVEs per technology
    - certificates: SSL/TLS certificate info (from CTLogs)
    - directories: Discovered directories (from dirsearch)
    - scan_hints: User-specified ports/paths from input
    - scan_history: Track scan runs per module
    - scan_queue: Queue for long-running scan tasks
    - scan_progress: Track progress for resumable scans
"""

import sqlite3
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_DIR = os.path.join(PROJECT_ROOT, "db")

if not os.path.exists(DB_DIR):
    os.makedirs(DB_DIR)

DB_NAME = os.path.join(DB_DIR, "lazyeasm.db")


def init_db():
    conn = sqlite3.connect(DB_NAME, timeout=30)
    # Owner-only, like .env: the database holds the asset inventory, findings
    # and the admin password hash. SQLite creates -wal/-shm with the same mode.
    try:
        os.chmod(DB_NAME, 0o600)
    except OSError:
        pass
    conn.execute("PRAGMA foreign_keys = ON;")
    # WAL lets the web process read while the worker writes. The setting is
    # stored in the database file, so it applies to every later connection.
    conn.execute("PRAGMA journal_mode = WAL;")
    cursor = conn.cursor()

    print(f"Connection initialized to {DB_NAME}")

    # ============================================
    # ASSET TABLES
    # ============================================

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS domain_asset (
        dom_id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain_name TEXT UNIQUE NOT NULL,
        first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
        last_seen TEXT,
        last_scanned TEXT,
        last_wappalyzer_scan TEXT,
        status TEXT DEFAULT 'up',
        is_wildcard INTEGER DEFAULT 0,
        wildcard_ip TEXT,
        notes TEXT
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS subdomain_asset (
        sub_id INTEGER PRIMARY KEY AUTOINCREMENT,
        dom_id INTEGER,
        subdomain_name TEXT UNIQUE NOT NULL,
        first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
        last_seen TEXT,
        last_scanned TEXT,
        last_wappalyzer_scan TEXT,
        status TEXT DEFAULT 'up',
        FOREIGN KEY(dom_id) REFERENCES domain_asset(dom_id) ON DELETE SET NULL
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS ip_asset (
        ip_id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_value TEXT UNIQUE NOT NULL,
        is_private INTEGER DEFAULT 0,
        is_shared INTEGER DEFAULT 0,
        shared_provider TEXT,
        first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
        last_seen TEXT,
        last_scanned TEXT,
        status TEXT DEFAULT 'up'
    )
    ''')

    # ============================================
    # JUNCTION TABLES (Asset Relationships)
    # ============================================

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS domain_ip (
        dom_id INTEGER,
        ip_id INTEGER,
        PRIMARY KEY (dom_id, ip_id),
        FOREIGN KEY(dom_id) REFERENCES domain_asset(dom_id) ON DELETE CASCADE,
        FOREIGN KEY(ip_id) REFERENCES ip_asset(ip_id) ON DELETE CASCADE
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS subdomain_ip (
        sub_id INTEGER,
        ip_id INTEGER,
        PRIMARY KEY (sub_id, ip_id),
        FOREIGN KEY(sub_id) REFERENCES subdomain_asset(sub_id) ON DELETE CASCADE,
        FOREIGN KEY(ip_id) REFERENCES ip_asset(ip_id) ON DELETE CASCADE
    )
    ''')

    # ============================================
    # SERVICE TABLES
    # ============================================

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS ports (
        port_id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_id INTEGER NOT NULL,
        port_num INTEGER NOT NULL,
        protocol TEXT DEFAULT 'tcp',
        service_name TEXT,
        banner TEXT,
        first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(ip_id) REFERENCES ip_asset(ip_id) ON DELETE CASCADE
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS http_services (
        http_id INTEGER PRIMARY KEY AUTOINCREMENT,
        host TEXT NOT NULL,
        ip_id INTEGER,
        port_num INTEGER NOT NULL,
        is_https INTEGER DEFAULT 0,
        title TEXT,
        web_server TEXT,
        first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
        last_seen TEXT,
        UNIQUE(host, port_num),
        FOREIGN KEY(ip_id) REFERENCES ip_asset(ip_id) ON DELETE SET NULL
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS technologies (
        tech_id INTEGER PRIMARY KEY AUTOINCREMENT,
        http_id INTEGER NOT NULL,
        tech_name TEXT NOT NULL,
        tech_version TEXT,
        first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(http_id) REFERENCES http_services(http_id) ON DELETE CASCADE
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        vuln_id INTEGER PRIMARY KEY AUTOINCREMENT,
        tech_id INTEGER,
        cve_id TEXT NOT NULL,
        cve_score REAL,
        description TEXT,
        recommendation TEXT,
        status TEXT DEFAULT 'open',
        first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
        last_seen TEXT,
        status_note TEXT,
        status_updated_at TEXT,
        match_method TEXT DEFAULT 'cpe',
        FOREIGN KEY(tech_id) REFERENCES technologies(tech_id) ON DELETE SET NULL
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS cve_cache (
        cpe TEXT PRIMARY KEY,
        result_json TEXT NOT NULL,
        fetched_at TEXT NOT NULL
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS certificates (
        cert_id INTEGER PRIMARY KEY AUTOINCREMENT,
        sub_id INTEGER,
        hostname TEXT NOT NULL,
        issuer TEXT,
        not_before TEXT,
        not_after TEXT,
        serial_number TEXT,
        fingerprint TEXT,
        source TEXT DEFAULT 'ctlogs',
        first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(sub_id) REFERENCES subdomain_asset(sub_id) ON DELETE CASCADE
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS directories (
        dir_id INTEGER PRIMARY KEY AUTOINCREMENT,
        http_id INTEGER NOT NULL,
        path TEXT NOT NULL,
        status_code INTEGER,
        content_length INTEGER,
        redirect_url TEXT,
        title TEXT,
        first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(http_id) REFERENCES http_services(http_id) ON DELETE CASCADE
    )
    ''')

    # ============================================
    # SCAN TRACKING TABLES
    # ============================================

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS scan_hints (
        hint_id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT NOT NULL,
        hint_type TEXT NOT NULL,
        hint_value TEXT NOT NULL,
        source TEXT DEFAULT 'input',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS scan_history (
        scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_type TEXT NOT NULL,
        target TEXT NOT NULL,
        started_at TEXT,
        completed_at TEXT,
        status TEXT,
        items_found INTEGER DEFAULT 0
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS scan_queue (
        queue_id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_type TEXT NOT NULL,
        cycle TEXT NOT NULL,
        target TEXT NOT NULL,
        target_id INTEGER,
        target_type TEXT,
        status TEXT DEFAULT 'pending',
        queued_at TEXT DEFAULT CURRENT_TIMESTAMP,
        started_at TEXT,
        completed_at TEXT,
        ports_found INTEGER DEFAULT 0,
        tech_found INTEGER DEFAULT 0,
        cve_found INTEGER DEFAULT 0,
        error_message TEXT
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS scan_progress (
        progress_id INTEGER PRIMARY KEY AUTOINCREMENT,
        cycle TEXT NOT NULL,
        scan_type TEXT NOT NULL,
        current_target TEXT,
        current_position INTEGER DEFAULT 0,
        total_targets INTEGER DEFAULT 0,
        status TEXT DEFAULT 'idle',
        started_at TEXT,
        updated_at TEXT
    )
    ''')

    # ============================================
    # SETTINGS (Phase 3 and general config)
    # ============================================
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        description TEXT,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Insert default settings
    cursor.execute("INSERT OR IGNORE INTO settings (key, value, description) VALUES ('phase3_enabled', '1', 'Enable Phase 3 continuous monitoring')")
    cursor.execute("INSERT OR IGNORE INTO settings (key, value, description) VALUES ('liveness_interval_min', '5', 'Liveness check interval in minutes')")
    cursor.execute("INSERT OR IGNORE INTO settings (key, value, description) VALUES ('ctlogs_interval_hr', '6', 'Certificates & CT logs interval in hours')")
    cursor.execute("INSERT OR IGNORE INTO settings (key, value, description) VALUES ('last_liveness_check', NULL, 'Last liveness check timestamp')")
    cursor.execute("INSERT OR IGNORE INTO settings (key, value, description) VALUES ('last_ctlogs_check', NULL, 'Last CT logs check timestamp')")
    cursor.execute("INSERT OR IGNORE INTO settings (key, value, description) VALUES ('wappalyzer_interval_hr', '24', 'Wappalyzer re-scan interval in hours')")
    cursor.execute("INSERT OR IGNORE INTO settings (key, value, description) VALUES ('last_wappalyzer_check', NULL, 'Last Wappalyzer scan timestamp')")

    # ============================================
    # INDEXES FOR PERFORMANCE
    # ============================================

    cursor.execute('CREATE INDEX IF NOT EXISTS idx_domain_name ON domain_asset(domain_name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_domain_status ON domain_asset(status)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_subdomain_name ON subdomain_asset(subdomain_name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_subdomain_status ON subdomain_asset(status)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_value ON ip_asset(ip_value)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_status ON ip_asset(status)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_last_scanned ON ip_asset(last_scanned)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_ports_ip_id ON ports(ip_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_http_host_port ON http_services(host, port_num)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_tech_http_id ON technologies(http_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_vuln_tech_id ON vulnerabilities(tech_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_vuln_status ON vulnerabilities(status)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_cert_hostname ON certificates(hostname)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_cert_not_after ON certificates(not_after)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_cert_sub_id ON certificates(sub_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_dirs_http_id ON directories(http_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_hints_target ON scan_hints(target)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_queue_status ON scan_queue(status)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_queue_cycle ON scan_queue(cycle)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_queue_target_type ON scan_queue(target_type)')
    
    # Unique index to prevent duplicate pending/processing entries
    cursor.execute('''
        CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_pending_queue
        ON scan_queue (scan_type, target)
        WHERE status IN ('pending', 'processing')
    ''')

    # ============================================
    # TOKEN BLACKLIST (Refresh token revocation)
    # ============================================
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS token_blacklist (
            jti TEXT PRIMARY KEY,
            user TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('CREATE INDEX IF NOT EXISTS idx_blacklist_expires ON token_blacklist(expires_at)')

    # ============================================
    # CERTIFICATE NOTIFICATION TRACKING
    # ============================================
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cert_notifications (
            notif_id INTEGER PRIMARY KEY AUTOINCREMENT,
            cert_id INTEGER NOT NULL,
            hostname TEXT NOT NULL,
            days_threshold INTEGER NOT NULL,
            notified_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(cert_id, days_threshold),
            FOREIGN KEY(cert_id) REFERENCES certificates(cert_id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('CREATE INDEX IF NOT EXISTS idx_cert_notif_lookup ON cert_notifications(cert_id, days_threshold)')

    # ============================================
    # PHASE STATUS TRACKING
    # ============================================
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS phase_status (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            current_phase INTEGER DEFAULT 0,
            started_at TEXT,
            total_assets INTEGER DEFAULT 0,
            processed_assets INTEGER DEFAULT 0,
            eta_minutes INTEGER
        )
    ''')
    
    cursor.execute('INSERT OR IGNORE INTO phase_status (id, current_phase) VALUES (1, 0)')

    # ============================================
    # MIGRATIONS (for existing databases)
    # ============================================
    cursor.execute("PRAGMA table_info(subdomain_asset)")
    subdomain_columns = [col[1] for col in cursor.fetchall()]
    if 'last_scanned' not in subdomain_columns:
        cursor.execute("ALTER TABLE subdomain_asset ADD COLUMN last_scanned TEXT")
    
    # Add last_deep_scan column to domain_asset
    cursor.execute("PRAGMA table_info(domain_asset)")
    domain_columns = [col[1] for col in cursor.fetchall()]
    if 'last_deep_scan' not in domain_columns:
        cursor.execute("ALTER TABLE domain_asset ADD COLUMN last_deep_scan TEXT")
    
    # Add last_deep_scan column to subdomain_asset
    if 'last_deep_scan' not in subdomain_columns:
        cursor.execute("ALTER TABLE subdomain_asset ADD COLUMN last_deep_scan TEXT")

    # Add last_dirsearch column to domain_asset and subdomain_asset
    if 'last_dirsearch' not in domain_columns:
        cursor.execute("ALTER TABLE domain_asset ADD COLUMN last_dirsearch TEXT")
    if 'last_dirsearch' not in subdomain_columns:
        cursor.execute("ALTER TABLE subdomain_asset ADD COLUMN last_dirsearch TEXT")

    # Add last_liveness_check column to domain_asset and subdomain_asset
    if 'last_liveness_check' not in domain_columns:
        cursor.execute("ALTER TABLE domain_asset ADD COLUMN last_liveness_check TEXT")
    if 'last_liveness_check' not in subdomain_columns:
        cursor.execute("ALTER TABLE subdomain_asset ADD COLUMN last_liveness_check TEXT")
    cursor.execute("PRAGMA table_info(ip_asset)")
    if 'last_liveness_check' not in [col[1] for col in cursor.fetchall()]:
        cursor.execute("ALTER TABLE ip_asset ADD COLUMN last_liveness_check TEXT")

    # Scope: a domain added only as the parent of a submitted subdomain is a
    # container (expand = 0): not scanned, monitored or used for discovery
    cursor.execute("PRAGMA table_info(domain_asset)")
    if 'expand' not in [col[1] for col in cursor.fetchall()]:
        cursor.execute("ALTER TABLE domain_asset ADD COLUMN expand INTEGER DEFAULT 1")

    # Certificates are read from the services themselves (source 'tls'); rows
    # from CT logs were never accurate for expiry (renewed certificates stay
    # listed) and are no longer read, so they are removed
    cursor.execute("PRAGMA table_info(certificates)")
    cert_columns = [col[1] for col in cursor.fetchall()]
    for column in ('port INTEGER', 'last_seen TEXT', 'replaced_at TEXT'):
        if column.split()[0] not in cert_columns:
            cursor.execute(f"ALTER TABLE certificates ADD COLUMN {column}")
    cursor.execute("DELETE FROM certificates WHERE source = 'ctlogs'")
    # The CT poll default moved from 1 to 6 hours (hourly polling is what makes
    # crt.sh return 502s); move installs still on the old default, once
    if not cursor.execute("SELECT 1 FROM settings WHERE key = 'ctlogs_default_moved_to_6h'").fetchone():
        cursor.execute("UPDATE settings SET value = '6' WHERE key = 'ctlogs_interval_hr' AND value = '1'")
        cursor.execute("INSERT INTO settings (key, value, description) VALUES ('ctlogs_default_moved_to_6h', '1', 'Migration marker')")
    cursor.execute("DELETE FROM cert_notifications WHERE cert_id NOT IN (SELECT cert_id FROM certificates)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_certificates_served ON certificates(hostname, port, source, replaced_at)")

    # Add last_wappalyzer_scan column to domain_asset and subdomain_asset
    if 'last_wappalyzer_scan' not in domain_columns:
        cursor.execute("ALTER TABLE domain_asset ADD COLUMN last_wappalyzer_scan TEXT")
    if 'last_wappalyzer_scan' not in subdomain_columns:
        cursor.execute("ALTER TABLE subdomain_asset ADD COLUMN last_wappalyzer_scan TEXT")
    
    # Add ports_found and dirs_found to scan_queue if not exists
    cursor.execute("PRAGMA table_info(scan_queue)")
    queue_columns = [col[1] for col in cursor.fetchall()]
    if 'ports_found' not in queue_columns:
        cursor.execute("ALTER TABLE scan_queue ADD COLUMN ports_found INTEGER DEFAULT 0")
    if 'dirs_found' not in queue_columns:
        cursor.execute("ALTER TABLE scan_queue ADD COLUMN dirs_found INTEGER DEFAULT 0")
    if 'error_message' not in queue_columns:
        cursor.execute("ALTER TABLE scan_queue ADD COLUMN error_message TEXT")

    # Finding lifecycle columns. Rows that predate CPE matching came from
    # keyword search, so they are tagged 'keyword' to be re-verified on rescan.
    cursor.execute("PRAGMA table_info(vulnerabilities)")
    vuln_columns = [col[1] for col in cursor.fetchall()]
    if 'status_note' not in vuln_columns:
        cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN status_note TEXT")
    if 'status_updated_at' not in vuln_columns:
        cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN status_updated_at TEXT")
    if 'match_method' not in vuln_columns:
        cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN match_method TEXT DEFAULT 'cpe'")
        cursor.execute("UPDATE vulnerabilities SET match_method = 'keyword'")

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cve_cache (
            cpe TEXT PRIMARY KEY,
            result_json TEXT NOT NULL,
            fetched_at TEXT NOT NULL
        )
    ''')

    # Non-CVE security findings (subdomain takeover, misconfigurations).
    # Same lifecycle as vulnerabilities: open / fixed / accepted / false_positive.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_type TEXT NOT NULL,
            host TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            evidence TEXT,
            status TEXT DEFAULT 'open',
            status_note TEXT,
            status_updated_at TEXT,
            first_seen TEXT,
            last_seen TEXT,
            UNIQUE(finding_type, host)
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(host)')

    # Single admin account; the password is stored hashed (see utils/auth.py)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_user (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            token_version INTEGER NOT NULL DEFAULT 1,
            password_changed_at TEXT
        )
    ''')

    # Web screenshots (files in db/screenshots/, see utils/screenshots.py)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS screenshots (
            screenshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
            http_id INTEGER NOT NULL,
            host TEXT NOT NULL,
            url TEXT NOT NULL,
            final_url TEXT,
            status_code INTEGER,
            title TEXT,
            image_file TEXT NOT NULL,
            thumb_file TEXT NOT NULL,
            phash TEXT,
            captured_at TEXT NOT NULL
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_screenshots_host ON screenshots(host, captured_at)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_screenshots_http ON screenshots(http_id, captured_at)')

    # Change history: one row per detected change on a host
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS asset_changes (
            change_id INTEGER PRIMARY KEY AUTOINCREMENT,
            host TEXT NOT NULL,
            change_type TEXT NOT NULL,
            summary TEXT NOT NULL,
            details TEXT,
            detected_at TEXT NOT NULL
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_changes_host ON asset_changes(host, detected_at)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_changes_time ON asset_changes(detected_at)')

    # Technologies no longer detected on a re-scan are marked removed (rows are
    # kept so vulnerability history stays linked)
    cursor.execute("PRAGMA table_info(technologies)")
    if 'removed_at' not in [col[1] for col in cursor.fetchall()]:
        cursor.execute("ALTER TABLE technologies ADD COLUMN removed_at TEXT")

    # Exploit intelligence per CVE (CISA KEV + FIRST EPSS), shared by all hosts
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cve_intel (
            cve_id TEXT PRIMARY KEY,
            epss REAL,
            epss_percentile REAL,
            epss_date TEXT,
            in_kev INTEGER DEFAULT 0,
            kev_date_added TEXT,
            kev_due_date TEXT,
            kev_required_action TEXT,
            kev_ransomware INTEGER DEFAULT 0,
            updated_at TEXT
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status)')

    # Create token_blacklist table if not exists (migration for existing DBs)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS token_blacklist (
            jti TEXT PRIMARY KEY,
            user TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_blacklist_expires ON token_blacklist(expires_at)')

    migrate_timestamps_to_utc(cursor)

    conn.commit()
    conn.close()
    print("Database initialization complete.")


# Columns that were written in the server's local time before timestamps moved
# to UTC (utils/timeutil.py). Columns that already held UTC are not listed:
# last_liveness_check, last_wappalyzer_scan, settings, certificate validity,
# and columns only ever filled by SQLite's CURRENT_TIMESTAMP default.
LOCAL_TIME_COLUMNS = {
    'domain_asset': ('first_seen', 'last_seen', 'last_scanned', 'last_deep_scan'),
    'subdomain_asset': ('first_seen', 'last_seen', 'last_scanned', 'last_deep_scan'),
    'ip_asset': ('first_seen', 'last_seen', 'last_scanned'),
    'ports': ('first_seen',),
    'http_services': ('first_seen', 'last_seen'),
    'technologies': ('first_seen', 'removed_at'),
    'vulnerabilities': ('first_seen', 'last_seen', 'status_updated_at'),
    'findings': ('first_seen', 'last_seen', 'status_updated_at'),
    'certificates': ('first_seen', 'last_seen', 'replaced_at'),
    'directories': ('first_seen',),
    'cve_cache': ('fetched_at',),
    'cve_intel': ('updated_at',),
    'scan_hints': ('created_at',),
    'scan_history': ('started_at', 'completed_at'),
    'scan_queue': ('queued_at', 'started_at', 'completed_at'),
    'scan_progress': ('started_at', 'updated_at'),
    'phase_status': ('started_at',),
    'asset_changes': ('detected_at',),
    'screenshots': ('captured_at',),
    'admin_user': ('password_changed_at',),
}


def migrate_timestamps_to_utc(cursor, offset_seconds: int = None) -> bool:
    """
    Shift timestamps written in local time to UTC, once. The marker row is
    claimed first, so two processes starting together cannot shift twice.
    A no-op (besides the marker) on servers running in UTC, e.g. Docker.

    Returns:
        True if this call did the migration
    """
    from datetime import datetime

    if offset_seconds is None:
        offset_seconds = int(datetime.now().astimezone().utcoffset().total_seconds())
    cursor.execute("INSERT OR IGNORE INTO settings (key, value, description) VALUES "
                   "('timestamps_in_utc', ?, 'Migration marker: seconds local timestamps were shifted by')",
                   (str(-offset_seconds),))
    if cursor.rowcount != 1:
        return False
    if offset_seconds:
        modifier = f'{-offset_seconds:+d} seconds'
        for table, columns in LOCAL_TIME_COLUMNS.items():
            existing = {row[1] for row in cursor.execute(f'PRAGMA table_info({table})')}
            for column in columns:
                if column in existing:
                    cursor.execute(f"""
                        UPDATE {table} SET {column} = strftime('%Y-%m-%d %H:%M:%S', {column}, ?)
                        WHERE {column} GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]*[0-9][0-9]:[0-9][0-9]:[0-9][0-9]*'
                    """, (modifier,))
    return True


def reset_db():
    if os.path.exists(DB_NAME):
        print(f"[!] Database found at: {DB_NAME}")
        
        while True:
            choice = input("Do you want to rewrite the current database? This will reset the database back to nothing-ness (y/N): ").lower().strip()
            
            if choice == "" or choice == 'n':
                print("[*] Skipping database rewrite...")
                print("[*] Checking for corrupted data...")
                init_db()
                break
            elif choice == 'y':
                try:
                    os.remove(DB_NAME)
                    print("[+] Database successfully rewritten.")
                    print("[*] Initializing new database...")
                    init_db()
                except OSError as e:
                    print(f"[-] An error occurred when deleting database: {e}")
                break
            else:
                print("[-] Input is not valid (y/n)")
    else:
        print("[*] No existing database found. Initializing...")
        init_db()


def show_schema():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    tables = cursor.fetchall()
    
    print("\n=== DATABASE SCHEMA ===\n")
    
    for table in tables:
        table_name = table[0]
        print(f"Table: {table_name}")
        
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = cursor.fetchall()
        
        for col in columns:
            col_id, col_name, col_type, not_null, default_val, pk = col
            pk_marker = " [PK]" if pk else ""
            not_null_marker = " NOT NULL" if not_null else ""
            default_marker = f" DEFAULT {default_val}" if default_val else ""
            print(f"  - {col_name}: {col_type}{pk_marker}{not_null_marker}{default_marker}")
        print()
    
    conn.close()


if __name__ == "__main__":
    reset_db()
    show_schema()