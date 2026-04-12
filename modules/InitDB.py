"""
Module: InitDB.py
Purpose: Initialize LazyEASM database with asset-centric schema

Tables:
    - domain_asset: Root domains (nutelyn.com)
    - subdomain_asset: Subdomains (blog.nutelyn.com)
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
    conn = sqlite3.connect(DB_NAME)
    conn.execute("PRAGMA foreign_keys = ON;")
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
        FOREIGN KEY(tech_id) REFERENCES technologies(tech_id) ON DELETE SET NULL
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

    conn.commit()
    conn.close()
    print("Database initialization complete.")


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