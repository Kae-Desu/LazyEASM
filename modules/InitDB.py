import sqlite3, os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_DIR = os.path.join(PROJECT_ROOT, "db")
if not os.path.exists(DB_DIR):
    os.makedirs(DB_DIR)

DB_NAME = os.path.join(DB_DIR, "lazyeasm.db")

def init_db():
    conn = sqlite3.connect(DB_NAME)
    conn.execute("PRAGMA foreign_keys = ON;")
    cursor = conn.cursor()

    print(f"Connection inisialised to {DB_NAME}")

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS domain_asset (
        dom_id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain_name TEXT UNIQUE,
        first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
        last_medium_scan TEXT,
        last_long_scan TEXT,
        dir_file_path TEXT,
        dir_file_hash TEXT,
        full_tcp_path TEXT,
        full_tcp_hash TEXT,
        full_udp_path TEXT,
        full_udp_hash TEXT
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS ip_asset (
        ip_id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_value TEXT UNIQUE,
        last_medium_scan TEXT,
        last_long_scan TEXT,
        dir_file_path TEXT,
        dir_file_hash TEXT,
        full_tcp_path TEXT,
        full_tcp_hash TEXT,
        full_udp_path TEXT,
        full_udp_hash TEXT
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS subdomain_asset (
        sub_id INTEGER PRIMARY KEY AUTOINCREMENT,
        dom_id INTEGER,
        subdomain_name TEXT,
        first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
        last_medium_scan TEXT,
        last_long_scan TEXT,
        dir_file_path TEXT,
        dir_file_hash TEXT,
        full_tcp_path TEXT,
        full_tcp_hash TEXT,
        full_udp_path TEXT,
        full_udp_hash TEXT,
        FOREIGN KEY(dom_id) REFERENCES domain_asset(dom_id) ON DELETE SET NULL
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS ports (
        port_id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_id INTEGER,
        port_num INTEGER,
        protocol TEXT,
        port_service TEXT,
        FOREIGN KEY(ip_id) REFERENCES ip_asset(ip_id) ON DELETE CASCADE
    )
    ''')

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

    conn.commit()
    conn.close()
    print("Database initialisation complete.")

def start_db_initialisation():
    if os.path.exists(DB_NAME):
        print(f"[!] Database Found at: {DB_NAME}")
        
        while True:
            choice = input("Do you want to rewrite the current database? this will reset the database back to nothing-ness (y/N): ").lower().strip()

            if choice == "":
                choice = 'n'
            else:
                choice = choice
            
            if choice == 'y':
                try:
                    os.remove(DB_NAME)
                    print("[+] Database sucessfully rewritten.")
                    print("[*] Initialising new database...")
                    init_db()
                except OSError as e:
                    print(f"[-] An error occured when deleting database: {e}")
                break
                
            elif choice == 'n':
                print("[*] Skipping Database rewrite...")
                print("[*] Checking for corrupted data...")
                # Tetap jalankan init_db untuk memastikan tabel lengkap (IF NOT EXISTS akan menangani duplikasi)
                init_db()
                break
            else:
                print("[-] Input is not valid (y/n)")
    else:
        # Jika database belum ada, langsung buat baru
        print("[*] No Existing Database found. initialising...")
        init_db()