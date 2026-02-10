import sqlite3, os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "db", "lazyeasm.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    return conn

def get_or_create_domain(domain_name):
    """Insert Root Domain atau ambil ID jika sudah ada."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Coba Insert
        cursor.execute("INSERT OR IGNORE INTO domain_asset (domain_name) VALUES (?)", (domain_name,))
        conn.commit()
        
        # Ambil ID (Entah baru dibuat atau sudah ada)
        cursor.execute("SELECT dom_id FROM domain_asset WHERE domain_name = ?", (domain_name,))
        result = cursor.fetchone()
        return result['dom_id'] if result else None
    finally:
        conn.close()

def get_or_create_subdomain(dom_id, subdomain_part):
    """Insert Subdomain yang terlink ke Parent Domain."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Gabungkan full name untuk kolom subdomain_name (opsional, tergantung preferensi)
        # Di sini kita simpan part-nya saja atau full, asumsi simpan part: "api"
        # Tapi biar enak search, biasanya disimpan full: "api.target.com"
        
        cursor.execute('''
            INSERT OR IGNORE INTO subdomain_asset (dom_id, subdomain_name) 
            VALUES (?, ?)
        ''', (dom_id, subdomain_part))
        conn.commit()
        
        cursor.execute("SELECT sub_id FROM subdomain_asset WHERE subdomain_name = ?", (subdomain_part,))
        result = cursor.fetchone()
        return result['sub_id'] if result else None
    finally:
        conn.close()

def get_or_create_ip(ip_address):
    """Insert IP Address."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT OR IGNORE INTO ip_asset (ip_value) VALUES (?)", (ip_address,))
        conn.commit()
        
        cursor.execute("SELECT ip_id FROM ip_asset WHERE ip_value = ?", (ip_address,))
        result = cursor.fetchone()
        return result['ip_id'] if result else None
    finally:
        conn.close()

def create_pair_domain_ip(dom_id, ip_id):
    conn = get_db_connection()
    conn.execute("INSERT OR IGNORE INTO domain_ip (dom_id, ip_id) VALUES (?, ?)", (dom_id, ip_id))
    conn.commit()
    conn.close()

def create_pair_subdomain_ip(sub_id, ip_id):
    conn = get_db_connection()
    conn.execute("INSERT OR IGNORE INTO subdomain_ip (sub_id, ip_id) VALUES (?, ?)", (sub_id, ip_id))
    conn.commit()
    conn.close()