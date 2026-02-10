"""
module 02: nmap scanner
this module performs nmap scans on targets.
"""
import sys
import os
import subprocess
import sqlite3
import xml.etree.ElementTree as ET
from datetime import datetime

# Add parent directory to path to allow importing utils
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'db', 'skripshit.db')

def get_targets():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    # Fetch IPs that need scanning (currently fetching all)
    cursor.execute("SELECT ip_id, ip_value FROM ip_asset")
    targets = cursor.fetchall()
    conn.close()
    return targets

def save_port(ip_id, port_num, protocol, service_name):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO ports (ip_id, port_num, protocol, port_service)
        VALUES (?, ?, ?, ?)
    ''', (ip_id, port_num, protocol, service_name))
    conn.commit()
    conn.close()

def update_scan_timestamp(ip_id, scan_type='medium'):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if scan_type == 'medium':
        cursor.execute("UPDATE ip_asset SET last_medium_scan = ? WHERE ip_id = ?", (timestamp, ip_id))
    conn.commit()
    conn.close()

def run_nmap():
    targets = get_targets()
    print(f"[*] Found {len(targets)} targets to scan.")

    for target in targets:
        ip_id = target['ip_id']
        ip_address = target['ip_value']
        
        print(f"[*] Scanning {ip_address} (Fast Mode)...")
        
        # Command: nmap -sV -T3 --top-ports 250 -oX - <ip>
        # Note: Requires nmap installed on system
        cmd = ["nmap", "-sV", "-T3", "--top-ports", "250", "-oX", "-", ip_address]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            # Parse XML Output
            root = ET.fromstring(result.stdout)
            
            for host in root.findall('host'):
                ports = host.find('ports')
                if ports:
                    for port in ports.findall('port'):
                        port_id = int(port.get('portid'))
                        protocol = port.get('protocol')
                        service = port.find('service')
                        service_name = service.get('name') if service is not None else 'unknown'
                        
                        save_port(ip_id, port_id, protocol, service_name)
            
            update_scan_timestamp(ip_id)
            print(f"[+] Finished scanning {ip_address}")
            
        except subprocess.CalledProcessError as e:
            print(f"[-] Error scanning {ip_address}: {e}")
        except ET.ParseError:
            print(f"[-] Error parsing XML for {ip_address}")

if __name__ == "__main__":
    run_nmap()
