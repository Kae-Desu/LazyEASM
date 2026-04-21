"""
Dirsearch Module - Non-recursive directory enumeration.

Requirements:
    - dirsearch installed (one of):
      pip install dirsearch
      git clone https://github.com/maurosorgenti/dirsearch.git /opt/dirsearch

Usage:
    dirsearch -u http://example.com -w dicc.txt -r false --json -o output.json
"""

import os
import sys
import json
import subprocess
import logging
import tempfile
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# Find project root and venv
PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
VENV_BIN = os.path.join(PROJECT_ROOT, '.venv', 'bin')

# Dirsearch paths to check (venv first, then system)
DIRSEARCH_PATHS = [
    os.path.join(VENV_BIN, 'dirsearch'),
    '/usr/local/bin/dirsearch',
    '/usr/bin/dirsearch',
    '/opt/dirsearch/dirsearch.py',
    os.path.expanduser('~/dirsearch/dirsearch.py'),
    os.path.expanduser('~/tools/dirsearch/dirsearch.py'),
]


def find_dirsearch() -> Optional[str]:
    """
    Find dirsearch executable.
    
    Returns:
        Path to dirsearch or None if not found
    """
    # Check common paths
    for path in DIRSEARCH_PATHS:
        if os.path.isfile(path):
            return path
    
    # Check if in PATH
    try:
        result = subprocess.run(['which', 'dirsearch'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except:
        pass
    
    # Check Python module
    try:
        import dirsearch
        return 'python -m dirsearch'
    except ImportError:
        pass
    
    return None


def run_dirsearch(asset_id: int, host: str, port: int,
                   wordlist: str = None,
                   threads: int = 25,
                   recursive: bool = False,
                   timeout: int = None) -> List[Dict]:
    """
    Run dirsearch on target.
    
    Args:
        asset_id: Asset ID (for linking)
        host: Hostname or IP
        port: Port number
        wordlist: Wordlist filename (optional, uses built-in if not specified)
        threads: Number of threads (default: 25)
        recursive: Enable recursive scanning (default: False)
        timeout: Timeout in seconds (default: None = no timeout)
    
    Returns:
        List of discovered directories
    """
    dirsearch_path = find_dirsearch()
    if not dirsearch_path:
        logger.warning("dirsearch not found, skipping directory enumeration")
        return []
    
    scheme = 'https' if port in (443, 8443) else 'http'
    url = f"{scheme}://{host}:{port}"
    
    if dirsearch_path.endswith('.py') or 'python -m' in dirsearch_path:
        cmd = ['python']
        if 'python -m' in dirsearch_path:
            cmd.extend(['-m', 'dirsearch'])
        else:
            cmd.append(dirsearch_path)
    else:
        cmd = [dirsearch_path]
    
    cmd.extend([
        '-u', url,
        '-t', str(threads),
        '--format', 'json'
    ])
    
    if wordlist:
        cmd.extend(['-w', wordlist])
    
    # Create temp file for output (dirsearch writes to file, not stdout)
    output_file = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
            output_file = tmp.name
        cmd.extend(['-o', output_file])
    except Exception as e:
        logger.warning(f"Failed to create temp file: {e}")
        output_file = None
    
    logger.info(f"Running dirsearch on {url}")
    
    try:
        if timeout:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        else:
            result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode > 1:
            logger.error(f"Dirsearch failed for {url}: {result.stderr}")
            return []
        
        # Read from output file (dirsearch writes JSON to file, not stdout)
        output = ""
        if output_file and os.path.exists(output_file):
            try:
                with open(output_file, 'r') as f:
                    output = f.read()
            except Exception as e:
                logger.error(f"Failed to read output file: {e}")
        else:
            # Fallback to stdout if no output file
            output = result.stdout.strip()
        
        if not output:
            logger.info(f"No output from dirsearch for {url}")
            return []
        
        try:
            data = json.loads(output)
            directories = data.get('results', [])
        except json.JSONDecodeError:
            directories = []
            for line in output.split('\n'):
                line = line.strip()
                if line and line.startswith('{'):
                    try:
                        directories.append(json.loads(line))
                    except:
                        continue
        
        if not directories:
            return []
        
        # Filter out 404s - only save interesting results
        interesting = [d for d in directories if d.get('status', 0) not in [404, 0]]
        
        if not interesting:
            logger.info(f"No interesting directories found for {url} (all 404)")
            return []
        
        # Save to database
        saved = save_directories(asset_id, host, port, interesting)
        
        return saved
        
    except subprocess.TimeoutExpired:
        logger.warning(f"Dirsearch timeout for {url}")
        return []
    except json.JSONDecodeError as e:
        logger.error(f"JSON parse error for {url}: {e}")
        return []
    except Exception as e:
        logger.error(f"Dirsearch error for {url}: {e}")
        return []
    finally:
        # Clean up temp file
        if output_file and os.path.exists(output_file):
            try:
                os.unlink(output_file)
            except:
                pass


def save_directories(asset_id: int, host: str, port: int, directories: List[Dict]) -> List[Dict]:
    """
    Save discovered directories to database.
    
    Args:
        asset_id: Asset ID
        host: Hostname
        port: Port number
        directories: List of directory results from dirsearch
    
    Returns:
        List of saved directories
    """
    from utils.db_utils import get_db_connection
    
    if not directories:
        return []
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Find http_id for this host:port
    cursor.execute('''
        SELECT http_id FROM http_services WHERE host = ? AND port_num = ?
    ''', (host, port))
    
    result = cursor.fetchone()
    if not result:
        logger.warning(f"No http_services entry for {host}:{port}, cannot save directories")
        conn.close()
        return []
    
    http_id = result['http_id']
    saved = []
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    for entry in directories:
        if isinstance(entry, dict):
            # Dirsearch JSON format: {"url": "https://host/path", "status": 200, "content-length": 1234, "redirect": ""}
            full_url = entry.get('url', '')
            if full_url:
                # Extract path from full URL
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(full_url)
                    path = parsed.path
                except:
                    path = full_url
            else:
                path = entry.get('path', '')
            
            status = entry.get('status', 0)
            length = entry.get('content-length', entry.get('length', 0))
            redirect = entry.get('redirect', '')
        else:
            continue
        
        if not path or path == '/':
            continue
        
        # Skip 404s (should already be filtered, but double check)
        if status == 404:
            continue
        
        # Ensure path starts with /
        if not path.startswith('/'):
            path = '/' + path
        
        try:
            cursor.execute('''
                INSERT OR IGNORE INTO directories (http_id, path, status_code, content_length, redirect_url, first_seen)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (http_id, path, status, length, redirect, now))
            
            if cursor.rowcount > 0:
                saved.append({
                    'path': path,
                    'status': status,
                    'length': length
                })
        except Exception as e:
            logger.debug(f"Skip duplicate or error: {path} - {e}")
    
    conn.commit()
    conn.close()
    
    logger.info(f"Saved {len(saved)} directories for {host}:{port}")
    return saved


if __name__ == '__main__':
    # CLI test
    import argparse
    
    parser = argparse.ArgumentParser(description='Dirsearch wrapper')
    parser.add_argument('host', help='Target host')
    parser.add_argument('-p', '--port', type=int, default=80, help='Port number')
    parser.add_argument('-w', '--wordlist', default='dicc.txt', help='Wordlist file')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads')
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    
    # Check dirsearch availability
    path = find_dirsearch()
    if path:
        print(f"Found dirsearch at: {path}")
    else:
        print("dirsearch not found!")
        sys.exit(1)
    
    # Run
    results = run_dirsearch(
        asset_id=0,
        host=args.host,
        port=args.port,
        wordlist=args.wordlist,
        threads=args.threads
    )
    
    print(f"\nFound {len(results)} directories:")
    for r in results:
        print(f"  [{r['status']}] {r['path']} ({r['length']} bytes)")