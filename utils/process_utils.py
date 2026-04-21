"""
Process Detection - Find and manage running scan processes.

Uses psutil to detect Phase 0 and Phase 1 processes.
Works in Docker containers with proper permissions.
"""

import psutil
import logging
import time
from typing import List, Dict

logger = logging.getLogger(__name__)


def find_phase0_processes() -> List[Dict]:
    """
    Find running Phase 0 processes.
    
    Phase 0 = Discovery (CTLogs, DNS resolution, etc.)
    
    Returns:
        List of dicts with 'pid', 'name', 'cmdline'
    """
    processes = []
    
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline_list = proc.info.get('cmdline') or []
            cmdline = ' '.join(cmdline_list)
            
            # Skip if this is just importing the module (not actually running Phase 0)
            if '-c' in cmdline_list and ('import' in cmdline or 'from' in cmdline):
                continue
            
            # Phase 0 discovery scripts - check for actual module execution
            if '03-asset-expansion' in cmdline or 'phase0_runner' in cmdline:
                processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'cmdline': cmdline,
                    'type': 'discovery'
                })
            
            # DNS resolution processes (dnspython in action)
            if any(arg.endswith('.py') and 'dns' in arg.lower() for arg in cmdline_list):
                processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'cmdline': cmdline,
                    'type': 'dns'
                })
                
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    
    return processes


def find_phase1_processes() -> List[Dict]:
    """
    Find running Phase 1 processes.
    
    Phase 1 = Active scanning (nmap --top-ports, wappalyzer)
    
    Returns:
        List of dicts with 'pid', 'type'
    """
    processes = []
    
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = ' '.join(proc.info.get('cmdline') or [])
            
            # Nmap from Phase 1 (uses --top-ports)
            if 'nmap' in cmdline.lower() and '--top-ports' in cmdline:
                processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'cmdline': cmdline,
                    'type': 'nmap'
                })
            
            # Wappalyzer from Phase 1
            if 'wappalyzer' in cmdline.lower() or 'Wappalyzer' in cmdline:
                processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'cmdline': cmdline,
                    'type': 'wappalyzer'
                })
            
            # Dirsearch from Phase 1 (shouldn't exist, but check anyway)
            if 'dirsearch' in cmdline.lower() and 'phase2' not in cmdline.lower():
                processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'cmdline': cmdline,
                    'type': 'dirsearch'
                })
                
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    
    return processes


def find_phase2_processes() -> List[Dict]:
    """
    Find running Phase 2 processes.
    
    Phase 2 = Deep scanning (nmap -p-, dirsearch with 3 threads)
    
    Returns:
        List of dicts with 'pid', 'type'
    """
    processes = []
    
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = ' '.join(proc.info.get('cmdline') or [])
            
            # Nmap full scan from Phase 2 (uses -p-)
            if 'nmap' in cmdline.lower() and '-p-' in cmdline:
                processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'cmdline': cmdline,
                    'type': 'nmap'
                })
            
            # Dirsearch from Phase 2
            if 'dirsearch' in cmdline.lower():
                processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'cmdline': cmdline,
                    'type': 'dirsearch'
                })
                
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    
    return processes


def kill_phase1_processes() -> List[Dict]:
    """
    Kill all Phase 1 related processes.
    
    Returns:
        List of killed processes
    """
    killed = []
    processes = find_phase1_processes()
    
    for proc_info in processes:
        try:
            proc = psutil.Process(proc_info['pid'])
            proc.terminate()  # SIGTERM first
            
            # Wait for process to die
            try:
                proc.wait(timeout=5)
            except psutil.TimeoutExpired:
                proc.kill()  # SIGKILL if terminate doesn't work
            
            killed.append(proc_info)
            logger.info(f"Killed Phase 1 process: PID {proc_info['pid']} ({proc_info['type']})")
            
        except psutil.NoSuchProcess:
            # Process already dead
            pass
        except psutil.AccessDenied:
            logger.warning(f"Access denied killing PID {proc_info['pid']}")
        except Exception as e:
            logger.error(f"Error killing PID {proc_info['pid']}: {e}")
    
    return killed


def wait_for_phase0_completion() -> bool:
    """
    Wait for Phase 0 to complete.
    
    Waits forever until Phase 0 processes are done.
    Phase 0 is crucial for discovery, so we must wait.
    
    Returns:
        Always True (never times out)
    """
    logger.info("Waiting for Phase 0 to complete...")
    
    check_interval = 60  # Check every 60 seconds
    
    while True:
        processes = find_phase0_processes()
        
        if not processes:
            logger.info("Phase 0 completed")
            return True
        
        logger.info(f"Phase 0 still running ({len(processes)} processes), waiting...")
        time.sleep(check_interval)


def get_process_info(pid: int) -> Dict:
    """
    Get detailed information about a process.
    
    Args:
        pid: Process ID
    
    Returns:
        Dict with process info or None if not found
    """
    try:
        proc = psutil.Process(pid)
        return {
            'pid': pid,
            'name': proc.name(),
            'cmdline': ' '.join(proc.cmdline()),
            'cpu_percent': proc.cpu_percent(),
            'memory_mb': proc.memory_info().rss / (1024 * 1024),
            'status': proc.status()
        }
    except psutil.NoSuchProcess:
        return None
    except Exception as e:
        logger.error(f"Error getting process info for {pid}: {e}")
        return None


def is_any_phase_running() -> bool:
    """
    Check if any phase is currently running.
    
    Returns:
        True if Phase 0 or Phase 1 is running
    """
    return bool(find_phase0_processes() or find_phase1_processes())