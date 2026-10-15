"""
Start LazyEASM: the web app and the background worker as separate processes.

    python run.py

- The database is initialized once, before either process starts.
- If either process exits, the other is stopped and run.py exits with an
  error, so a container restart policy (or systemd) restarts the whole app.
- SIGINT / SIGTERM stop both processes.
"""

import os
import signal
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

STOP_TIMEOUT = 20


def _spawn(script: str, extra_env: dict = None) -> subprocess.Popen:
    env = {**os.environ, 'PYTHONUNBUFFERED': '1', **(extra_env or {})}
    return subprocess.Popen([sys.executable, os.path.join(ROOT, script)], cwd=ROOT, env=env)


def _stop(processes):
    for proc in processes:
        if proc.poll() is None:
            proc.terminate()
    deadline = time.monotonic() + STOP_TIMEOUT
    for proc in processes:
        try:
            proc.wait(timeout=max(0.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            proc.kill()


def print_setup_code():
    """First run: the code that creates the account in the browser."""
    from utils.auth import ensure_setup_code
    code = ensure_setup_code()
    if code:
        line = '=' * 60
        print(f"[run] {line}\n"
              f"[run]  First run: open LazyEASM in your browser and create your\n"
              f"[run]  account with this one-time setup code:\n"
              f"[run]\n"
              f"[run]      {code}\n"
              f"[run]\n"
              f"[run] {line}", flush=True)


def print_address(scheme: str):
    """Where to open LazyEASM. In Docker the entrypoint prints the published port instead."""
    if os.path.exists('/.dockerenv'):
        return
    from utils.config import get_env
    from utils.tls import _primary_ip
    port = get_env('PORT', '10001')
    host = get_env('PUBLIC_IP', '') or get_env('HOST', '')
    if host in ('', '0.0.0.0', '::'):
        host = _primary_ip() or 'localhost'
    host = f'[{host}]' if ':' in host else host
    print(f"[run] Open LazyEASM at {scheme}://{host}:{port}", flush=True)


def main() -> int:
    import logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    from modules.InitDB import init_db
    from utils.auth import bootstrap_admin_from_env
    from utils.backup import BackupError, backup_before_upgrade, record_schema_signature
    try:
        snapshot = backup_before_upgrade()      # before migrations change an existing database
        if snapshot:
            print(f"[run] Database changes after an upgrade; backed up first: {snapshot}", flush=True)
    except (BackupError, OSError) as e:
        print(f"[run] Could not back up the database before upgrading it: {e}", flush=True)
        return 1
    init_db()
    record_schema_signature()
    bootstrap_admin_from_env()
    print_setup_code()

    from utils.tls import TLSConfigError, certificate_files, describe
    try:
        tls_files = certificate_files()
    except TLSConfigError as e:
        print(f"[run] HTTPS is enabled but cannot start: {e}", flush=True)
        return 1
    print_address('https' if tls_files else 'http')
    if tls_files:
        print(f"[run] HTTPS certificate SHA-256 fingerprint: {describe(tls_files[0])['fingerprint']}", flush=True)

    processes = {
        'worker': _spawn('worker.py'),
        'web': _spawn('main.py', {'LAZYEASM_ROLE': 'web'}),
    }

    stopping = {'requested': False}

    def request_stop(*_):
        stopping['requested'] = True

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    exit_code = 0
    while not stopping['requested']:
        exited = {name: proc.returncode for name, proc in processes.items() if proc.poll() is not None}
        if exited:
            for name, code in exited.items():
                print(f"[run] {name} process exited with code {code}; stopping LazyEASM", flush=True)
            exit_code = 1
            break
        time.sleep(1)

    _stop(processes.values())
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
