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


def main() -> int:
    import logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    from modules.InitDB import init_db
    from utils.auth import bootstrap_admin_from_env
    init_db()
    bootstrap_admin_from_env()

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
