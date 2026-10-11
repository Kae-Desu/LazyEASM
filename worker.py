"""
LazyEASM background worker process.

Runs every queue consumer and Phase 3 monitor (see utils/worker_runtime.py).
Start it next to the web app with `python run.py`, or on its own with
`python worker.py`. Run exactly one worker per database.
"""

import logging
import os
import signal
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    from modules.InitDB import init_db
    from utils.worker_runtime import start_background_workers, stop_background_workers

    init_db()

    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())

    start_background_workers()
    try:
        while not stop.wait(1):
            pass
    finally:
        stop_background_workers()


if __name__ == '__main__':
    main()
