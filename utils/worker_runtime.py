"""
Background worker runtime.

Everything that runs on a schedule or from a queue lives here, separate from
the web app:
    - Phase 0 discovery queue (subdomains from CT logs)
    - input discovery jobs (assets submitted in the dashboard)
    - Phase 1 queue (per-asset scans)
    - Phase 2 deep-scan queue
    - Phase 3 monitors

Run it with `python worker.py` (production, separate process) or let
`python main.py` start it in-process for local development. Exactly one
worker runtime may run per database.

The runtime writes a heartbeat to the settings table so the web process can
report worker health without sharing memory with it.
"""

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from utils.timeutil import utc_now_str

logger = logging.getLogger(__name__)

HEARTBEAT_KEY = 'worker_heartbeat'
HEARTBEAT_SECONDS = 15
STALE_AFTER_SECONDS = 60
JOB_POLL_SECONDS = 3

_running = False
_threads = {}


# ---------------------------------------------------------------------------
# Input discovery jobs (queued by the web app, run here)
# ---------------------------------------------------------------------------

def _claim_input_job():
    from utils.pipeline import INPUT_DISCOVERY
    return _claim_job((INPUT_DISCOVERY,))


def _claim_job(job_types):
    from utils.db_utils import get_db_connection

    conn = get_db_connection()
    try:
        while True:
            row = conn.execute(f'''
                SELECT queue_id, scan_type, target FROM scan_queue
                WHERE scan_type IN ({','.join('?' * len(job_types))}) AND status = 'pending'
                ORDER BY queue_id LIMIT 1
            ''', tuple(job_types)).fetchone()
            if not row:
                return None
            cursor = conn.execute('''
                UPDATE scan_queue SET status = 'processing', started_at = ?
                WHERE queue_id = ? AND status = 'pending'
            ''', (_now(), row['queue_id']))
            conn.commit()
            if cursor.rowcount == 1:
                return dict(row)
    finally:
        conn.close()


def _finish_input_job(queue_id: int, status: str, error: str = None):
    from utils.db_utils import get_db_connection

    conn = get_db_connection()
    try:
        conn.execute('UPDATE scan_queue SET status = ?, completed_at = ?, error_message = ? WHERE queue_id = ?',
                     (status, _now(), error, queue_id))
        conn.commit()
    finally:
        conn.close()


def _run_job(job: dict):
    from utils.pipeline import INPUT_DISCOVERY, MONITOR_RUN, run_input_discovery
    from utils.phase3_worker import run_monitor

    if job['scan_type'] == INPUT_DISCOVERY:
        run_input_discovery(json.loads(job['target']))
    elif job['scan_type'] == MONITOR_RUN:
        run_monitor(job['target'])
    else:
        raise ValueError(f"unknown job type {job['scan_type']}")


def _input_discovery_loop():
    """Runs queued jobs: submitted-asset discovery and manual Phase 3 checks."""
    from utils.pipeline import JOB_TYPES

    while _running:
        job = None
        try:
            job = _claim_job(JOB_TYPES)
            if not job:
                time.sleep(JOB_POLL_SECONDS)
                continue
            _run_job(job)
            _finish_input_job(job['queue_id'], 'completed')
        except Exception as e:
            logger.error(f"[Discovery] Job failed: {e}")
            if job:
                _finish_input_job(job['queue_id'], 'failed', str(e)[:500])
            time.sleep(JOB_POLL_SECONDS)


# ---------------------------------------------------------------------------
# Crash recovery
# ---------------------------------------------------------------------------

def recover_interrupted_jobs() -> int:
    """
    Re-queue work a previous worker left half-done. Safe because only one
    worker runtime runs per database.
    """
    from utils.db_utils import get_db_connection
    from utils.pipeline import INPUT_DISCOVERY, MONITOR_RUN

    conn = get_db_connection()
    try:
        cursor = conn.execute('''
            UPDATE scan_queue SET status = 'pending', started_at = NULL
            WHERE status = 'processing' AND scan_type IN (?, ?, 'phase0_discovery', 'phase2_deep_scan')
        ''', (INPUT_DISCOVERY, MONITOR_RUN))
        conn.commit()
        recovered = cursor.rowcount
    finally:
        conn.close()

    from utils.queue_manager import Phase1Worker
    recovered += Phase1Worker.recover_interrupted()
    if recovered:
        logger.warning(f"Re-queued {recovered} jobs interrupted by a previous shutdown")
    return recovered


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------

def _now() -> str:
    return utc_now_str()


def _component_status() -> dict:
    from utils.phase0_worker import get_phase0_status
    from utils.phase3_worker import phase3_threads_alive
    from utils.queue_manager import phase1_worker

    return {
        'phase0': bool(get_phase0_status().get('thread_alive')),
        'discovery': bool(_threads.get('discovery') and _threads['discovery'].is_alive()),
        'phase1': phase1_worker.is_alive(),
        'phase2': bool(_threads.get('phase2') and _threads['phase2'].is_alive()),
        'phase3': phase3_threads_alive(),
    }


def write_heartbeat():
    from utils.db_utils import set_setting

    set_setting(HEARTBEAT_KEY, json.dumps({
        'ts': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'pid': os.getpid(),
        'components': _component_status(),
    }))


def _heartbeat_loop():
    while _running:
        try:
            write_heartbeat()
        except Exception as e:
            logger.error(f"Heartbeat failed: {e}")
        time.sleep(HEARTBEAT_SECONDS)


def get_worker_status() -> dict:
    """
    Worker health as seen from any process.

    Returns:
        {'alive': bool, 'age_seconds': float | None, 'pid': int | None,
         'components': {name: bool}}
    """
    from utils.db_utils import get_setting

    status = {'alive': False, 'age_seconds': None, 'pid': None, 'components': {}}
    raw = get_setting(HEARTBEAT_KEY)
    if not raw:
        return status
    try:
        data = json.loads(raw)
        ts = datetime.strptime(data['ts'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except (ValueError, KeyError, TypeError):
        return status

    age = (datetime.now(timezone.utc) - ts).total_seconds()
    status.update(alive=age <= STALE_AFTER_SECONDS, age_seconds=round(age, 1),
                  pid=data.get('pid'), components=data.get('components', {}))
    return status


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

def start_background_workers():
    """Start every background component in this process."""
    global _running

    if _running:
        logger.warning("Background workers already running")
        return
    _running = True

    recover_interrupted_jobs()

    from utils.phase0_worker import start_phase0_worker
    from utils.phase2_worker import phase2_worker_loop
    from utils.phase3_worker import start_phase3_workers
    from utils.queue_manager import phase1_worker
    import utils.phase2_worker

    start_phase0_worker()

    _threads['discovery'] = threading.Thread(target=_input_discovery_loop, daemon=True, name='Input-Discovery')
    _threads['discovery'].start()

    phase1_worker.start()

    _threads['phase2'] = threading.Thread(target=phase2_worker_loop, args=(5,), daemon=True, name='Phase2-Worker')
    _threads['phase2'].start()
    utils.phase2_worker._phase2_thread = _threads['phase2']

    start_phase3_workers()

    _threads['heartbeat'] = threading.Thread(target=_heartbeat_loop, daemon=True, name='Worker-Heartbeat')
    _threads['heartbeat'].start()

    logger.info(f"Background workers started (pid {os.getpid()})")


def stop_background_workers():
    """Signal components to stop. Daemon threads that are mid-scan end with the process."""
    global _running

    _running = False
    from utils.phase0_worker import stop_phase0_worker
    from utils.phase3_worker import stop_phase3_workers
    from utils.queue_manager import phase1_worker

    phase1_worker.stop()
    stop_phase0_worker()
    stop_phase3_workers()
    logger.info("Background workers stopped")
