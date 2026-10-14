"""
Queue Manager for Phase 1 processing.

Architecture:
    - The scan_queue table is the queue (scan_type='phase1'), so any process
      can enqueue and the dashboard can read status from the database
    - Phase1Worker runs only in the worker process: it claims pending rows
      atomically and processes up to 4 assets at a time
      (nmap -> wappalyzer -> cve -> intel -> misconfig)
    - On worker start, rows left 'running' by a crash go back to 'pending'
"""

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Dict, Optional
from utils.timeutil import utc_now_str

logger = logging.getLogger(__name__)

PHASE1 = 'phase1'
MAX_WORKERS = 4


def _now() -> str:
    return utc_now_str()


def _db():
    from utils.db_utils import get_db_connection
    return get_db_connection()


class TaskQueue:
    """Database-backed Phase 1 queue. Safe to use from the web and worker processes."""

    def enqueue(self, target_id: Optional[int], target_type: str, target_name: str) -> int:
        """
        Add an asset to the queue unless it is already pending or running.

        Returns:
            queue_id of the new or existing row
        """
        conn = _db()
        try:
            existing = conn.execute('''
                SELECT queue_id FROM scan_queue
                WHERE scan_type = ? AND target = ? AND status IN ('pending', 'running')
            ''', (PHASE1, target_name)).fetchone()
            if existing:
                return existing['queue_id']

            # A new batch starts when the queue was idle
            idle = conn.execute('''
                SELECT COUNT(*) AS n FROM scan_queue
                WHERE scan_type = ? AND status IN ('pending', 'running')
            ''', (PHASE1,)).fetchone()['n'] == 0
            now = _now()
            if idle:
                conn.execute('''
                    INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
                ''', ('phase1_batch_started_at', now, now))

            cursor = conn.execute('''
                INSERT INTO scan_queue (scan_type, cycle, target, target_id, target_type, status, queued_at)
                VALUES (?, 'standard', ?, ?, ?, 'pending', ?)
            ''', (PHASE1, target_name, target_id, target_type, now))
            conn.commit()
            logger.info(f"Enqueued: {target_name} (queue_id={cursor.lastrowid})")
            return cursor.lastrowid
        finally:
            conn.close()

    def get_status(self) -> Dict:
        """Counts for the current batch; all zero when the queue is idle."""
        conn = _db()
        try:
            counts = {row['status']: row['n'] for row in conn.execute('''
                SELECT status, COUNT(*) AS n FROM scan_queue
                WHERE scan_type = ? AND status IN ('pending', 'running')
                GROUP BY status
            ''', (PHASE1,))}
            pending, running = counts.get('pending', 0), counts.get('running', 0)
            active = pending + running > 0

            completed = failed = 0
            if active:
                started = conn.execute("SELECT value FROM settings WHERE key = 'phase1_batch_started_at'").fetchone()
                done = {row['status']: row['n'] for row in conn.execute('''
                    SELECT status, COUNT(*) AS n FROM scan_queue
                    WHERE scan_type = ? AND status IN ('completed', 'failed') AND queued_at >= ?
                    GROUP BY status
                ''', (PHASE1, started['value'] if started else ''))}
                completed, failed = done.get('completed', 0), done.get('failed', 0)
        finally:
            conn.close()

        return {
            'pending': pending,
            'running': running,
            'completed': completed,
            'failed': failed,
            'total': pending + running + completed + failed,
            'active': active,
        }

    def is_active(self) -> bool:
        return self.get_status()['active']


class Phase1Worker:
    """Processes the Phase 1 queue. Run exactly one per deployment (the worker process)."""

    def __init__(self, max_workers: int = MAX_WORKERS, poll_seconds: float = 3.0):
        self.max_workers = max_workers
        self.poll_seconds = poll_seconds
        self._running = False
        self._thread = None
        self._executor = None
        self._in_flight = 0
        self._batch = {'completed': 0, 'failed': 0}
        self._lock = threading.Lock()

    def start(self):
        if self._running:
            return
        self.recover_interrupted()
        self._running = True
        self._executor = ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix='Phase1')
        self._thread = threading.Thread(target=self._loop, daemon=True, name='Phase1-Dispatcher')
        self._thread.start()
        logger.info(f"[Phase1] Worker started ({self.max_workers} slots)")

    def stop(self):
        self._running = False
        if self._executor:
            self._executor.shutdown(wait=False, cancel_futures=True)

    def is_alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    @staticmethod
    def recover_interrupted() -> int:
        """Put rows left 'running' by a previous worker back to 'pending'."""
        conn = _db()
        try:
            cursor = conn.execute('''
                UPDATE scan_queue SET status = 'pending', started_at = NULL
                WHERE scan_type = ? AND status = 'running'
            ''', (PHASE1,))
            conn.commit()
            if cursor.rowcount:
                logger.warning(f"[Phase1] Re-queued {cursor.rowcount} interrupted tasks")
            return cursor.rowcount
        finally:
            conn.close()

    @staticmethod
    def claim_next() -> Optional[dict]:
        """Atomically move the oldest pending row to 'running' and return it."""
        conn = _db()
        try:
            while True:
                row = conn.execute('''
                    SELECT queue_id, target, target_id, target_type FROM scan_queue
                    WHERE scan_type = ? AND status = 'pending'
                    ORDER BY queued_at, queue_id LIMIT 1
                ''', (PHASE1,)).fetchone()
                if not row:
                    return None
                cursor = conn.execute('''
                    UPDATE scan_queue SET status = 'running', started_at = ?
                    WHERE queue_id = ? AND status = 'pending'
                ''', (_now(), row['queue_id']))
                conn.commit()
                if cursor.rowcount == 1:
                    return dict(row)
                # another process claimed it first; try the next one
        finally:
            conn.close()

    def _loop(self):
        while self._running:
            try:
                dispatched = False
                with self._lock:
                    free = self._in_flight < self.max_workers
                if free:
                    task = self.claim_next()
                    if task:
                        with self._lock:
                            self._in_flight += 1
                        self._executor.submit(self._run_task, task)
                        dispatched = True
                if not dispatched:
                    self._check_batch_complete()
                    time.sleep(self.poll_seconds)
            except Exception as e:
                logger.error(f"[Phase1] Dispatcher error: {e}")
                time.sleep(self.poll_seconds)

    def _run_task(self, task: dict):
        name = task['target']
        logger.info(f"[Phase1] Processing: {name}")
        try:
            from modules.phase1_runner import run_phase1
            stats = run_phase1(asset_id=task['target_id'], asset_type=task['target_type'], asset_name=name)
            self._finish(task['queue_id'], 'completed', stats)
            logger.info(f"[Phase1] Completed: {name}")
        except Exception as e:
            self._finish(task['queue_id'], 'failed', {'error_message': str(e)})
            logger.error(f"[Phase1] Failed: {name} - {e}")
        finally:
            with self._lock:
                self._in_flight -= 1

    def _finish(self, queue_id: int, status: str, stats: dict):
        conn = _db()
        try:
            if status == 'completed':
                conn.execute('''
                    UPDATE scan_queue SET status = ?, completed_at = ?, ports_found = ?, tech_found = ?, cve_found = ?
                    WHERE queue_id = ?
                ''', (status, _now(), stats.get('ports_found', 0), stats.get('tech_found', 0),
                      stats.get('cve_found', 0), queue_id))
            else:
                conn.execute('''
                    UPDATE scan_queue SET status = ?, completed_at = ?, error_message = ? WHERE queue_id = ?
                ''', (status, _now(), stats.get('error_message', ''), queue_id))
            conn.commit()
        finally:
            conn.close()
        with self._lock:
            self._batch[status] += 1

    def _check_batch_complete(self):
        """Send the completion notification once the queue drains after work was done."""
        with self._lock:
            if self._in_flight or not (self._batch['completed'] or self._batch['failed']):
                return
        if task_queue.get_status()['active']:
            return
        with self._lock:
            completed, failed = self._batch['completed'], self._batch['failed']
            self._batch = {'completed': 0, 'failed': 0}
        self._send_completion_notification(completed, failed)

    @staticmethod
    def _send_completion_notification(completed: int, failed: int):
        try:
            from modules.Notify import send_message

            total = completed + failed
            lines = ["**Initialization Complete**", "━━━━━━━━━━━━━━━━━━"]
            if failed == 0:
                lines.append(f"**Processed:** {completed}/{total}")
            else:
                lines.append(f"**Completed:** {completed}/{total}")
                lines.append(f"**Failed:** {failed}/{total}")
            lines.append("All assets have been scanned.")
            send_message('\n'.join(lines))
            logger.info(f"Phase 1 completion notification sent: {completed} completed, {failed} failed")
        except Exception as e:
            logger.error(f"Failed to send completion notification: {e}")


# Global singletons
task_queue = TaskQueue()
phase1_worker = Phase1Worker()
