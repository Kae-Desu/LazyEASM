"""
System watchdog: alerts when the background worker stops or the disk fills up.

Runs as a thread in the web process, so it keeps watching while the worker is
down. Alert state is kept in memory, not in the database: on a full disk the
database cannot be written. Each problem is alerted once it has lasted long
enough, reminded every REMIND_AFTER while it lasts, and followed by a
"recovered" message.

Thresholds are dashboard settings (Settings > Schedule & thresholds, see
utils/scan_settings.SYSTEM_ALERTS); 0 turns an alert off.
"""

import logging
import os
import shutil
import threading
import time
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

CHECK_SECONDS = 60
REMIND_AFTER = 24 * 3600
# Below this much free space the disk counts as almost full whatever the
# percentage (a large disk at 90% still has plenty)
MIN_FREE_BYTES = 1024 ** 3
# Below this the web app reports itself unhealthy in /health
CRITICAL_FREE_BYTES = 100 * 1024 ** 2

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'db')

_thread = None
_stop = threading.Event()


def _format_bytes(n: float) -> str:
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024 or unit == 'TB':
            return f"{n:.0f} {unit}" if unit in ('B', 'KB') else f"{n:.1f} {unit}"
        n /= 1024


def _format_duration(seconds: float) -> str:
    minutes = int(seconds // 60)
    if minutes < 60:
        return f"{max(minutes, 1)} min"
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return f"{hours} h {minutes} min" if minutes else f"{hours} h"
    return f"{hours // 24} days"


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def disk_status(path: str = DATA_DIR, threshold_percent: Optional[int] = None) -> Dict:
    """
    Space on the filesystem holding the database.

    Returns:
        {'path', 'total', 'free', 'used_percent', 'low': bool, 'critical': bool}
        low is False when the alert is off (threshold 0)
    """
    if threshold_percent is None:
        threshold_percent = _setting('disk')
    usage = shutil.disk_usage(path if os.path.isdir(path) else os.path.dirname(path))
    used_percent = round(100 * (usage.total - usage.free) / usage.total, 1) if usage.total else 0.0
    low = bool(threshold_percent) and (used_percent >= threshold_percent or usage.free < MIN_FREE_BYTES)
    return {'path': path, 'total': usage.total, 'free': usage.free, 'used_percent': used_percent,
            'low': low, 'critical': usage.free < CRITICAL_FREE_BYTES}


def describe_disk(disk: Dict) -> str:
    return f"{disk['used_percent']:.0f}% used, {_format_bytes(disk['free'])} free"


def worker_problem() -> Optional[Dict]:
    """
    What is wrong with the worker, or None if it is running.

    Returns:
        {'text': str, 'age_seconds': float | None}
    """
    from utils.worker_runtime import get_worker_status

    status = get_worker_status()
    if not status['alive']:
        age = status['age_seconds']
        text = 'no heartbeat yet' if age is None else f"last heartbeat {_format_duration(age)} ago"
        return {'text': text, 'age_seconds': age}
    stopped = sorted(name for name, alive in status['components'].items() if not alive)
    if stopped:
        return {'text': f"{', '.join(stopped)} not running", 'age_seconds': None}
    return None


def _setting(name: str) -> int:
    from utils.scan_settings import SYSTEM_ALERTS, system_alert_value
    try:
        return system_alert_value(name)
    except Exception:
        # Database unreadable: fall back to the default rather than going quiet
        return next(row[3] for row in SYSTEM_ALERTS if row[0] == name)


def current_warnings() -> List[str]:
    """Problems to show in the dashboard banner (same checks, no delay)."""
    warnings = []
    try:
        problem = worker_problem()
        if problem:
            warnings.append(f"The background worker is not running ({problem['text']}): no scans or monitoring "
                            f"are happening. Check the service logs.")
    except Exception as e:
        warnings.append(f"The worker status could not be read: {str(e)[:80]}")
    try:
        disk = disk_status()
        if disk['low']:
            warnings.append(f"The disk is almost full ({describe_disk(disk)}). When it is full, LazyEASM stops "
                            f"recording scans.")
    except OSError:
        pass
    return warnings


# ---------------------------------------------------------------------------
# Alert state
# ---------------------------------------------------------------------------

class Alert:
    """
    One watched condition. update() is called every check with whether the
    problem is present and returns what to send: 'alert', 'remind',
    'recovered' or None.
    """

    def __init__(self, clock: Callable[[], float] = time.time):
        self.clock = clock
        self.since = None          # first time the problem was seen
        self.alerted_at = None     # last alert or reminder sent

    def update(self, present: bool, delay_seconds: float, started_ago: float = 0) -> Optional[str]:
        now = self.clock()
        if not present:
            was_alerted = self.alerted_at is not None
            self.since = self.alerted_at = None
            return 'recovered' if was_alerted else None
        if self.since is None:
            self.since = now - max(started_ago, 0)
        if self.alerted_at is None:
            return 'alert' if now - self.since >= delay_seconds else None
        return 'remind' if now - self.alerted_at >= REMIND_AFTER else None

    def sent(self):
        self.alerted_at = self.clock()

    def duration(self) -> float:
        return self.clock() - self.since if self.since is not None else 0


class Watchdog:
    def __init__(self, send: Callable[[str], tuple] = None, clock: Callable[[], float] = time.time):
        self.send = send or _send
        self.worker = Alert(clock)
        self.disk = Alert(clock)
        self._last_worker_text = ''

    def check(self):
        self._check_worker()
        self._check_disk()

    def _check_worker(self):
        minutes = _setting('worker')
        try:
            problem = worker_problem()
        except Exception as e:
            problem = {'text': f"status unreadable ({str(e)[:80]})", 'age_seconds': None}
        if not minutes:
            problem = None
        if problem:
            self._last_worker_text = problem['text']
        down_for = self.worker.duration()
        action = self.worker.update(bool(problem), minutes * 60, (problem or {}).get('age_seconds') or 0)
        if action in ('alert', 'remind'):
            self._deliver(self.worker,
                          f"**LazyEASM worker stopped** ({self._last_worker_text}): no scans or monitoring are "
                          f"running. Check the service logs (`./start.sh --logs`, `docker compose logs` or "
                          f"`journalctl -u lazyeasm`) and free disk space; restart LazyEASM once fixed.")
        elif action == 'recovered':
            self._deliver(None, f"**LazyEASM worker running again** (was down for {_format_duration(down_for)}).")

    def _check_disk(self):
        try:
            disk = disk_status()
        except OSError as e:
            logger.warning(f"Disk space check failed: {e}")
            return
        action = self.disk.update(disk['low'], 0)
        if action in ('alert', 'remind'):
            self._deliver(self.disk,
                          f"**Disk almost full on the LazyEASM server**: {describe_disk(disk)}. When it is full, "
                          f"LazyEASM stops recording scans. Free space (old logs, unused Docker images), or change "
                          f"the alert in Settings > Schedule & thresholds.")
        elif action == 'recovered':
            self._deliver(None, f"**Disk space back to normal** on the LazyEASM server: {describe_disk(disk)}.")

    def _deliver(self, alert: Optional[Alert], message: str):
        try:
            success, detail = self.send(message)
        except Exception as e:
            success, detail = False, str(e)
        logger.warning(f"System alert: {message} [{detail}]")
        # A failed send is retried at the next check; with no channel
        # configured there is nothing to retry (the dashboard banner shows it)
        if alert is not None and (success or detail == 'No notification channel configured'):
            alert.sent()


def _send(message: str) -> tuple:
    from modules.Notify import send_message
    return send_message(message)


# ---------------------------------------------------------------------------
# Thread
# ---------------------------------------------------------------------------

def _loop(watchdog: Watchdog):
    # Give the worker time to write its first heartbeat after a start
    if _stop.wait(CHECK_SECONDS):
        return
    while True:
        try:
            watchdog.check()
        except Exception as e:
            logger.error(f"System watchdog check failed: {e}")
        if _stop.wait(CHECK_SECONDS):
            return


def start_watchdog():
    """Start the watchdog thread (web process)."""
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(target=_loop, args=(Watchdog(),), daemon=True, name='System-Watchdog')
    _thread.start()
    logger.info("System watchdog started")


def stop_watchdog():
    _stop.set()
