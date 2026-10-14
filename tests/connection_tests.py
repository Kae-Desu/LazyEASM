"""
Database connections are closed even when a query fails.

An unclosed sqlite3 connection is only freed by the cyclic garbage collector,
so every failing query that skipped close() kept file handles open; on a full
disk that exhausted the worker's file descriptors within minutes and it never
recovered after space was freed.
"""

import ast
import pathlib
import sqlite3
import unittest
from unittest.mock import patch

from utils import db_utils, phase0_worker, phase2_worker, phase_lock

ROOT = pathlib.Path(__file__).resolve().parent.parent


def unclosed_connections():
    """`x = get_db_connection()` statements not followed by a try whose finally closes."""
    found = []
    for path in ROOT.rglob('*.py'):
        rel = path.relative_to(ROOT)
        if rel.parts[0] in ('.venv', 'venv', 'tests'):
            continue
        tree = ast.parse(path.read_text(encoding='utf-8'))
        for node in ast.walk(tree):
            body = getattr(node, 'body', None)
            if not isinstance(body, list):
                continue
            for i, st in enumerate(body):
                if not (isinstance(st, ast.Assign) and isinstance(st.value, ast.Call)
                        and getattr(st.value.func, 'id', getattr(st.value.func, 'attr', '')) == 'get_db_connection'):
                    continue
                if isinstance(node, ast.FunctionDef) and node.name == 'get_db_connection':
                    continue
                closed = any(isinstance(s, ast.Try) and any('close' in ast.dump(f) for f in s.finalbody)
                             for s in body[i + 1:i + 4])
                if not closed:
                    found.append(f'{rel}:{st.lineno}')
    return found


class FailingConnection:
    """Stands in for a connection whose every query fails, like on a full disk."""

    instances = []

    def __init__(self):
        self.closed = False
        self.row_factory = None
        FailingConnection.instances.append(self)

    def execute(self, *args, **kwargs):
        raise sqlite3.OperationalError('disk I/O error')

    executemany = execute
    commit = execute

    def cursor(self):
        return self

    def close(self):
        self.closed = True


class ConnectionClosingTests(unittest.TestCase):
    def test_every_connection_is_closed_in_finally(self):
        self.assertEqual(unclosed_connections(), [],
                         'wrap each get_db_connection() in try/finally: conn.close()')

    def test_failing_queries_close_their_connection(self):
        calls = [
            lambda: db_utils.get_setting('phase3_enabled'),
            lambda: db_utils.set_setting('worker_heartbeat', '{}'),
            lambda: db_utils.is_token_blacklisted('jti'),
            phase_lock.get_current_phase,
            phase_lock.get_phase2_progress,
            phase0_worker.get_pending_phase0_item,
            lambda: phase0_worker.reset_stuck_processing_items(timeout_minutes=30),
            phase2_worker.get_next_queued_scan,
        ]
        with patch.object(db_utils, 'get_db_connection', FailingConnection), \
                patch.object(phase2_worker, 'get_db_connection', FailingConnection):
            for call in calls:
                FailingConnection.instances.clear()
                with self.assertRaises(sqlite3.OperationalError):
                    call()
                self.assertTrue(FailingConnection.instances, call)
                self.assertTrue(all(c.closed for c in FailingConnection.instances), call)


if __name__ == '__main__':
    unittest.main()
