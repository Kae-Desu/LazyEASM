"""
Queue Manager for Phase 1 processing.

Architecture:
    - In-memory queue (queue.Queue)
    - ThreadPoolExecutor(max_workers=4)
    - Each worker processes one asset completely:
      nmap → wappalyzer → dirsearch → cve → discord

No persistence - queue state lost on restart.
"""

import queue
import threading
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class TaskQueue:
    """In-memory task queue with 4 workers."""
    
    def __init__(self, max_workers: int = 4):
        self.queue = queue.Queue()
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.workers = []
        self._lock = threading.Lock()
        
        self.stats = {
            'pending': 0,
            'running': 0,
            'completed': 0,
            'failed': 0,
            'total': 0,
            'active': False
        }
    
    def _cleanup_workers(self):
        """Remove completed futures from workers list."""
        before = len(self.workers)
        self.workers = [f for f in self.workers if not f.done()]
        after = len(self.workers)
        if before != after:
            logger.debug(f"Cleaned up {before - after} completed workers")
    
    def enqueue(self, target_id: int, target_type: str, target_name: str):
        """
        Add asset to queue. Updates DB scan_queue table.
        
        Args:
            target_id: Database ID (dom_id, sub_id, or ip_id)
            target_type: 'domain', 'subdomain', or 'ip'
            target_name: Hostname or IP address
        """
        task = {
            'target_id': target_id,
            'target_type': target_type,
            'target_name': target_name,
            'queued_at': datetime.now()
        }
        
        # Insert to DB
        queue_id = self._insert_to_db(task)
        task['queue_id'] = queue_id
        
        # Add to in-memory queue
        self.queue.put(task)
        
        with self._lock:
            self.stats['pending'] += 1
            self.stats['total'] += 1
            self.stats['active'] = True
        
        # Clean up finished workers before checking
        self._cleanup_workers()
        
        # Start worker if available
        if len(self.workers) < self.executor._max_workers:
            future = self.executor.submit(self._worker)
            self.workers.append(future)
            logger.debug(f"Started new worker, total: {len(self.workers)}")
        
        logger.info(f"Enqueued: {target_name} (queue_id={queue_id})")
    
    def get_status(self) -> Dict:
        """Return current queue status."""
        with self._lock:
            return self.stats.copy()
    
    def is_active(self) -> bool:
        """Check if queue has pending/running tasks."""
        with self._lock:
            return self.stats['active']
    
    def _worker(self):
        """Process tasks from queue."""
        worker_id = id(threading.current_thread())
        logger.debug(f"Worker {worker_id} started")
        
        try:
            while True:
                try:
                    task = self.queue.get(timeout=60)
                    if task is None:
                        break
                    
                    self._process_task(task)
                    self.queue.task_done()
                    
                except queue.Empty:
                    with self._lock:
                        self.stats['active'] = False
                    logger.debug(f"Worker {worker_id} exiting (idle)")
                    break
                except Exception as e:
                    logger.error(f"Worker {worker_id} error: {e}")
        finally:
            self._cleanup_workers()
    
    def _process_task(self, task: Dict):
        """Run Phase 1 pipeline for one asset."""
        queue_id = task['queue_id']
        target_name = task['target_name']
        
        logger.info(f"Processing: {target_name}")
        
        # Update status: running
        self._update_db_status(queue_id, 'running')
        with self._lock:
            self.stats['pending'] -= 1
            self.stats['running'] += 1
        
        try:
            # Run Phase 1
            from modules.phase1_runner import run_phase1
            stats = run_phase1(
                asset_id=task['target_id'],
                asset_type=task['target_type'],
                asset_name=target_name
            )
            
            # Update status: completed
            self._update_db_status(queue_id, 'completed', **stats)
            with self._lock:
                self.stats['running'] -= 1
                self.stats['completed'] += 1
            
            logger.info(f"Completed: {target_name}")
            
        except Exception as e:
            # Update status: failed
            self._update_db_status(queue_id, 'failed', error_message=str(e))
            with self._lock:
                self.stats['running'] -= 1
                self.stats['failed'] += 1
            
            logger.error(f"Failed: {target_name} - {e}")
    
    def _insert_to_db(self, task: Dict) -> int:
        """Insert task to scan_queue table, return queue_id."""
        from utils.db_utils import get_db_connection
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO scan_queue (scan_type, cycle, target, target_id, target_type, status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', ('phase1', 'standard', task['target_name'], task['target_id'], 
              task['target_type'], 'pending'))
        
        queue_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return queue_id or 0
    
    def _update_db_status(self, queue_id: int, status: str, **kwargs):
        """Update scan_queue status."""
        from utils.db_utils import get_db_connection
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        if status == 'running':
            cursor.execute('''
                UPDATE scan_queue SET status=?, started_at=? WHERE queue_id=?
            ''', (status, now, queue_id))
        elif status == 'completed':
            cursor.execute('''
                UPDATE scan_queue SET status=?, completed_at=?, ports_found=?, tech_found=?, cve_found=?
                WHERE queue_id=?
            ''', (status, now, kwargs.get('ports_found', 0), kwargs.get('tech_found', 0), 
                  kwargs.get('cve_found', 0), queue_id))
        elif status == 'failed':
            cursor.execute('''
                UPDATE scan_queue SET status=?, completed_at=?, error_message=? WHERE queue_id=?
            ''', (status, now, kwargs.get('error_message', ''), queue_id))
        
        conn.commit()
        conn.close()


# Global singleton
task_queue = TaskQueue(max_workers=4)