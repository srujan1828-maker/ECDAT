"""Persistent scan jobs. Run one API process; worker threads are bounded."""
import hashlib
import json
import os
import sqlite3
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone


def now():
    return datetime.now(timezone.utc).isoformat()


class ScanStore:
    def __init__(self, path=None):
        self.path = path or os.getenv('ECDAT_DB', 'data/scans.sqlite3')
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        self.pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix='scan')
        self.lock = threading.Lock()
        with self.connect() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY, project TEXT NOT NULL, kind TEXT NOT NULL,
                status TEXT NOT NULL, created_at TEXT NOT NULL, finished_at TEXT,
                input_hash TEXT NOT NULL, payload TEXT, result TEXT, error TEXT)''')
            db.execute("UPDATE scans SET status='failed', error='Worker interrupted; submit again', finished_at=? WHERE status IN ('queued','running')", (now(),))

    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    def submit(self, project, kind, payload, worker):
        encoded = json.dumps(payload, sort_keys=True)
        scan_id = str(uuid.uuid4())
        with self.lock, self.connect() as db:
            count = db.execute("SELECT count(*) FROM scans WHERE status IN ('queued','running')").fetchone()[0]
            if count >= 20:
                raise ValueError('Scan queue is full; retry later')
            db.execute('INSERT INTO scans VALUES (?,?,?,?,?,?,?,?,?,?)',
                       (scan_id, project, kind, 'queued', now(), None,
                        hashlib.sha256(encoded.encode()).hexdigest(), None, None, None))
        self.pool.submit(self._run, scan_id, payload, worker)
        return self.get(scan_id, project)

    def _run(self, scan_id, payload, worker):
        with self.connect() as db:
            changed = db.execute("UPDATE scans SET status='running' WHERE id=? AND status='queued'", (scan_id,)).rowcount
        if not changed:
            return
        try:
            result = worker(payload)
            status = 'failed' if result.get('status') == 'error' else 'completed'
            error = result.get('error')
        except Exception as exc:
            result, status, error = None, 'failed', str(exc)
        with self.connect() as db:
            db.execute("UPDATE scans SET status=?, result=?, error=?, finished_at=? WHERE id=? AND status='running'",
                       (status, json.dumps(result) if result is not None else None, error, now(), scan_id))

    def get(self, scan_id, project):
        with self.connect() as db:
            row = db.execute('SELECT * FROM scans WHERE id=? AND project=?', (scan_id, project)).fetchone()
        if not row:
            return None
        value = dict(row)
        value.pop('payload', None)
        value['result'] = json.loads(value['result']) if value['result'] else None
        value['engine_version'] = '3.0.0'
        return value

    def list(self, project):
        with self.connect() as db:
            ids = db.execute('SELECT id FROM scans WHERE project=? ORDER BY created_at DESC LIMIT 200', (project,)).fetchall()
        return [self.get(row['id'], project) for row in ids]

    def cancel(self, scan_id, project):
        with self.connect() as db:
            db.execute("UPDATE scans SET status='cancelled', finished_at=? WHERE id=? AND project=? AND status IN ('queued','running')", (now(), scan_id, project))
        return self.get(scan_id, project)

    def close(self):
        self.pool.shutdown(wait=True)
