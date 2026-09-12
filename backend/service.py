"""Bounded shared cache and durable quota counters for a single VPS."""
import json
import os
import sqlite3
import time
from pathlib import Path
from threading import RLock

LOCK = RLock()
DB = os.getenv('STATE_DB', '/tmp/vulnsoc-state.sqlite3')

def connect():
    Path(DB).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB, timeout=15)
    db.execute('CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, expires REAL, value TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS quota (key TEXT PRIMARY KEY, count INTEGER, expires REAL)')
    return db

def cached(key, ttl, fn):
    # Serialize misses to avoid duplicate expensive upstream calls.
    with LOCK, connect() as db:
        now = time.time()
        row = db.execute('SELECT value FROM cache WHERE key=? AND expires>?', (key, now)).fetchone()
        if row:
            return json.loads(row[0])
        value = fn()
        if 'error' not in value and not any(isinstance(v, dict) and 'error' in v for v in value.values()):
            db.execute('DELETE FROM cache WHERE expires<?', (now,))
            db.execute('INSERT OR REPLACE INTO cache VALUES (?,?,?)', (key, now + ttl, json.dumps(value)))
            db.execute('DELETE FROM cache WHERE key IN (SELECT key FROM cache ORDER BY expires DESC LIMIT -1 OFFSET 1000)')
        return value

def allowance(key, limit, seconds):
    now = time.time()
    with LOCK, connect() as db:
        db.execute('BEGIN IMMEDIATE')
        db.execute('DELETE FROM quota WHERE expires<?', (now,))
        row = db.execute('SELECT count FROM quota WHERE key=?', (key,)).fetchone()
        if row and row[0] >= limit:
            return False
        db.execute('INSERT INTO quota VALUES (?,1,?) ON CONFLICT(key) DO UPDATE SET count=count+1', (key, now+seconds))
        return True
