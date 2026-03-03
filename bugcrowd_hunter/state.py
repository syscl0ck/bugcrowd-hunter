"""
State manager for Bugcrowd Hunter.

Persists:
  - Program list + in-scope targets (SQLite)
  - Scan queue and status per domain
  - Discovered subdomains (fed back from subfinder into the scan pipeline)
  - Deduplicated findings with severity tracking
  - Per-program configuration (priority, exclusions)
  - HackerOne programs alongside Bugcrowd
"""

import json
import sqlite3
import threading
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


SCHEMA = """
CREATE TABLE IF NOT EXISTS programs (
    code            TEXT NOT NULL,
    platform        TEXT NOT NULL DEFAULT 'bugcrowd',
    name            TEXT NOT NULL,
    url             TEXT NOT NULL,
    last_synced     TEXT,
    priority        INTEGER NOT NULL DEFAULT 5,
    excluded        INTEGER NOT NULL DEFAULT 0,
    notes           TEXT,
    PRIMARY KEY (code, platform)
);

CREATE TABLE IF NOT EXISTS targets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    program         TEXT NOT NULL,
    platform        TEXT NOT NULL DEFAULT 'bugcrowd',
    name            TEXT NOT NULL,
    base_domain     TEXT NOT NULL,
    is_wildcard     INTEGER NOT NULL DEFAULT 0,
    category        TEXT,
    source          TEXT NOT NULL DEFAULT 'scope',
    discovered_from INTEGER,
    last_seen       TEXT,
    UNIQUE(program, platform, name),
    FOREIGN KEY(discovered_from) REFERENCES targets(id)
);

CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL,
    tool        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',
    started_at  TEXT,
    finished_at TEXT,
    result_file TEXT,
    error       TEXT,
    FOREIGN KEY(target_id) REFERENCES targets(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    program     TEXT NOT NULL,
    platform    TEXT NOT NULL DEFAULT 'bugcrowd',
    target      TEXT NOT NULL,
    tool        TEXT NOT NULL,
    name        TEXT NOT NULL,
    severity    TEXT,
    fingerprint TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    count       INTEGER NOT NULL DEFAULT 1,
    notified    INTEGER NOT NULL DEFAULT 0,
    raw         TEXT,
    UNIQUE(fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_scans_target    ON scans(target_id);
CREATE INDEX IF NOT EXISTS idx_scans_status    ON scans(status);
CREATE INDEX IF NOT EXISTS idx_targets_program ON targets(program, platform);
CREATE INDEX IF NOT EXISTS idx_findings_prog   ON findings(program, platform);
CREATE INDEX IF NOT EXISTS idx_findings_sev    ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_notif  ON findings(notified);
"""

# Severity sort expression reused in multiple queries
_SEV_SORT = """
  CASE severity
    WHEN 'critical' THEN 1
    WHEN 'high'     THEN 2
    WHEN 'medium'   THEN 3
    WHEN 'low'      THEN 4
    ELSE 5
  END
"""


class StateManager:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        # WAL mode gives much better concurrent read/write performance
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(SCHEMA)
        self._conn.commit()
        self._migrate()

    def _migrate(self):
        """
        Safe migration: add new columns to existing DBs.
        Uses per-table column inspection so it's idempotent.
        """
        migrations = [
            ("programs", "priority",  "ALTER TABLE programs ADD COLUMN priority INTEGER NOT NULL DEFAULT 5"),
            ("programs", "excluded",  "ALTER TABLE programs ADD COLUMN excluded INTEGER NOT NULL DEFAULT 0"),
            ("programs", "notes",     "ALTER TABLE programs ADD COLUMN notes TEXT"),
            ("programs", "platform",  "ALTER TABLE programs ADD COLUMN platform TEXT NOT NULL DEFAULT 'bugcrowd'"),
            ("targets",  "source",    "ALTER TABLE targets ADD COLUMN source TEXT NOT NULL DEFAULT 'scope'"),
            ("targets",  "discovered_from", "ALTER TABLE targets ADD COLUMN discovered_from INTEGER"),
            ("targets",  "last_seen", "ALTER TABLE targets ADD COLUMN last_seen TEXT"),
            ("targets",  "platform",  "ALTER TABLE targets ADD COLUMN platform TEXT NOT NULL DEFAULT 'bugcrowd'"),
            ("targets", "in_scope", "ALTER TABLE targets ADD COLUMN in_scope INTEGER NOT NULL DEFAULT 1"),
        ]
        for table, col, sql in migrations:
            existing = {r[1] for r in self._conn.execute(f"PRAGMA table_info({table})")}
            if col not in existing:
                try:
                    self._conn.execute(sql)
                    logger.debug(f"Migration: added {table}.{col}")
                except Exception as e:
                    logger.debug(f"Migration skipped {table}.{col}: {e}")
        self._conn.commit()

    # -------------------------------------------------------------------------
    # Programs
    # -------------------------------------------------------------------------

    def upsert_program(self, code: str, name: str, url: str, platform: str = "bugcrowd"):
        with self._lock:
            self._conn.execute(
                """INSERT INTO programs(code, platform, name, url, last_synced)
                   VALUES(?, ?, ?, ?, ?)
                   ON CONFLICT(code, platform) DO UPDATE SET
                     name=excluded.name,
                     url=excluded.url,
                     last_synced=excluded.last_synced""",
                (code, platform, name, url, datetime.utcnow().isoformat()),
            )
            self._conn.commit()

    def get_programs(self, platform: str = None, excluded: bool = None) -> list[sqlite3.Row]:
        with self._lock:
            query = "SELECT * FROM programs WHERE 1=1"
            params: list = []
            if platform:
                query += " AND platform=?"
                params.append(platform)
            if excluded is not None:
                query += " AND excluded=?"
                params.append(int(excluded))
            query += " ORDER BY priority ASC, code ASC"
            return self._conn.execute(query, params).fetchall()

    def get_program(self, code: str, platform: str = "bugcrowd") -> Optional[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM programs WHERE code=? AND platform=?", (code, platform)
            ).fetchone()

    def get_out_of_scope_target_names(self, program: str, platform: str = "bugcrowd") -> set[str]:
        """Return target names explicitly listed as out-of-scope (from sync)"""
        with self._lock:
            rows = self._conn.execute(
                """SELECT name FROM targets 
                WHERE program=? AND platform=? AND source='scope' AND in_scope=0""",
                (program, platform),
            ).fetchall()
            return set(row["name"].lower() for row in rows)

    def set_program_priority(self, code: str, priority: int, platform: str = "bugcrowd"):
        with self._lock:
            self._conn.execute(
                "UPDATE programs SET priority=? WHERE code=? AND platform=?",
                (max(1, min(10, priority)), code, platform),
            )
            self._conn.commit()

    def set_program_excluded(self, code: str, excluded: bool, platform: str = "bugcrowd"):
        with self._lock:
            self._conn.execute(
                "UPDATE programs SET excluded=? WHERE code=? AND platform=?",
                (int(excluded), code, platform),
            )
            self._conn.commit()

    def set_program_notes(self, code: str, notes: str, platform: str = "bugcrowd"):
        with self._lock:
            self._conn.execute(
                "UPDATE programs SET notes=? WHERE code=? AND platform=?",
                (notes, code, platform),
            )
            self._conn.commit()

    # -------------------------------------------------------------------------
    # Targets
    # -------------------------------------------------------------------------

    def upsert_target(self, program: str, name: str, base_domain: str,
                      is_wildcard: bool, category: str, platform: str = "bugcrowd",
                      source: str = "scope", discovered_from: int = None, in_scope: bool = True) -> Optional[int]:
        with self._lock:
            now = datetime.utcnow().isoformat()
            try:
                cur = self._conn.execute(
                    """INSERT INTO targets(program, platform, name, base_domain, is_wildcard,
                                           category, source, discovered_from, last_seen, in_scope)
                       VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(program, platform, name) DO UPDATE SET
                         base_domain=excluded.base_domain,
                         is_wildcard=excluded.is_wildcard,
                         category=excluded.category,
                         last_seen=excluded.last_seen,
                         in_scope=excluded.in_scope
                       RETURNING id""",
                    (program, platform, name, base_domain, int(is_wildcard),
                     category, source, discovered_from, now, int(in_scope)),
                )
                row = cur.fetchone()
                self._conn.commit()
                if row:
                    return row["id"]
            except sqlite3.Error as e:
                logger.error(f"upsert_target error: {e}")
            # Fallback lookup if RETURNING didn't fire (older SQLite versions)
            return self._get_target_id(program, platform, name)

    def _get_target_id(self, program: str, platform: str, name: str) -> Optional[int]:
        row = self._conn.execute(
            "SELECT id FROM targets WHERE program=? AND platform=? AND name=?",
            (program, platform, name),
        ).fetchone()
        return row["id"] if row else None

    def get_targets(self, program: str = None, platform: str = None,
                    wildcard_only: bool = False, source: str = None,
                    excluded_programs: bool = False, in_scope: bool = True) -> list[sqlite3.Row]:
        with self._lock:
            query = """
                SELECT t.* FROM targets t
                JOIN programs p ON t.program = p.code AND t.platform = p.platform
                WHERE 1=1
            """
            params: list = []
            if not excluded_programs:
                query += " AND p.excluded=0"
            if program:
                query += " AND t.program=?"
                params.append(program)
            if platform:
                query += " AND t.platform=?"
                params.append(platform)
            if wildcard_only:
                query += " AND t.is_wildcard=1"
            if source:
                query += " AND t.source=?"
                params.append(source)
            if in_scope is not None:
                query += " AND t.in_scope=?"
                params.append(int(in_scope))
            query += " ORDER BY p.priority ASC, t.id ASC"
            return self._conn.execute(query, params).fetchall()

    def count_targets(self, program: str = None, platform: str = None) -> int:
        with self._lock:
            query = "SELECT COUNT(*) FROM targets WHERE 1=1"
            params: list = []
            if program:
                query += " AND program=?"
                params.append(program)
            if platform:
                query += " AND platform=?"
                params.append(platform)
            return self._conn.execute(query, params).fetchone()[0]

    def target_exists(self, program: str, platform: str, name: str) -> bool:
        with self._lock:
            return self._get_target_id(program, platform, name) is not None

    def get_targets_with_scan_done(self, tool: str, program: str = None,
                                    platform: str = None) -> list:
        """
        Return target rows that have a completed (done) scan for the given tool.
        Use e.g. to queue nuclei for targets that already have httpx results.
        """
        with self._lock:
            query = """
                SELECT t.* FROM targets t
                JOIN programs p ON t.program = p.code AND t.platform = p.platform
                JOIN scans s ON s.target_id = t.id AND s.tool = ? AND s.status = 'done'
                WHERE 1=1
            """
            params: list = [tool]
            query += " AND p.excluded=0"
            if program:
                query += " AND t.program=?"
                params.append(program)
            if platform:
                query += " AND t.platform=?"
                params.append(platform)
            query += " ORDER BY p.priority ASC, t.id ASC"
            return self._conn.execute(query, params).fetchall()

    # -------------------------------------------------------------------------
    # Scans
    # -------------------------------------------------------------------------

    def queue_scan(self, target_id: int, tool: str, force: bool = False) -> tuple[int, bool]:
        """
        Add a scan to the queue.
        If force=False (default), skips if a pending/running/done scan already exists.
        Returns (scan_id, was_inserted).
        """
        with self._lock:
            if not force:
                existing = self._conn.execute(
                    """SELECT id FROM scans
                       WHERE target_id=? AND tool=? AND status IN ('pending','running','done')""",
                    (target_id, tool),
                ).fetchone()
                if existing:
                    return (existing["id"], False)

            cur = self._conn.execute(
                "INSERT INTO scans(target_id, tool, status) VALUES(?, ?, 'pending') RETURNING id",
                (target_id, tool),
            )
            row = cur.fetchone()
            self._conn.commit()
            return (row["id"], True)

    def claim_scan(self, scan_id: int) -> bool:
        """Atomically mark a scan as running. Returns False if already claimed."""
        with self._lock:
            now = datetime.utcnow().isoformat()
            cur = self._conn.execute(
                "UPDATE scans SET status='running', started_at=? WHERE id=? AND status='pending'",
                (now, scan_id),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def complete_scan(self, scan_id: int, result_file: str = None, error: str = None):
        with self._lock:
            status = "failed" if error else "done"
            now = datetime.utcnow().isoformat()
            self._conn.execute(
                "UPDATE scans SET status=?, finished_at=?, result_file=?, error=? WHERE id=?",
                (status, now, result_file, error, scan_id),
            )
            self._conn.commit()

    def count_scans_to_clear(self, tool: str = None, program: str = None,
                             platform: str = None, all: bool = False) -> int:
        """Return how many scans would be removed by clear_pending_scans with the same args."""
        with self._lock:
            subquery = """
                SELECT s.id FROM scans s
                JOIN targets t ON s.target_id = t.id
            """
            params: list = []
            if not all:
                subquery += " WHERE s.status = 'pending'"
            else:
                subquery += " WHERE 1=1"
            if tool:
                subquery += " AND s.tool=?"
                params.append(tool)
            if program:
                subquery += " AND t.program=?"
                params.append(program)
            if platform:
                subquery += " AND t.platform=?"
                params.append(platform)
            row = self._conn.execute(
                f"SELECT COUNT(*) AS n FROM scans WHERE id IN ({subquery})", params
            ).fetchone()
            return row["n"] if row else 0

    def clear_pending_scans(self, tool: str = None, program: str = None,
                            platform: str = None, all: bool = False) -> int:
        """
        Delete scans from the queue.
        By default, only pending scans are removed.
        With all=True, removes pending, running, done, and failed.
        Optionally filter by tool, program, or platform.
        Returns number of scans removed.
        """
        with self._lock:
            subquery = """
                SELECT s.id FROM scans s
                JOIN targets t ON s.target_id = t.id
            """
            params: list = []
            if not all:
                subquery += " WHERE s.status = 'pending'"
            else:
                subquery += " WHERE 1=1"
            if tool:
                subquery += " AND s.tool=?"
                params.append(tool)
            if program:
                subquery += " AND t.program=?"
                params.append(program)
            if platform:
                subquery += " AND t.platform=?"
                params.append(platform)
            cur = self._conn.execute(f"DELETE FROM scans WHERE id IN ({subquery})", params)
            self._conn.commit()
            return cur.rowcount

    def get_pending_scans(self, tool: str = None, limit: int = 50) -> list[sqlite3.Row]:
        with self._lock:
            query = """
                SELECT s.*, t.name as target_name, t.base_domain, t.is_wildcard,
                       t.program, t.platform, p.priority
                FROM scans s
                JOIN targets t ON s.target_id = t.id
                JOIN programs p ON t.program = p.code AND t.platform = p.platform
                WHERE s.status='pending' AND p.excluded=0
            """
            params: list = []
            if tool:
                query += " AND s.tool=?"
                params.append(tool)
            query += " ORDER BY p.priority ASC, s.id ASC LIMIT ?"
            params.append(limit)
            return self._conn.execute(query, params).fetchall()

    def get_scan_stats(self) -> dict:
        with self._lock:
            rows = self._conn.execute(
                "SELECT tool, status, COUNT(*) as cnt FROM scans GROUP BY tool, status"
            ).fetchall()
            stats: dict = {}
            for r in rows:
                stats.setdefault(r["tool"], {})[r["status"]] = r["cnt"]
            return stats

    def reset_stale_scans(self, older_than_minutes: int = 60):
        """Reset scans stuck in 'running' (e.g. after a crash)."""
        with self._lock:
            cutoff = datetime.utcnow().timestamp() - (older_than_minutes * 60)
            cutoff_str = datetime.utcfromtimestamp(cutoff).isoformat()
            cur = self._conn.execute(
                """UPDATE scans SET status='pending', started_at=NULL
                   WHERE status='running' AND started_at < ?""",
                (cutoff_str,),
            )
            self._conn.commit()
            if cur.rowcount:
                logger.info(f"Reset {cur.rowcount} stale scans to pending")

    # -------------------------------------------------------------------------
    # Findings
    # -------------------------------------------------------------------------

    def upsert_finding(self, program: str, platform: str, target: str,
                       tool: str, name: str, severity: str,
                       fingerprint: str, raw: dict) -> tuple[int, bool]:
        """
        Insert a new finding or increment count on an existing one.
        Returns (finding_id, is_new).
        """
        with self._lock:
            now = datetime.utcnow().isoformat()
            existing = self._conn.execute(
                "SELECT id FROM findings WHERE fingerprint=?", (fingerprint,)
            ).fetchone()

            if existing:
                self._conn.execute(
                    "UPDATE findings SET last_seen=?, count=count+1 WHERE fingerprint=?",
                    (now, fingerprint),
                )
                self._conn.commit()
                return existing["id"], False

            cur = self._conn.execute(
                """INSERT INTO findings(program, platform, target, tool, name, severity,
                                        fingerprint, first_seen, last_seen, raw)
                   VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   RETURNING id""",
                (program, platform, target, tool, name, severity,
                 fingerprint, now, now, json.dumps(raw)),
            )
            row = cur.fetchone()
            self._conn.commit()
            return row["id"], True

    def get_findings(self, program: str = None, platform: str = None,
                     severity: str = None, notified: bool = None,
                     limit: int = 500) -> list[sqlite3.Row]:
        with self._lock:
            query = "SELECT * FROM findings WHERE 1=1"
            params: list = []
            if program:
                query += " AND program=?"
                params.append(program)
            if platform:
                query += " AND platform=?"
                params.append(platform)
            if severity:
                query += " AND severity=?"
                params.append(severity)
            if notified is not None:
                query += " AND notified=?"
                params.append(int(notified))
            query += f" ORDER BY {_SEV_SORT}, first_seen DESC LIMIT ?"
            params.append(limit)
            return self._conn.execute(query, params).fetchall()

    def get_unnotified_findings(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                f"SELECT * FROM findings WHERE notified=0 ORDER BY {_SEV_SORT}"
            ).fetchall()

    def mark_findings_notified(self, finding_ids: list[int]):
        if not finding_ids:
            return
        with self._lock:
            placeholders = ",".join("?" * len(finding_ids))
            self._conn.execute(
                f"UPDATE findings SET notified=1 WHERE id IN ({placeholders})",
                finding_ids,
            )
            self._conn.commit()

    def get_finding_summary(self) -> dict:
        with self._lock:
            rows = self._conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity"
            ).fetchall()
            return {r["severity"]: r["cnt"] for r in rows}

    # -------------------------------------------------------------------------
    # Housekeeping
    # -------------------------------------------------------------------------

    def close(self):
        with self._lock:
            self._conn.close()
