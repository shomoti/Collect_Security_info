from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class StoredRecord:
    normalized_url: str
    jira_intel_key: str
    jira_validation_key: str
    content_hash: str
    fetched_at: str
    source: str
    title_norm: str
    content_fp: str
    last_seen_at: str
    canonical_key: str
    update_count: int


@dataclass
class SourceFeedbackStats:
    source: str
    useful_count: int
    noise_count: int
    total_count: int


class StateStore:
    def __init__(self, db_path: str) -> None:
        self.conn = sqlite3.connect(db_path)
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS processed_articles (
                normalized_url TEXT PRIMARY KEY,
                jira_intel_key TEXT,
                jira_validation_key TEXT,
                content_hash TEXT,
                fetched_at TEXT,
                source TEXT DEFAULT '',
                title_norm TEXT DEFAULT '',
                content_fp TEXT DEFAULT '',
                last_seen_at TEXT DEFAULT '',
                canonical_key TEXT DEFAULT '',
                update_count INTEGER DEFAULT 0
            )
            """
        )
        self._ensure_column("source", "TEXT DEFAULT ''")
        self._ensure_column("title_norm", "TEXT DEFAULT ''")
        self._ensure_column("content_fp", "TEXT DEFAULT ''")
        self._ensure_column("last_seen_at", "TEXT DEFAULT ''")
        self._ensure_column("canonical_key", "TEXT DEFAULT ''")
        self._ensure_column("update_count", "INTEGER DEFAULT 0")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_processed_content_hash ON processed_articles(content_hash)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_processed_source_title ON processed_articles(source, title_norm)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_processed_canonical_key ON processed_articles(canonical_key)")
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS analyst_feedback (
                issue_key TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                verdict TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_feedback_source ON analyst_feedback(source)")
        self.conn.commit()

    def _ensure_column(self, column_name: str, definition: str) -> None:
        rows = self.conn.execute("PRAGMA table_info(processed_articles)").fetchall()
        existing = {str(r[1]) for r in rows}
        if column_name in existing:
            return
        self.conn.execute(f"ALTER TABLE processed_articles ADD COLUMN {column_name} {definition}")

    def get(self, normalized_url: str) -> StoredRecord | None:
        row = self.conn.execute(
            "SELECT normalized_url, jira_intel_key, jira_validation_key, content_hash, fetched_at, source, title_norm, content_fp, "
            "last_seen_at, canonical_key, update_count "
            "FROM processed_articles WHERE normalized_url = ?",
            (normalized_url,),
        ).fetchone()
        if not row:
            return None
        return StoredRecord(*row)

    def find_by_content_hash(self, content_hash: str) -> StoredRecord | None:
        row = self.conn.execute(
            "SELECT normalized_url, jira_intel_key, jira_validation_key, content_hash, fetched_at, source, title_norm, content_fp, "
            "last_seen_at, canonical_key, update_count "
            "FROM processed_articles WHERE content_hash = ? AND jira_validation_key != '' "
            "ORDER BY fetched_at DESC LIMIT 1",
            (content_hash,),
        ).fetchone()
        if not row:
            return None
        return StoredRecord(*row)

    def iter_by_source(self, source: str) -> list[StoredRecord]:
        rows = self.conn.execute(
            "SELECT normalized_url, jira_intel_key, jira_validation_key, content_hash, fetched_at, source, title_norm, content_fp, "
            "last_seen_at, canonical_key, update_count "
            "FROM processed_articles WHERE source = ?",
            (source,),
        ).fetchall()
        return [StoredRecord(*r) for r in rows]

    def save(
        self,
        normalized_url: str,
        jira_intel_key: str,
        jira_validation_key: str,
        content_hash: str,
        source: str = "",
        title_norm: str = "",
        content_fp: str = "",
        canonical_key: str = "",
        update_count: int = 0,
    ) -> None:
        fetched_at = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            """
            INSERT INTO processed_articles (
              normalized_url, jira_intel_key, jira_validation_key, content_hash, fetched_at, source, title_norm, content_fp,
              last_seen_at, canonical_key, update_count
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(normalized_url) DO UPDATE SET
              jira_intel_key = excluded.jira_intel_key,
              jira_validation_key = excluded.jira_validation_key,
              content_hash = excluded.content_hash,
              fetched_at = excluded.fetched_at,
              last_seen_at = excluded.last_seen_at,
              source = excluded.source,
              title_norm = excluded.title_norm,
              content_fp = excluded.content_fp,
              canonical_key = excluded.canonical_key,
              update_count = excluded.update_count
            """,
            (
                normalized_url,
                jira_intel_key,
                jira_validation_key,
                content_hash,
                fetched_at,
                source,
                title_norm,
                content_fp,
                fetched_at,
                canonical_key,
                update_count,
            ),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def upsert_feedback(self, issue_key: str, source: str, verdict: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            """
            INSERT INTO analyst_feedback (issue_key, source, verdict, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(issue_key) DO UPDATE SET
              source = excluded.source,
              verdict = excluded.verdict,
              updated_at = excluded.updated_at
            """,
            (issue_key, source, verdict, now),
        )
        self.conn.commit()

    def get_feedback_stats_by_source(self) -> list[SourceFeedbackStats]:
        rows = self.conn.execute(
            """
            SELECT
              source,
              SUM(CASE WHEN verdict = 'useful' THEN 1 ELSE 0 END) AS useful_count,
              SUM(CASE WHEN verdict = 'noise' THEN 1 ELSE 0 END) AS noise_count,
              COUNT(*) AS total_count
            FROM analyst_feedback
            GROUP BY source
            """
        ).fetchall()
        return [
            SourceFeedbackStats(
                source=str(r[0]),
                useful_count=int(r[1] or 0),
                noise_count=int(r[2] or 0),
                total_count=int(r[3] or 0),
            )
            for r in rows
        ]
