"""Append-only evidence store: SQLite locally, Postgres in production.

The repository only issues INSERT and SELECT. Triggers reject UPDATE, DELETE, and
TRUNCATE as a second line of defense.
HACKATHON: production should also give the scanner a DB role with INSERT/SELECT
only, and the dashboard SELECT only, so the triggers are not the sole guard.
"""

import json
import secrets
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import psycopg

from pdp_guardian.checks import CheckResult, Status
from pdp_guardian.evidence.chain import (
    ChainCheck,
    EvidenceRecord,
    build_records,
    canonical_json,
    format_time,
    verify_chain,
)
from pdp_guardian.evidence.diff import DiffEntry, diff_scans

_COLUMNS = (
    "seq, scan_id, check_id, article, resource, locator, status, method,"
    " counts, masked_samples, details, scanned_at, prev_hash, hash"
)
_DIFF_COLUMNS = (
    "scan_id, prev_scan_id, check_id, article, resource, locator, status_before, status_after"
)

_TABLES = (
    """CREATE TABLE IF NOT EXISTS evidence (
        seq BIGINT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        check_id TEXT NOT NULL,
        article TEXT NOT NULL,
        resource TEXT NOT NULL,
        locator TEXT NOT NULL,
        status TEXT NOT NULL,
        method TEXT NOT NULL,
        counts TEXT NOT NULL,
        masked_samples TEXT NOT NULL,
        details TEXT NOT NULL,
        scanned_at TEXT NOT NULL,
        prev_hash TEXT NOT NULL,
        hash TEXT NOT NULL UNIQUE
    )""",
    "CREATE INDEX IF NOT EXISTS evidence_scan_id ON evidence (scan_id)",
    """CREATE TABLE IF NOT EXISTS evidence_diff (
        scan_id TEXT NOT NULL,
        prev_scan_id TEXT NOT NULL,
        check_id TEXT NOT NULL,
        article TEXT NOT NULL,
        resource TEXT NOT NULL,
        locator TEXT NOT NULL,
        status_before TEXT,
        status_after TEXT,
        regression BOOLEAN NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS evidence_diff_scan_id ON evidence_diff (scan_id)",
)

_SQLITE_GUARDS = tuple(
    f"""CREATE TRIGGER IF NOT EXISTS {table}_no_{action} BEFORE {action.upper()} ON {table}
        BEGIN SELECT RAISE(ABORT, '{table} is append-only'); END"""
    for table in ("evidence", "evidence_diff")
    for action in ("update", "delete")
)

_POSTGRES_GUARDS = (
    """CREATE OR REPLACE FUNCTION pdp_guardian_append_only() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION '% is append-only', TG_TABLE_NAME; END $$""",
    *(
        f"""CREATE OR REPLACE TRIGGER {table}_append_only
            BEFORE UPDATE OR DELETE ON {table}
            FOR EACH ROW EXECUTE FUNCTION pdp_guardian_append_only()"""
        for table in ("evidence", "evidence_diff")
    ),
    *(
        f"""CREATE OR REPLACE TRIGGER {table}_no_truncate
            BEFORE TRUNCATE ON {table}
            FOR EACH STATEMENT EXECUTE FUNCTION pdp_guardian_append_only()"""
        for table in ("evidence", "evidence_diff")
    ),
)


@dataclass(frozen=True, slots=True)
class AppendedScan:
    scan_id: str
    records: list[EvidenceRecord]
    diff: list[DiffEntry]  # empty for the first scan

    @property
    def regressions(self) -> list[DiffEntry]:
        return [entry for entry in self.diff if entry.regression]


class EvidenceRepository:
    """Evidence store at ``url``: ``sqlite:///path.db`` or ``postgresql://...``."""

    def __init__(self, url: str) -> None:
        if url.startswith("sqlite:///"):
            self._sqlite = True
            # isolation_level=None: transactions are opened explicitly below.
            self._conn: Any = sqlite3.connect(url.removeprefix("sqlite:///"), isolation_level=None)
        elif url.startswith(("postgresql://", "postgres://")):
            self._sqlite = False
            self._conn = psycopg.connect(url, autocommit=True)
        else:
            raise ValueError("evidence URL must start with sqlite:/// or postgresql://")
        for statement in _TABLES + (_SQLITE_GUARDS if self._sqlite else _POSTGRES_GUARDS):
            self._execute(statement)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "EvidenceRepository":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def append_scan(
        self, results: Sequence[CheckResult], scanned_at: datetime | None = None
    ) -> AppendedScan:
        """Chain one scan's results onto the store and record its diff against the last scan."""
        scanned_at = scanned_at or datetime.now(UTC)
        scan_id = f"{scanned_at.astimezone(UTC):%Y%m%dT%H%M%SZ}-{secrets.token_hex(3)}"
        with self._write_transaction():
            head = self._head()
            previous = self.records(head.scan_id) if head else []
            records = build_records(results, scan_id, scanned_at, head)
            for record in records:
                self._insert_record(record)
            diff = diff_scans(previous, records)
            for entry in diff:
                self._insert_diff(entry)
        return AppendedScan(scan_id, records, diff)

    def scan_ids(self) -> list[str]:
        """All scans, oldest first."""
        rows = self._execute(
            "SELECT scan_id FROM evidence GROUP BY scan_id ORDER BY MIN(seq)"
        ).fetchall()
        return [row[0] for row in rows]

    def latest_scan_id(self) -> str | None:
        head = self._head()
        return head.scan_id if head else None

    def records(self, scan_id: str | None = None) -> list[EvidenceRecord]:
        """One scan's records, or the whole chain when ``scan_id`` is None, in ``seq`` order."""
        if scan_id is None:
            rows = self._execute(f"SELECT {_COLUMNS} FROM evidence ORDER BY seq").fetchall()
        else:
            rows = self._execute(
                f"SELECT {_COLUMNS} FROM evidence WHERE scan_id = %s ORDER BY seq", (scan_id,)
            ).fetchall()
        return [_record(row) for row in rows]

    def diff(self, scan_id: str) -> list[DiffEntry]:
        rows = self._execute(
            f"SELECT {_DIFF_COLUMNS} FROM evidence_diff WHERE scan_id = %s"
            " ORDER BY check_id, resource, locator",
            (scan_id,),
        ).fetchall()
        return [_diff_entry(row) for row in rows]

    def verify(self) -> ChainCheck:
        # HACKATHON: reads the whole chain into memory; fine for demo-sized stores.
        return verify_chain(self.records())

    def _head(self) -> EvidenceRecord | None:
        row = self._execute(f"SELECT {_COLUMNS} FROM evidence ORDER BY seq DESC LIMIT 1").fetchone()
        return _record(row) if row else None

    def _insert_record(self, record: EvidenceRecord) -> None:
        self._execute(
            f"INSERT INTO evidence ({_COLUMNS}) VALUES ({', '.join(['%s'] * 14)})",
            (
                record.seq,
                record.scan_id,
                record.check_id,
                record.article,
                record.resource,
                record.locator,
                record.status.value,
                record.method,
                canonical_json(record.counts),
                canonical_json(list(record.masked_samples)),
                canonical_json(record.details),
                format_time(record.scanned_at),
                record.prev_hash,
                record.hash,
            ),
        )

    def _insert_diff(self, entry: DiffEntry) -> None:
        self._execute(
            f"INSERT INTO evidence_diff ({_DIFF_COLUMNS}, regression)"
            f" VALUES ({', '.join(['%s'] * 9)})",
            (
                entry.scan_id,
                entry.prev_scan_id,
                entry.check_id,
                entry.article,
                entry.resource,
                entry.locator,
                entry.before.value if entry.before else None,
                entry.after.value if entry.after else None,
                entry.regression,
            ),
        )

    @contextmanager
    def _write_transaction(self) -> Iterator[None]:
        """One writer at a time, so two scans cannot both extend the same head."""
        if self._sqlite:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")
        else:
            with self._conn.transaction():
                # Conflicts with itself, not with readers.
                self._conn.execute("LOCK TABLE evidence IN SHARE ROW EXCLUSIVE MODE")
                yield

    def _execute(self, sql: str, params: Sequence[Any] = ()) -> Any:
        if self._sqlite:
            return self._conn.execute(sql.replace("%s", "?"), params)
        # No params: psycopg must not read the '%' in the trigger DDL as a placeholder.
        return self._conn.execute(sql, params or None)


def _record(row: Sequence[Any]) -> EvidenceRecord:
    return EvidenceRecord(
        seq=int(row[0]),
        scan_id=row[1],
        check_id=row[2],
        article=row[3],
        resource=row[4],
        locator=row[5],
        status=Status(row[6]),
        method=row[7],
        counts=json.loads(row[8]),
        masked_samples=tuple(json.loads(row[9])),
        details=json.loads(row[10]),
        scanned_at=datetime.fromisoformat(row[11]),
        prev_hash=row[12],
        hash=row[13],
    )


def _diff_entry(row: Sequence[Any]) -> DiffEntry:
    return DiffEntry(
        scan_id=row[0],
        prev_scan_id=row[1],
        check_id=row[2],
        article=row[3],
        resource=row[4],
        locator=row[5],
        before=Status(row[6]) if row[6] else None,
        after=Status(row[7]) if row[7] else None,
    )
