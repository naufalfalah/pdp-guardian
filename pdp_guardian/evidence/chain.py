"""Evidence records and the hash chain that makes tampering detectable.

``hash = sha256(prev_hash + canonical_json(record_without_hash))``. Each record
commits to the one before it, so changing, removing, or reordering any record
breaks every hash after it.
"""

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any

from pdp_guardian.checks import CheckResult, Status, article_for

GENESIS_HASH = "0" * 64


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    seq: int  # position in the chain, starting at 1
    scan_id: str
    check_id: str
    article: str
    resource: str
    locator: str
    status: Status
    method: str
    counts: dict[str, int]
    masked_samples: tuple[str, ...]
    details: dict[str, str]
    scanned_at: datetime  # UTC
    prev_hash: str
    hash: str

    @property
    def evidence_id(self) -> str:
        return f"EV-{self.seq:06d}"

    @property
    def key(self) -> tuple[str, str, str]:
        """Identifies the same check on the same thing across scans."""
        return (self.check_id, self.resource, self.locator)

    def payload(self) -> dict[str, Any]:
        """Everything that is hashed: the record without ``hash``, as JSON-ready values."""
        return {
            "seq": self.seq,
            "scan_id": self.scan_id,
            "check_id": self.check_id,
            "article": self.article,
            "resource": self.resource,
            "locator": self.locator,
            "status": self.status.value,
            "method": self.method,
            "counts": self.counts,
            "masked_samples": list(self.masked_samples),
            "details": self.details,
            "scanned_at": format_time(self.scanned_at),
            "prev_hash": self.prev_hash,
        }


@dataclass(frozen=True, slots=True)
class ChainCheck:
    valid: bool
    checked: int
    first_invalid: int | None = None  # seq of the first record that does not verify
    reason: str | None = None


def canonical_json(value: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace, UTF-8 kept as is."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    return hashlib.sha256((prev_hash + canonical_json(payload)).encode("utf-8")).hexdigest()


def format_time(moment: datetime) -> str:
    """UTC, ISO 8601, microseconds: the one textual form that is hashed and stored."""
    if moment.tzinfo is None:
        raise ValueError("evidence timestamps must be timezone-aware")
    return moment.astimezone(UTC).isoformat(timespec="microseconds")


def build_records(
    results: Sequence[CheckResult],
    scan_id: str,
    scanned_at: datetime,
    head: EvidenceRecord | None,
) -> list[EvidenceRecord]:
    """Chain ``results`` onto ``head`` (the last stored record, or ``None`` for a new chain)."""
    seq = head.seq if head else 0
    prev_hash = head.hash if head else GENESIS_HASH
    scanned_at = datetime.fromisoformat(format_time(scanned_at))
    records = []
    for result in results:
        seq += 1
        unsigned = EvidenceRecord(
            seq=seq,
            scan_id=scan_id,
            check_id=result.check_id,
            article=article_for(result.check_id).label,
            resource=result.resource,
            locator=result.locator,
            status=result.status,
            method=result.method,
            counts=dict(result.counts),
            masked_samples=result.masked_samples,
            details=dict(result.details),
            scanned_at=scanned_at,
            prev_hash=prev_hash,
            hash="",
        )
        record = replace(unsigned, hash=compute_hash(prev_hash, unsigned.payload()))
        records.append(record)
        prev_hash = record.hash
    return records


def verify_chain(records: Sequence[EvidenceRecord]) -> ChainCheck:
    """Recompute every hash and link, from the genesis record, in ``seq`` order."""
    prev_hash = GENESIS_HASH
    for expected_seq, record in enumerate(records, start=1):
        if record.seq != expected_seq:
            return ChainCheck(False, expected_seq - 1, record.seq, "sequence gap or reordering")
        if record.prev_hash != prev_hash:
            return ChainCheck(False, expected_seq - 1, record.seq, "prev_hash does not link")
        if compute_hash(prev_hash, record.payload()) != record.hash:
            return ChainCheck(False, expected_seq - 1, record.seq, "content does not match hash")
        prev_hash = record.hash
    return ChainCheck(True, len(records))
