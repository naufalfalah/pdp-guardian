"""Connector contract: what every platform connector must provide.

Samples carry raw values in memory only. They are passed to ``detect/`` and must
never be logged, persisted, or serialized. Raw-value fields are excluded from
``repr`` so an accidental log line or traceback cannot leak them. Do not call
``dataclasses.asdict`` on a sample: it would copy the raw values out.
"""

from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Protocol

MAX_MASKED_SAMPLES = 3


class ResourceKind(StrEnum):
    TABLE = "table"
    BUCKET = "bucket"
    LOG = "log"


@dataclass(frozen=True, slots=True)
class Resource:
    """Something that can hold personal data.

    ``uri`` must match the ``resource`` values in declaration.yaml, e.g.
    ``cloudsql://kopi-senja/app/customers``. ``location`` is the cloud region
    (e.g. ``asia-southeast2``), or ``None`` when unknown, which makes C5 return
    NEEDS_REVIEW.
    """

    uri: str
    kind: ResourceKind
    location: str | None


@dataclass(frozen=True, slots=True)
class ColumnSample:
    """Sampled non-null values of one table column."""

    resource: Resource
    column: str
    sql_type: str  # declared column type, e.g. "text", "bytea"
    sampled_rows: int  # rows sampled, including rows where this column is NULL
    values: tuple[str, ...] = field(repr=False)


@dataclass(frozen=True, slots=True)
class FileSample:
    """The first ``max_bytes`` of one object in a bucket, decoded as text."""

    resource: Resource
    path: str
    content_type: str | None
    size_bytes: int  # full object size
    truncated: bool
    text: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class LogSample:
    """One log entry's payload, rendered as text."""

    resource: Resource
    entry_id: str | None
    timestamp: datetime
    text: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class TimestampStats:
    """Aggregates over a declared timestamp column, used by C2 (retention).

    Retention needs the oldest row, which sampling cannot find reliably, so this
    is an aggregate query. It returns counts and a timestamp only, no values.
    """

    resource: Resource
    column: str
    row_count: int
    rows_before_cutoff: int
    null_rows: int  # rows where the column is NULL: their age cannot be judged
    oldest: datetime | None  # None when the table is empty or the column is all NULL


@dataclass(frozen=True, slots=True)
class Finding:
    """Detector output. Safe to persist: counts and masked samples only."""

    resource: Resource
    locator: str  # column name, object path, or log entry id
    data_type: str  # personal data type, e.g. "NIK"
    hits: int  # values that passed the structural validator
    scanned: int  # non-null values examined
    masked_samples: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not 0 <= self.hits <= self.scanned:
            raise ValueError(f"hits must be between 0 and scanned ({self.scanned})")
        if len(self.masked_samples) > MAX_MASKED_SAMPLES:
            raise ValueError(f"at most {MAX_MASKED_SAMPLES} masked samples allowed")


class Connector(Protocol):
    """Read-only access to one platform. The only platform-specific code.

    Implementations must never write to the scanned system. Calling a scan
    method with a resource of the wrong kind raises ``ValueError``.
    """

    def inventory(self) -> list[Resource]:
        """Everything that exists, including each resource's location."""
        ...

    def scan_tables(self, resource: Resource, sample: int) -> Iterator[ColumnSample]:
        """One sample per column, drawn from at most ``sample`` rows."""
        ...

    def scan_files(self, resource: Resource, max_bytes: int) -> Iterator[FileSample]:
        """One sample per object, reading at most ``max_bytes`` of each."""
        ...

    def scan_logs(self, resource: Resource, since: datetime, limit: int) -> Iterator[LogSample]:
        """At most ``limit`` entries written at or after ``since``."""
        ...

    def timestamp_stats(self, resource: Resource, column: str, cutoff: datetime) -> TimestampStats:
        """Row counts and the oldest value of ``column``; rows before ``cutoff`` are counted."""
        ...
