from datetime import UTC, datetime

import pytest

from pdp_guardian.connectors.base import (
    ColumnSample,
    FileSample,
    Finding,
    LogSample,
    Resource,
    ResourceKind,
)

# Deliberately not NIK-shaped: these tests check plumbing, not detection.
RAW = "RAW-VALUE-MUST-NOT-LEAK"

TABLE = Resource("cloudsql://kopi-senja/app/customers", ResourceKind.TABLE, "asia-southeast2")
BUCKET = Resource("gs://kopi-senja-exports", ResourceKind.BUCKET, "us")
LOG = Resource("logging://kopi-senja/app", ResourceKind.LOG, None)


@pytest.mark.parametrize(
    "sample",
    [
        ColumnSample(TABLE, "nik", "text", sampled_rows=1, values=(RAW,)),
        FileSample(BUCKET, "export.csv", "text/csv", size_bytes=23, truncated=False, text=RAW),
        LogSample(LOG, "entry-1", datetime(2026, 10, 24, tzinfo=UTC), text=RAW),
    ],
    ids=["column", "file", "log"],
)
def test_raw_values_are_hidden_from_repr(sample: object) -> None:
    assert RAW not in repr(sample)
    assert RAW not in str(sample)


def test_finding_allows_zero_hits() -> None:
    finding = Finding(TABLE, "nik", "NIK", hits=0, scanned=100)
    assert finding.masked_samples == ()


def test_finding_rejects_hits_above_scanned() -> None:
    with pytest.raises(ValueError):
        Finding(TABLE, "nik", "NIK", hits=5, scanned=4)


def test_finding_rejects_negative_hits() -> None:
    with pytest.raises(ValueError):
        Finding(TABLE, "nik", "NIK", hits=-1, scanned=4)


def test_finding_rejects_more_than_three_masked_samples() -> None:
    with pytest.raises(ValueError):
        Finding(TABLE, "nik", "NIK", hits=4, scanned=4, masked_samples=("a", "b", "c", "d"))


def test_resource_is_hashable() -> None:
    assert {TABLE: 1}[Resource(TABLE.uri, TABLE.kind, TABLE.location)] == 1
