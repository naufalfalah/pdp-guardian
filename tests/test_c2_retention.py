from datetime import UTC, datetime, timedelta

from pdp_guardian.checks import Status, check_retention, retention_cutoff
from pdp_guardian.connectors.base import Resource, ResourceKind, TimestampStats
from pdp_guardian.declaration import Category, Location

NOW = datetime(2026, 10, 24, 9, 0, tzinfo=UTC)
URI = "cloudsql://kopi-senja/app/customers"
TABLE = Resource(URI, ResourceKind.TABLE, "asia-southeast2")
LOCATION = Location(URI, timestamp_column="created_at")
CATEGORY = Category("customer_identity", ("NIK", "NAME"), "KYC", 730, (LOCATION,))


def stats(row_count: int, before: int, null_rows: int = 0, oldest_days: int | None = 100):
    oldest = NOW - timedelta(days=oldest_days) if oldest_days is not None else None
    return TimestampStats(TABLE, "created_at", row_count, before, null_rows, oldest)


def test_cutoff_is_now_minus_declared_days() -> None:
    assert retention_cutoff(CATEGORY, NOW) == NOW - timedelta(days=730)


def test_rows_older_than_retention_fail() -> None:
    result = check_retention(CATEGORY, LOCATION, stats(100, 12, oldest_days=900), NOW)

    assert result.status is Status.FAIL
    assert (result.check_id, result.resource) == ("C2", URI)
    assert result.locator == "customer_identity:created_at"
    assert result.counts == {
        "retention_days": 730,
        "row_count": 100,
        "rows_before_cutoff": 12,
        "null_rows": 0,
    }
    assert result.details["oldest"] == (NOW - timedelta(days=900)).isoformat()
    assert result.details["cutoff"] == (NOW - timedelta(days=730)).isoformat()


def test_all_rows_within_retention_pass() -> None:
    assert check_retention(CATEGORY, LOCATION, stats(100, 0), NOW).status is Status.PASS


def test_undeclared_timestamp_column_is_not_assessed() -> None:
    location = Location(URI)
    result = check_retention(CATEGORY, location, None, NOW)
    assert result.status is Status.NOT_ASSESSED
    assert result.details["note"] == "timestamp column not declared"
    assert result.locator == "customer_identity:*"


def test_missing_stats_are_not_assessed() -> None:
    result = check_retention(CATEGORY, LOCATION, None, NOW, unavailable="resource not in inventory")
    assert result.status is Status.NOT_ASSESSED
    assert result.details["note"] == "resource not in inventory"


def test_empty_table_is_not_assessed() -> None:
    result = check_retention(CATEGORY, LOCATION, stats(0, 0, oldest_days=None), NOW)
    assert result.status is Status.NOT_ASSESSED


def test_rows_without_timestamp_need_review() -> None:
    assert check_retention(CATEGORY, LOCATION, stats(100, 0, 3), NOW).status is Status.NEEDS_REVIEW


def test_old_rows_fail_even_when_some_timestamps_are_null() -> None:
    assert check_retention(CATEGORY, LOCATION, stats(100, 1, 3), NOW).status is Status.FAIL
