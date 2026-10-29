"""C2: rows kept longer than the company's own declared retention period."""

from datetime import datetime, timedelta

from pdp_guardian.checks.model import WHOLE_RESOURCE, CheckResult, Status
from pdp_guardian.connectors.base import TimestampStats
from pdp_guardian.declaration import Category, Location

CHECK_ID = "C2"


def retention_cutoff(category: Category, now: datetime) -> datetime:
    """Rows with a timestamp before this are older than the declared retention period."""
    return now - timedelta(days=category.retention_days)


def check_retention(
    category: Category,
    location: Location,
    stats: TimestampStats | None,
    now: datetime,
    unavailable: str = "timestamp statistics could not be collected",
) -> CheckResult:
    """C2 for one declared location of one category.

    ``stats`` is ``None`` when they could not be collected (resource not found,
    query error); ``unavailable`` says why. Both cases are NOT_ASSESSED.
    """
    cutoff = retention_cutoff(category, now)
    column = location.timestamp_column
    # A resource can appear in several categories with different retention periods.
    locator = f"{category.id}:{column or WHOLE_RESOURCE}"
    details = {
        "category": category.id,
        "cutoff": cutoff.isoformat(),
        **({"timestamp_column": column} if column else {}),
    }

    def outcome(status: Status, method: str, **extra: str) -> CheckResult:
        counts = {"retention_days": category.retention_days}
        if stats is not None:
            counts |= {
                "row_count": stats.row_count,
                "rows_before_cutoff": stats.rows_before_cutoff,
                "null_rows": stats.null_rows,
            }
        return CheckResult(
            check_id=CHECK_ID,
            resource=location.resource,
            locator=locator,
            status=status,
            method=method,
            counts=counts,
            details=details | extra,
        )

    if column is None:
        return outcome(
            Status.NOT_ASSESSED,
            "no timestamp_column declared for this location",
            note="timestamp column not declared",
        )
    if stats is None:
        return outcome(Status.NOT_ASSESSED, f"aggregate over column {column}", note=unavailable)

    method = (
        f"aggregate over column {column}: count(*), rows with {column} < cutoff "
        f"(now - {category.retention_days} days), NULL count, min({column})"
    )
    oldest = {"oldest": stats.oldest.isoformat()} if stats.oldest else {}
    if stats.rows_before_cutoff > 0:
        return outcome(Status.FAIL, method, **oldest)
    if stats.row_count == 0:
        return outcome(Status.NOT_ASSESSED, method, note="table is empty")
    if stats.null_rows > 0:
        return outcome(Status.NEEDS_REVIEW, method, note="some rows have no timestamp", **oldest)
    return outcome(Status.PASS, method, **oldest)
