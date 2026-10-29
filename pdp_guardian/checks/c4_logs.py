"""C4: personal data written to application logs."""

from datetime import datetime, timedelta

from pdp_guardian.checks.model import CheckResult, Status
from pdp_guardian.connectors.base import MAX_MASKED_SAMPLES
from pdp_guardian.detect import ScanResult

CHECK_ID = "C4"

#: Default scan window: log entries written in the last 7 days.
C4_WINDOW_DAYS = 7


def log_window_start(now: datetime, days: int = C4_WINDOW_DAYS) -> datetime:
    return now - timedelta(days=days)


def check_logs(result: ScanResult, since: datetime, limit: int) -> CheckResult:
    """C4 for one log resource, from the entries written at or after ``since``."""
    hits = {f.data_type: f for f in result.findings if f.hits > 0}
    counts = {"scanned": result.scanned, "limit": limit}
    counts.update({data_type: f.hits for data_type, f in sorted(hits.items())})
    details = {"since": since.isoformat()}
    if result.scanned >= limit:
        details["note"] = "entry limit reached; older entries in the window were not scanned"

    if result.scanned == 0:
        status = Status.NOT_ASSESSED
        details["note"] = "no log entries in the window"
    elif hits:
        status = Status.FAIL
        details["data_types"] = ", ".join(sorted(hits))
    else:
        status = Status.PASS

    masked = tuple(s for _, f in sorted(hits.items()) for s in f.masked_samples)
    return CheckResult(
        check_id=CHECK_ID,
        resource=result.resource.uri,
        locator=result.locator,
        status=status,
        method=f"scanned up to {limit} log entries written since {since.isoformat()}",
        counts=counts,
        masked_samples=masked[:MAX_MASKED_SAMPLES],
        details=details,
    )
