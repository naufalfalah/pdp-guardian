"""Check results and per-article aggregation.

Every status is decided here, by deterministic code. Nothing downstream (the
narrator included) may change one.
"""

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum

from pdp_guardian.connectors.base import MAX_MASKED_SAMPLES

# Locator for a result about a whole resource rather than one column, path, or log payload.
WHOLE_RESOURCE = "*"


class Status(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    NOT_ASSESSED = "NOT_ASSESSED"


@dataclass(frozen=True, slots=True)
class CheckResult:
    """One check's outcome for one resource (and locator). Safe to persist.

    ``method`` describes how the result was obtained and never contains values.
    ``counts`` holds numbers only; ``details`` holds short strings such as data
    type names, a region, or an ISO timestamp, never personal data.
    """

    check_id: str
    resource: str
    locator: str
    status: Status
    method: str
    counts: dict[str, int] = field(default_factory=dict)
    masked_samples: tuple[str, ...] = ()
    details: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if len(self.masked_samples) > MAX_MASKED_SAMPLES:
            raise ValueError(f"at most {MAX_MASKED_SAMPLES} masked samples allowed")


def aggregate(statuses: Iterable[Status]) -> Status:
    """Article status from its check results.

    Any FAIL wins, then any NEEDS_REVIEW. PASS only when there is at least one
    result and every result is PASS. Anything else is NOT_ASSESSED: no default pass.
    """
    seen = set(statuses)
    if Status.FAIL in seen:
        return Status.FAIL
    if Status.NEEDS_REVIEW in seen:
        return Status.NEEDS_REVIEW
    if seen == {Status.PASS}:
        return Status.PASS
    return Status.NOT_ASSESSED
