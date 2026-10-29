"""Changes between two consecutive scans; PASS -> FAIL is flagged as a regression."""

from collections.abc import Sequence
from dataclasses import dataclass

from pdp_guardian.checks import Status
from pdp_guardian.evidence.chain import EvidenceRecord


@dataclass(frozen=True, slots=True)
class DiffEntry:
    scan_id: str
    prev_scan_id: str
    check_id: str
    article: str
    resource: str
    locator: str
    before: Status | None  # None: not checked in the previous scan
    after: Status | None  # None: not checked in this scan

    @property
    def regression(self) -> bool:
        return self.before is Status.PASS and self.after is Status.FAIL


def diff_scans(
    previous: Sequence[EvidenceRecord], current: Sequence[EvidenceRecord]
) -> list[DiffEntry]:
    """Every (check, resource, locator) whose status changed, appeared, or disappeared."""
    if not previous or not current:
        return []
    before = {r.key: r for r in previous}
    after = {r.key: r for r in current}
    prev_scan_id, scan_id = previous[0].scan_id, current[0].scan_id

    entries = []
    for key in sorted(before.keys() | after.keys()):
        old, new = before.get(key), after.get(key)
        old_status = old.status if old else None
        new_status = new.status if new else None
        if old_status == new_status:
            continue
        check_id, resource, locator = key
        entries.append(
            DiffEntry(
                scan_id=scan_id,
                prev_scan_id=prev_scan_id,
                check_id=check_id,
                article=new.article if new else old.article,
                resource=resource,
                locator=locator,
                before=old_status,
                after=new_status,
            )
        )
    return entries
