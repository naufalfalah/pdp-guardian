"""C3: personal data found where the declaration (records of processing) does not list it."""

from collections.abc import Iterable

from pdp_guardian.checks.model import WHOLE_RESOURCE, CheckResult, Status
from pdp_guardian.connectors.base import MAX_MASKED_SAMPLES, Finding, ResourceKind
from pdp_guardian.declaration import Declaration

CHECK_ID = "C3"

# Logs are not processing locations a DPO declares; personal data there is C4's job.
_KINDS = (ResourceKind.TABLE, ResourceKind.BUCKET)


def check_ropa(
    declaration: Declaration, scanned: Iterable[str], findings: Iterable[Finding]
) -> list[CheckResult]:
    """C3 per resource, over every resource that was declared or where data was found.

    ``scanned`` holds the URIs of resources that were actually scanned. A (resource,
    data type) pair found but not declared FAILs. Declared but not found is only a
    warning in ``details``: the declaration may be broader than the sample.
    """
    scanned = set(scanned)
    found: dict[str, set[str]] = {}
    masked: dict[str, dict[str, tuple[str, ...]]] = {}
    for finding in findings:
        if finding.hits == 0 or finding.resource.kind not in _KINDS:
            continue
        uri = finding.resource.uri
        found.setdefault(uri, set()).add(finding.data_type)
        masked.setdefault(uri, {})
        masked[uri][finding.data_type] = (
            masked[uri].get(finding.data_type, ()) + finding.masked_samples
        )

    declared = declaration.declared_types()
    results = []
    for uri in sorted(found.keys() | declared.keys()):
        found_types = found.get(uri, set())
        declared_types = declared.get(uri, frozenset())
        undeclared = sorted(found_types - declared_types)
        not_found = sorted(declared_types - found_types)

        details = {}
        if undeclared:
            details["undeclared_types"] = ", ".join(undeclared)
        if not_found:
            details["declared_not_found"] = ", ".join(not_found)
        counts = {
            "found_types": len(found_types),
            "declared_types": len(declared_types),
            "undeclared_types": len(undeclared),
        }

        if uri not in scanned:
            status = Status.NOT_ASSESSED
            method = "declared resource was not found in the inventory, so it was not scanned"
        else:
            status = Status.FAIL if undeclared else Status.PASS
            method = "compared data types detected in the scan with those declared for the resource"

        samples = tuple(s for t in undeclared for s in masked[uri][t])
        results.append(
            CheckResult(
                check_id=CHECK_ID,
                resource=uri,
                locator=WHOLE_RESOURCE,
                status=status,
                method=method,
                counts=counts,
                masked_samples=_unique(samples)[:MAX_MASKED_SAMPLES],
                details=details,
            )
        )
    return results


def _unique(items: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(items))
