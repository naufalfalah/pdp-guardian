"""C5: personal data held in a region outside Indonesia.

Never FAIL: a cross-border transfer is lawful under conditions (adequacy, safeguards,
consent) that PDP Guardian cannot see. The most it reports is NEEDS_REVIEW.
"""

from collections.abc import Iterable

from pdp_guardian.checks.model import WHOLE_RESOURCE, CheckResult, Status
from pdp_guardian.connectors.base import Resource

CHECK_ID = "C5"

# Cloud regions physically in Indonesia: GCP Jakarta, AWS Jakarta, Azure Indonesia Central.
# A multi-region such as GCS "ASIA" spans other countries, so it is not listed.
INDONESIA_REGIONS = frozenset({"asia-southeast2", "ap-southeast-3", "indonesiacentral"})


def check_region(resource: Resource, data_types: Iterable[str]) -> CheckResult | None:
    """C5 for one resource, or ``None`` when no personal data was found in it."""
    types = sorted(set(data_types))
    if not types:
        return None

    details = {"data_types": ", ".join(types)}
    if resource.location is None:
        status = Status.NEEDS_REVIEW
        details["note"] = "location unknown"
    else:
        details["location"] = resource.location
        inside = resource.location.lower() in INDONESIA_REGIONS
        status = Status.PASS if inside else Status.NEEDS_REVIEW

    return CheckResult(
        check_id=CHECK_ID,
        resource=resource.uri,
        locator=WHOLE_RESOURCE,
        status=status,
        method="compared the resource location reported by the platform with Indonesian regions",
        counts={"data_types": len(types)},
        details=details,
    )
