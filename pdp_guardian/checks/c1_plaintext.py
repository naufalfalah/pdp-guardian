"""C1: national identifiers stored as plaintext in a table column."""

from pdp_guardian.checks.model import CheckResult, Status
from pdp_guardian.connectors.base import MAX_MASKED_SAMPLES
from pdp_guardian.detect import ScanResult

CHECK_ID = "C1"

#: Share of sampled non-null values that must pass a structural validator to FAIL.
C1_PLAINTEXT_RATIO = 0.10

# Identifiers with a structural validator (region code, birth-date encoding, check digits).
# HACKATHON: passport, SIM, BPJS, and NIP have no structural validator in lokal-id yet,
# so they are not counted here; production would add validators for them.
IDENTIFIER_TYPES = ("NIK", "KK", "NPWP")

ENCRYPTION_NOTE = "encryption strength not assessed"
UNRECOGNISED_NOTE = (
    "values are neither plaintext identifiers nor ciphertext-like; format not assessed"
)


def check_plaintext(result: ScanResult, ratio: float = C1_PLAINTEXT_RATIO) -> CheckResult | None:
    """C1 for one column, or ``None`` when the column holds no identifiers.

    A column applies when a sampled value passes an identifier validator, or when
    its name announces an identifier (``nik``, ``no_kk``, ...): an encrypted
    ``nik`` column must still produce evidence.
    """
    findings = {f.data_type: f for f in result.findings if f.data_type in IDENTIFIER_TYPES}
    named = result.named_type in IDENTIFIER_TYPES
    if not findings and not named:
        return None

    counts = {"scanned": result.scanned, "opaque": result.opaque}
    counts.update({data_type: f.hits for data_type, f in sorted(findings.items())})
    method = (
        f"sampled {result.scanned} non-null values of column {result.locator}; counted values "
        f"passing the {'/'.join(IDENTIFIER_TYPES)} structural validator; FAIL at >= {ratio:.0%}"
    )

    def outcome(status: Status, masked: tuple[str, ...] = (), **details: str) -> CheckResult:
        return CheckResult(
            check_id=CHECK_ID,
            resource=result.resource.uri,
            locator=result.locator,
            status=status,
            method=method,
            counts=counts,
            masked_samples=masked,
            details=details,
        )

    if result.scanned == 0:
        return outcome(Status.NOT_ASSESSED, note="no non-null values sampled")

    failing = [f for _, f in sorted(findings.items()) if f.hits / result.scanned >= ratio]
    if failing:
        masked = tuple(s for f in failing for s in f.masked_samples)[:MAX_MASKED_SAMPLES]
        return outcome(Status.FAIL, masked, data_types=", ".join(f.data_type for f in failing))

    if result.opaque:
        return outcome(Status.PASS, note=ENCRYPTION_NOTE)
    if not findings:
        return outcome(Status.PASS, note=UNRECOGNISED_NOTE)
    return outcome(Status.PASS)
