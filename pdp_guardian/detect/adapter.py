"""Adapter around lokal-id: the only module that touches raw values.

Samples go in, ``ScanResult`` objects come out holding counts and masked samples
only. Nothing here logs, and no raw value is ever copied into a result.
"""

import math
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from lokal import (
    PII_TYPES,
    detect_pii,
    field_type,
    is_valid_nik,
    parse_npwp,
    parse_phone,
    partial_mask,
)

from pdp_guardian.connectors.base import (
    MAX_MASKED_SAMPLES,
    ColumnSample,
    FileSample,
    Finding,
    LogSample,
    Resource,
)

#: Every personal data type the detector knows. declaration.yaml may only use these.
DATA_TYPES: tuple[str, ...] = PII_TYPES

# "high" keeps only matches that pass a structural validator (NIK region and birth
# date, Luhn, ...) or are anchored by a field label. Medium matches are guesses.
_MIN_CONFIDENCE = "high"

LOG_LOCATOR = "payload"

# lokal-id rates a value under a matching label ("nik: ...") as high confidence
# without checking its structure, so "nik: <hex ciphertext>" would count as a NIK.
# Identifiers with a structural rule are re-validated before they count.
# HACKATHON: KK reuses the NIK structure check (region + date + serial); a KK encodes
# an issue date rather than a birth date, so this is slightly lenient.
_VALIDATORS: dict[str, Callable[[str], bool]] = {
    "NIK": is_valid_nik,
    "KK": is_valid_nik,
    "NPWP": lambda value: parse_npwp(value).valid,
    "PHONE": lambda value: parse_phone(value).valid,
}


@dataclass(frozen=True, slots=True)
class ScanResult:
    """What detection found in one column, file, or log resource."""

    resource: Resource
    locator: str  # column name, object path, or LOG_LOCATOR
    scanned: int  # non-null column values, non-empty file lines, or log entries
    findings: tuple[Finding, ...]
    # Columns only: the data type the column *name* announces, e.g. "nik" -> "NIK".
    named_type: str | None = None
    # Columns only: values that look like ciphertext or hashes (long hex/base64, high entropy).
    opaque: int = 0


def mask(data_type: str, value: str) -> str:
    """Masked form of a value, e.g. ``3201********0001``. Raises on unknown types."""
    return partial_mask(data_type, value)


def scan_column(sample: ColumnSample) -> ScanResult:
    # The column name is passed as a label ("no kk: 3201..."), the way lokal-id reads
    # forms. It tells KK from NIK (same structure) and anchors names and addresses.
    label = sample.column.replace("_", " ")
    tally = _Tally()
    opaque = 0
    for value in sample.values:
        tally.add(f"{label}: {value}", skip=len(label) + 2)
        opaque += _looks_opaque(value)
    return ScanResult(
        resource=sample.resource,
        locator=sample.column,
        scanned=len(sample.values),
        findings=tally.findings(sample.resource, sample.column, len(sample.values)),
        named_type=field_type(sample.column),
        opaque=opaque,
    )


def scan_file(sample: FileSample) -> ScanResult:
    lines = [line for line in sample.text.splitlines() if line.strip()]
    tally = _Tally()
    for line in lines:
        tally.add(line)
    return ScanResult(
        resource=sample.resource,
        locator=sample.path,
        scanned=len(lines),
        findings=tally.findings(sample.resource, sample.path, len(lines)),
    )


def scan_logs(resource: Resource, samples: Iterable[LogSample]) -> ScanResult:
    tally = _Tally()
    scanned = 0
    for sample in samples:
        tally.add(sample.text)
        scanned += 1
    return ScanResult(
        resource=resource,
        locator=LOG_LOCATOR,
        scanned=scanned,
        findings=tally.findings(resource, LOG_LOCATOR, scanned),
    )


class _Tally:
    """Counts, per data type, how many texts contain it, keeping a few masked samples."""

    def __init__(self) -> None:
        self._hits: Counter[str] = Counter()
        self._masked: dict[str, list[str]] = {}

    def add(self, text: str, skip: int = 0) -> None:
        """Detect in ``text``, ignoring matches that start before ``skip`` (the label)."""
        seen: set[str] = set()
        for match in detect_pii(text, min_confidence=_MIN_CONFIDENCE):
            if match.start < skip:
                continue
            validator = _VALIDATORS.get(match.type)
            if validator is not None and not validator(match.value):
                continue
            seen.add(match.type)
            masked = mask(match.type, match.value)
            samples = self._masked.setdefault(match.type, [])
            # Defense in depth: never keep a "masked" value that still contains the raw one.
            keep = match.value not in masked and masked not in samples
            if keep and len(samples) < MAX_MASKED_SAMPLES:
                samples.append(masked)
        self._hits.update(seen)

    def findings(self, resource: Resource, locator: str, scanned: int) -> tuple[Finding, ...]:
        return tuple(
            Finding(
                resource=resource,
                locator=locator,
                data_type=data_type,
                hits=hits,
                scanned=scanned,
                masked_samples=tuple(self._masked.get(data_type, ())),
            )
            for data_type, hits in sorted(self._hits.items())
        )


_HEX = frozenset("0123456789abcdefABCDEF")
_BASE64 = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_")


# HACKATHON: a heuristic. It cannot tell strong encryption from weak encoding; C1
# reports "encryption strength not assessed" for that reason. Production would read
# the column's encryption metadata (e.g. pgcrypto usage, KMS-backed columns).
def _looks_opaque(value: str) -> bool:
    """Long hex or base64 with high entropy: likely ciphertext or a hash."""
    v = value.strip().removeprefix("\\x").removeprefix("0x")
    if len(v) >= 32 and set(v) <= _HEX:
        return _entropy(v) >= 3.0
    if len(v) >= 24 and set(v) <= _BASE64:
        return _entropy(v) >= 4.0
    return False


def _entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in Counter(text).values())
