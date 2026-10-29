import dataclasses
import hashlib
import json
from datetime import UTC, datetime

import pytest
from lokal import is_valid_nik

from pdp_guardian.connectors.base import (
    ColumnSample,
    FileSample,
    LogSample,
    Resource,
    ResourceKind,
)
from pdp_guardian.detect import LOG_LOCATOR, ScanResult, mask, scan_column, scan_file, scan_logs

# Synthetic, structurally valid NIKs (region 32.01 / 32.73, plausible birth dates).
FAKE_NIKS = ("3201010101900001", "3201014505920002", "3273012208850003", "3273010304880004")

TABLE = Resource("cloudsql://kopi-senja/app/customers", ResourceKind.TABLE, "asia-southeast2")
BUCKET = Resource("gs://kopi-senja-exports", ResourceKind.BUCKET, "us")
LOG = Resource("logging://kopi-senja/app", ResourceKind.LOG, None)


def column(name: str, *values: str) -> ColumnSample:
    return ColumnSample(TABLE, name, "text", sampled_rows=len(values), values=values)


def assert_no_raw_values(result: ScanResult, raws: tuple[str, ...]) -> None:
    dumped = json.dumps(dataclasses.asdict(result), default=str)
    for raw in raws:
        assert raw not in repr(result)
        assert raw not in dumped


def test_fake_niks_are_structurally_valid() -> None:
    assert all(is_valid_nik(nik) for nik in FAKE_NIKS)


def test_mask_nik() -> None:
    assert mask("NIK", FAKE_NIKS[0]) == "3201********0001"


def test_plaintext_nik_column_is_counted_and_masked() -> None:
    result = scan_column(column("nik", *FAKE_NIKS))

    (finding,) = result.findings
    assert finding.data_type == "NIK"
    assert (finding.hits, finding.scanned) == (4, 4)
    assert finding.masked_samples == ("3201********0001", "3201********0002", "3273********0003")
    assert result.named_type == "NIK"
    assert result.opaque == 0
    assert_no_raw_values(result, FAKE_NIKS)


def test_column_label_tells_kk_from_nik() -> None:
    result = scan_column(column("no_kk", FAKE_NIKS[0]))
    assert [f.data_type for f in result.findings] == ["KK"]


def test_hits_count_values_not_matches() -> None:
    result = scan_column(column("nik", FAKE_NIKS[0], "bukan nik", FAKE_NIKS[0]))
    (finding,) = result.findings
    assert (finding.hits, finding.scanned) == (2, 3)
    assert finding.masked_samples == ("3201********0001",)


def test_encrypted_column_has_no_hits_but_is_opaque() -> None:
    ciphertexts = tuple("\\x" + hashlib.sha256(nik.encode()).hexdigest() for nik in FAKE_NIKS)
    result = scan_column(column("nik", *ciphertexts))

    assert result.findings == ()
    assert result.named_type == "NIK"
    assert (result.scanned, result.opaque) == (4, 4)


def test_labelled_value_must_pass_the_structural_validator() -> None:
    # Region 12, then day 78 - 40 = 38: not a NIK, even under a "nik" label.
    result = scan_column(column("nik", "1234567890123456"))
    assert result.findings == ()


def test_column_without_personal_data() -> None:
    result = scan_column(column("status", "active", "inactive"))
    assert result.findings == ()
    assert result.named_type is None
    assert result.opaque == 0


def test_file_counts_lines() -> None:
    text = "id,nik\n1," + FAKE_NIKS[0] + "\n\n2," + FAKE_NIKS[1] + "\n3,-\n"
    sample = FileSample(BUCKET, "export.csv", "text/csv", len(text), truncated=False, text=text)

    result = scan_file(sample)

    assert (result.locator, result.scanned) == ("export.csv", 4)
    (finding,) = result.findings
    assert (finding.data_type, finding.hits) == ("NIK", 2)
    assert_no_raw_values(result, FAKE_NIKS)


def test_logs_count_entries() -> None:
    at = datetime(2026, 10, 24, tzinfo=UTC)
    samples = [
        LogSample(LOG, "e1", at, text="GET /health 200"),
        LogSample(LOG, "e2", at, text=f"registered user nik={FAKE_NIKS[0]}"),
        LogSample(LOG, "e3", at, text="GET /menu 200"),
    ]

    result = scan_logs(LOG, samples)

    assert (result.locator, result.scanned) == (LOG_LOCATOR, 3)
    (finding,) = result.findings
    assert (finding.data_type, finding.hits) == ("NIK", 1)
    assert_no_raw_values(result, FAKE_NIKS)


def test_empty_logs_scan_nothing() -> None:
    result = scan_logs(LOG, [])
    assert (result.scanned, result.findings) == (0, ())


@pytest.mark.parametrize(
    ("data_type", "value"),
    [
        ("NIK", FAKE_NIKS[0]),
        ("NAME", "Budi Santoso"),
        ("PHONE", "081234567890"),
        ("EMAIL", "budi@example.com"),
    ],
)
def test_mask_hides_the_value(data_type: str, value: str) -> None:
    assert value not in mask(data_type, value)
