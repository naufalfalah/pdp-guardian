import hashlib

from pdp_guardian.checks import Status, check_plaintext
from pdp_guardian.checks.c1_plaintext import ENCRYPTION_NOTE, UNRECOGNISED_NOTE
from pdp_guardian.connectors.base import ColumnSample, Resource, ResourceKind
from pdp_guardian.detect import scan_column

# Synthetic, structurally valid NIKs.
FAKE_NIKS = ("3201010101900001", "3201014505920002", "3273012208850003", "3273010304880004")

TABLE = Resource("cloudsql://kopi-senja/app/customers", ResourceKind.TABLE, "asia-southeast2")


def column(name: str, *values: str):
    return scan_column(ColumnSample(TABLE, name, "text", sampled_rows=len(values), values=values))


def test_plaintext_nik_column_fails_with_masked_samples() -> None:
    result = check_plaintext(column("nik", *FAKE_NIKS))

    assert result is not None
    assert result.status is Status.FAIL
    assert (result.check_id, result.resource, result.locator) == ("C1", TABLE.uri, "nik")
    assert result.counts == {"scanned": 4, "opaque": 0, "NIK": 4}
    assert result.details["data_types"] == "NIK"
    assert result.masked_samples == ("3201********0001", "3201********0002", "3273********0003")
    for nik in FAKE_NIKS:
        assert nik not in repr(result)


def test_ratio_threshold_is_inclusive() -> None:
    filler = ("bukan nomor",) * 9
    assert check_plaintext(column("nik", FAKE_NIKS[0], *filler)).status is Status.FAIL  # 1/10


def test_below_ratio_passes() -> None:
    filler = ("bukan nomor",) * 10
    result = check_plaintext(column("nik", FAKE_NIKS[0], *filler))  # 1/11
    assert result.status is Status.PASS
    assert result.counts["NIK"] == 1
    assert result.masked_samples == ()


def test_ratio_is_configurable() -> None:
    filler = ("bukan nomor",) * 10
    assert check_plaintext(column("nik", FAKE_NIKS[0], *filler), ratio=0.05).status is Status.FAIL


def test_encrypted_named_column_passes_with_encryption_note() -> None:
    ciphertexts = tuple("\\x" + hashlib.sha256(n.encode()).hexdigest() for n in FAKE_NIKS)
    result = check_plaintext(column("nik", *ciphertexts))

    assert result is not None
    assert result.status is Status.PASS
    assert result.details["note"] == ENCRYPTION_NOTE
    assert result.counts == {"scanned": 4, "opaque": 4}


def test_named_column_with_unrecognised_values_passes_with_note() -> None:
    result = check_plaintext(column("nik", "3201********0001", "3201********0002"))
    assert result.status is Status.PASS
    assert result.details["note"] == UNRECOGNISED_NOTE


def test_empty_named_column_is_not_assessed() -> None:
    result = check_plaintext(column("nik"))
    assert result is not None
    assert result.status is Status.NOT_ASSESSED


def test_identifier_in_unnamed_column_still_counts() -> None:
    result = check_plaintext(column("catatan", *FAKE_NIKS))
    assert result.status is Status.FAIL


def test_column_without_identifiers_does_not_apply() -> None:
    assert check_plaintext(column("status", "aktif", "nonaktif")) is None
    assert check_plaintext(column("no_hp", "081234567890")) is None  # phone is not an identifier
