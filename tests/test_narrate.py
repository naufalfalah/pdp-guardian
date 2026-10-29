import re
from datetime import UTC, datetime

import pytest

from pdp_guardian.checks import CheckResult, Status
from pdp_guardian.evidence import EvidenceRecord, build_records
from pdp_guardian.narrate import STATUS_LABELS, narrate

AT = datetime(2026, 10, 24, 9, 0, tzinfo=UTC)
FORBIDDEN = re.compile(r"patuh|compliant|compliance|certif|sertifi", re.IGNORECASE)

C2_COUNTS = {"retention_days": 730, "row_count": 100, "rows_before_cutoff": 12, "null_rows": 3}

# Every check in every status it can produce, with the counts/details it would carry.
RESULTS = [
    CheckResult("C1", "db/customers", "nik", Status.FAIL, "m", {"scanned": 4, "NIK": 4},
                ("3201********0001",), {"data_types": "NIK"}),
    CheckResult("C1", "db/customers", "nik", Status.PASS, "m", {"scanned": 4, "opaque": 4},
                details={"note": "encryption strength not assessed"}),
    CheckResult("C1", "db/customers", "nik", Status.NOT_ASSESSED, "m", {"scanned": 0},
                details={"note": "no non-null values sampled"}),
    CheckResult("C1", "db/orders", "*", Status.NOT_ASSESSED, "m", details={"error": "Timeout"}),
    CheckResult("C2", "db/customers", "ci:created_at", Status.FAIL, "m", C2_COUNTS,
                details={"category": "ci", "oldest": "2024-04-07T00:00:00+00:00"}),
    CheckResult("C2", "db/customers", "ci:created_at", Status.PASS, "m", C2_COUNTS,
                details={"category": "ci"}),
    CheckResult("C2", "db/customers", "ci:created_at", Status.NEEDS_REVIEW, "m", C2_COUNTS,
                details={"category": "ci", "note": "some rows have no timestamp"}),
    CheckResult("C2", "db/customers", "ci:*", Status.NOT_ASSESSED, "m", {"retention_days": 730},
                details={"category": "ci", "note": "timestamp column not declared"}),
    CheckResult("C3", "db/leads", "*", Status.FAIL, "m", details={"undeclared_types": "PHONE"}),
    CheckResult("C3", "db/customers", "*", Status.PASS, "m",
                details={"declared_not_found": "ADDRESS"}),
    CheckResult("C3", "db/gone", "*", Status.NOT_ASSESSED, "m"),
    CheckResult("C4", "logs/app", "payload", Status.FAIL, "m", {"scanned": 3, "NIK": 1},
                ("3201********0001",), {"since": "2026-10-17", "data_types": "NIK"}),
    CheckResult("C4", "logs/app", "payload", Status.PASS, "m", {"scanned": 3},
                details={"since": "2026-10-17"}),
    CheckResult("C4", "logs/app", "payload", Status.NOT_ASSESSED, "m", {"scanned": 0},
                details={"since": "2026-10-17", "note": "no log entries in the window"}),
    CheckResult("C5", "gs://exports", "*", Status.NEEDS_REVIEW, "m",
                details={"data_types": "NIK", "location": "us"}),
    CheckResult("C5", "gs://exports", "*", Status.NEEDS_REVIEW, "m",
                details={"data_types": "NIK", "note": "location unknown"}),
    CheckResult("C5", "db/customers", "*", Status.PASS, "m",
                details={"data_types": "NIK", "location": "asia-southeast2"}),
]  # fmt: skip

RECORDS = build_records(RESULTS, "s1", AT, head=None)


def ids(record: EvidenceRecord) -> str:
    return f"{record.check_id}-{record.status}-{record.seq}"


@pytest.mark.parametrize("record", RECORDS, ids=ids)
def test_never_claims_a_verdict(record: EvidenceRecord) -> None:
    story = narrate(record)
    text = " ".join(filter(None, [story.title, story.summary, story.remediation]))
    assert not FORBIDDEN.search(text)
    assert not FORBIDDEN.search(" ".join(STATUS_LABELS.values()))


@pytest.mark.parametrize("record", RECORDS, ids=ids)
def test_every_sentence_cites_the_evidence_id(record: EvidenceRecord) -> None:
    story = narrate(record)
    tag = f"[{record.evidence_id}]"
    for part in filter(None, [story.summary, story.remediation]):
        sentences = [s for s in re.split(r"(?=\[EV-)", part) if s.strip()]
        assert sentences
        assert all(s.startswith(tag) for s in sentences)


@pytest.mark.parametrize("record", RECORDS, ids=ids)
def test_status_is_copied_not_derived(record: EvidenceRecord) -> None:
    assert narrate(record).status is record.status


def test_fail_explains_and_suggests_a_fix() -> None:
    story = narrate(RECORDS[0])
    assert "4 dari 4 nilai sampel (100%)" in story.summary
    assert "NIK" in story.summary
    assert story.remediation and "Enkripsi" in story.remediation


def test_encryption_note_is_translated() -> None:
    assert "kekuatan enkripsinya tidak dinilai" in narrate(RECORDS[1]).summary


def test_scan_errors_are_explained() -> None:
    assert "Pemindaian gagal (Timeout)" in narrate(RECORDS[3]).summary


def test_declared_not_found_is_a_warning() -> None:
    summary = narrate(RECORDS[9]).summary
    assert "Peringatan: ADDRESS dideklarasikan tetapi tidak ditemukan" in summary
