import dataclasses
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pdp_guardian.checks import CheckResult, Status
from pdp_guardian.evidence import (
    GENESIS_HASH,
    EvidenceRepository,
    build_records,
    canonical_json,
    compute_hash,
    diff_scans,
    verify_chain,
)

AT = datetime(2026, 10, 24, 9, 0, tzinfo=UTC)
LATER = datetime(2026, 10, 24, 9, 5, tzinfo=UTC)
CUSTOMERS = "cloudsql://kopi-senja/app/customers"


def c1(status: Status) -> CheckResult:
    masked = ("3201********0001",) if status is Status.FAIL else ()
    return CheckResult("C1", CUSTOMERS, "nik", status, "sampled", {"scanned": 4}, masked)


def c5(status: Status) -> CheckResult:
    return CheckResult("C5", "gs://exports", "*", status, "region", details={"location": "us"})


def test_canonical_json_is_order_independent() -> None:
    assert canonical_json({"b": 1, "a": [1, "é"]}) == '{"a":[1,"é"],"b":1}'


def test_records_chain_from_genesis() -> None:
    records = build_records([c1(Status.FAIL), c5(Status.NEEDS_REVIEW)], "s1", AT, head=None)

    first, second = records
    assert (first.seq, first.prev_hash) == (1, GENESIS_HASH)
    assert first.hash == compute_hash(GENESIS_HASH, first.payload())
    assert second.prev_hash == first.hash
    assert first.article == "PP 33/2026 Pasal 123"
    assert first.evidence_id == "EV-000001"
    assert verify_chain(records).valid


def test_build_records_continues_from_head() -> None:
    first = build_records([c1(Status.FAIL)], "s1", AT, head=None)
    second = build_records([c1(Status.PASS)], "s2", LATER, head=first[-1])
    assert second[0].seq == 2
    assert second[0].prev_hash == first[-1].hash
    assert verify_chain(first + second).valid


@pytest.mark.parametrize(
    "tamper",
    [
        lambda r: dataclasses.replace(r, status=Status.PASS),
        lambda r: dataclasses.replace(r, counts={"scanned": 400}),
        lambda r: dataclasses.replace(r, masked_samples=()),
        lambda r: dataclasses.replace(r, scanned_at=LATER),
    ],
    ids=["status", "counts", "masked_samples", "scanned_at"],
)
def test_modified_record_is_detected(tamper) -> None:
    records = build_records([c1(Status.FAIL), c5(Status.NEEDS_REVIEW)], "s1", AT, head=None)
    records[0] = tamper(records[0])

    check = verify_chain(records)

    assert not check.valid
    assert check.first_invalid == 1
    assert check.reason == "content does not match hash"


def test_removed_record_is_detected() -> None:
    records = build_records([c1(Status.FAIL), c5(Status.NEEDS_REVIEW)], "s1", AT, head=None)
    check = verify_chain(records[1:])
    assert not check.valid


def test_rehashed_record_breaks_the_next_link() -> None:
    records = build_records([c1(Status.FAIL), c5(Status.NEEDS_REVIEW)], "s1", AT, head=None)
    forged = dataclasses.replace(records[0], status=Status.PASS)
    records[0] = dataclasses.replace(forged, hash=compute_hash(GENESIS_HASH, forged.payload()))

    check = verify_chain(records)

    assert (check.valid, check.first_invalid, check.reason) == (False, 2, "prev_hash does not link")


def test_diff_flags_pass_to_fail_as_regression() -> None:
    before = build_records([c1(Status.PASS), c5(Status.NEEDS_REVIEW)], "s1", AT, head=None)
    after = build_records([c1(Status.FAIL), c5(Status.NEEDS_REVIEW)], "s2", LATER, before[-1])

    (entry,) = diff_scans(before, after)

    assert (entry.check_id, entry.before, entry.after) == ("C1", Status.PASS, Status.FAIL)
    assert (entry.prev_scan_id, entry.scan_id) == ("s1", "s2")
    assert entry.regression


def test_diff_fail_to_pass_is_not_a_regression() -> None:
    before = build_records([c1(Status.FAIL)], "s1", AT, head=None)
    after = build_records([c1(Status.PASS)], "s2", LATER, before[-1])
    (entry,) = diff_scans(before, after)
    assert not entry.regression


def test_diff_reports_new_and_removed_results() -> None:
    before = build_records([c1(Status.FAIL)], "s1", AT, head=None)
    after = build_records([c5(Status.NEEDS_REVIEW)], "s2", LATER, before[-1])
    entries = {(e.check_id, e.before, e.after) for e in diff_scans(before, after)}
    assert entries == {("C1", Status.FAIL, None), ("C5", None, Status.NEEDS_REVIEW)}


def test_first_scan_has_no_diff() -> None:
    assert diff_scans([], build_records([c1(Status.FAIL)], "s1", AT, head=None)) == []


# Set PDP_TEST_EVIDENCE_POSTGRES_URL to a throwaway Postgres database to also run on Postgres.
@pytest.fixture(params=["sqlite", "postgres"])
def repository_url(request, tmp_path: Path) -> str:
    if request.param == "sqlite":
        return f"sqlite:///{tmp_path / 'evidence.db'}"
    url = os.environ.get("PDP_TEST_EVIDENCE_POSTGRES_URL")
    if not url:
        pytest.skip("PDP_TEST_EVIDENCE_POSTGRES_URL not set")
    import psycopg

    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute("DROP TABLE IF EXISTS evidence, evidence_diff")
    return url


def test_repository_appends_and_diffs(repository_url: str) -> None:
    with EvidenceRepository(repository_url) as store:
        first = store.append_scan([c1(Status.PASS), c5(Status.NEEDS_REVIEW)], AT)
        second = store.append_scan([c1(Status.FAIL), c5(Status.NEEDS_REVIEW)], LATER)

        assert first.diff == []
        assert [r.seq for r in second.records] == [3, 4]
        assert [e.regression for e in second.regressions] == [True]
        assert store.scan_ids() == [first.scan_id, second.scan_id]
        assert store.latest_scan_id() == second.scan_id
        assert store.records(second.scan_id) == second.records
        assert store.diff(second.scan_id) == second.diff
        assert store.verify().valid
        assert store.verify().checked == 4

    # Reopening an existing store keeps the chain.
    with EvidenceRepository(repository_url) as store:
        third = store.append_scan([c1(Status.PASS)], LATER)
        assert third.records[0].prev_hash == second.records[-1].hash
        assert store.verify().valid


def test_repository_rejects_update_and_delete(repository_url: str) -> None:
    with EvidenceRepository(repository_url) as store:
        store.append_scan([c1(Status.FAIL)], AT)
        for statement in ("UPDATE evidence SET status = 'PASS'", "DELETE FROM evidence"):
            with pytest.raises(Exception, match="append-only"):
                store._execute(statement)
        assert store.records()[0].status is Status.FAIL


def test_tampering_in_the_database_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "evidence.db"
    with EvidenceRepository(f"sqlite:///{path}") as store:
        store.append_scan([c1(Status.FAIL), c5(Status.NEEDS_REVIEW)], AT)

    # An attacker with file access drops the guard and rewrites a status.
    with sqlite3.connect(path) as conn:
        conn.execute("DROP TRIGGER evidence_no_update")
        conn.execute("UPDATE evidence SET status = 'PASS' WHERE seq = 1")

    with EvidenceRepository(f"sqlite:///{path}") as store:
        check = store.verify()
    assert (check.valid, check.first_invalid) == (False, 1)


def test_unknown_evidence_url() -> None:
    with pytest.raises(ValueError, match="evidence URL"):
        EvidenceRepository("mysql://localhost/evidence")
