import hashlib
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

from pdp_guardian.checks import Status
from pdp_guardian.connectors.base import (
    ColumnSample,
    FileSample,
    LogSample,
    Resource,
    ResourceKind,
    TimestampStats,
)
from pdp_guardian.declaration import Category, Declaration, Location
from pdp_guardian.engine import ScanConfig, run_checks

NOW = datetime(2026, 10, 24, 9, 0, tzinfo=UTC)
FAKE_NIKS = ("3201010101900001", "3201014505920002", "3273012208850003")

CUSTOMERS = Resource("cloudsql://kopi-senja/app/customers", ResourceKind.TABLE, "asia-southeast2")
LEADS = Resource("cloudsql://kopi-senja/app/marketing_leads", ResourceKind.TABLE, "asia-southeast2")
EXPORTS = Resource("gs://kopi-senja-exports", ResourceKind.BUCKET, "us")
LOGS = Resource("logging://kopi-senja/app", ResourceKind.LOG, "asia-southeast2")

DECLARATION = Declaration(
    organization="PT Kopi Senja (demo)",
    categories=(
        Category(
            "customer_identity",
            ("NIK", "NAME", "PHONE"),
            "KYC",
            730,
            (Location(CUSTOMERS.uri, "created_at"), Location(EXPORTS.uri)),
        ),
    ),
)


class FakeConnector:
    """In-memory Kopi Senja: plaintext (or encrypted) NIKs, an undeclared table, an export."""

    def __init__(self, encrypted: bool = False, log_text: str = "GET /menu 200") -> None:
        self.encrypted = encrypted
        self.log_text = log_text
        self.failing: set[str] = set()

    def inventory(self) -> list[Resource]:
        return [CUSTOMERS, LEADS, EXPORTS, LOGS]

    def scan_tables(self, resource: Resource, sample: int) -> Iterator[ColumnSample]:
        if resource.uri in self.failing:
            raise TimeoutError("statement timeout")
        if resource == CUSTOMERS:
            niks = FAKE_NIKS
            if self.encrypted:
                niks = tuple("\\x" + hashlib.sha256(n.encode()).hexdigest() for n in niks)
            yield ColumnSample(resource, "nik", "text", 3, niks)
            yield ColumnSample(resource, "status", "text", 3, ("aktif",) * 3)
        else:
            yield ColumnSample(resource, "no_hp", "text", 2, ("081234567890", "081298765432"))

    def scan_files(self, resource: Resource, max_bytes: int) -> Iterator[FileSample]:
        text = "id,nik\n1," + FAKE_NIKS[0] + "\n"
        yield FileSample(resource, "export.csv", "text/csv", len(text), False, text)

    def scan_logs(self, resource: Resource, since: datetime, limit: int) -> Iterator[LogSample]:
        yield LogSample(resource, "e1", NOW - timedelta(hours=1), self.log_text)

    def timestamp_stats(self, resource: Resource, column: str, cutoff: datetime) -> TimestampStats:
        return TimestampStats(resource, column, 3, 1, 0, NOW - timedelta(days=900))


def by_check(results) -> dict[tuple[str, str, str], Status]:
    return {(r.check_id, r.resource, r.locator): r.status for r in results}


def test_kopi_senja_scan() -> None:
    results = run_checks(FakeConnector(), DECLARATION, NOW)

    assert by_check(results) == {
        ("C1", CUSTOMERS.uri, "nik"): Status.FAIL,
        ("C2", CUSTOMERS.uri, "customer_identity:created_at"): Status.FAIL,
        ("C2", EXPORTS.uri, "customer_identity:*"): Status.NOT_ASSESSED,
        ("C3", CUSTOMERS.uri, "*"): Status.PASS,
        ("C3", LEADS.uri, "*"): Status.FAIL,
        ("C3", EXPORTS.uri, "*"): Status.PASS,
        ("C4", LOGS.uri, "payload"): Status.PASS,
        ("C5", CUSTOMERS.uri, "*"): Status.PASS,
        ("C5", LEADS.uri, "*"): Status.PASS,
        ("C5", EXPORTS.uri, "*"): Status.NEEDS_REVIEW,
    }


def test_encrypting_nik_flips_c1_only() -> None:
    before = by_check(run_checks(FakeConnector(), DECLARATION, NOW))
    after = by_check(run_checks(FakeConnector(encrypted=True), DECLARATION, NOW))

    changed = {key for key in before if before[key] != after.get(key)}
    assert changed == {("C1", CUSTOMERS.uri, "nik"), ("C5", CUSTOMERS.uri, "*")}
    assert after[("C1", CUSTOMERS.uri, "nik")] is Status.PASS
    # Encrypted: no personal data detected in the table any more, so C5 no longer applies.
    assert ("C5", CUSTOMERS.uri, "*") not in after


def test_personal_data_in_logs_fails_c4_and_triggers_c5() -> None:
    results = by_check(run_checks(FakeConnector(log_text="nik=" + FAKE_NIKS[0]), DECLARATION, NOW))
    assert results[("C4", LOGS.uri, "payload")] is Status.FAIL
    assert results[("C5", LOGS.uri, "*")] is Status.PASS
    assert ("C3", LOGS.uri, "*") not in results


def test_failing_resource_is_not_assessed_and_names_only_the_error_class() -> None:
    connector = FakeConnector()
    connector.failing.add(CUSTOMERS.uri)

    results = run_checks(connector, DECLARATION, NOW)

    failed = [r for r in results if r.resource == CUSTOMERS.uri and r.check_id in ("C1", "C3")]
    assert {(r.check_id, r.status) for r in failed} == {
        ("C1", Status.NOT_ASSESSED),
        ("C3", Status.NOT_ASSESSED),
    }
    assert failed[0].details == {"error": "TimeoutError"}
    assert "statement timeout" not in repr(results)


def test_no_raw_value_reaches_any_result() -> None:
    results = run_checks(FakeConnector(log_text="nik=" + FAKE_NIKS[0]), DECLARATION, NOW)
    dumped = repr(results)
    for raw in (*FAKE_NIKS, "081234567890", "081298765432"):
        assert raw not in dumped


def test_config_is_passed_to_connector_and_checks() -> None:
    results = run_checks(FakeConnector(), DECLARATION, NOW, ScanConfig(log_window_days=1))
    (c4,) = [r for r in results if r.check_id == "C4"]
    assert c4.details["since"] == (NOW - timedelta(days=1)).isoformat()
