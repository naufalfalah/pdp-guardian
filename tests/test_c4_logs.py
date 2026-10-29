from datetime import UTC, datetime, timedelta

from pdp_guardian.checks import C4_WINDOW_DAYS, Status, check_logs, log_window_start
from pdp_guardian.connectors.base import LogSample, Resource, ResourceKind
from pdp_guardian.detect import scan_logs

NOW = datetime(2026, 10, 24, 9, 0, tzinfo=UTC)
SINCE = log_window_start(NOW)
LOG = Resource("logging://kopi-senja/app", ResourceKind.LOG, "asia-southeast2")
FAKE_NIK = "3201010101900001"


def logs(*texts: str):
    return scan_logs(LOG, [LogSample(LOG, f"e{i}", NOW, t) for i, t in enumerate(texts)])


def test_default_window_is_seven_days() -> None:
    assert C4_WINDOW_DAYS == 7
    assert NOW - timedelta(days=7) == SINCE


def test_personal_data_in_logs_fails() -> None:
    result = check_logs(logs("GET /menu 200", f"registered nik={FAKE_NIK}"), SINCE, limit=1000)

    assert result.status is Status.FAIL
    assert (result.check_id, result.resource, result.locator) == ("C4", LOG.uri, "payload")
    assert result.counts == {"scanned": 2, "limit": 1000, "NIK": 1}
    assert result.masked_samples == ("3201********0001",)
    assert FAKE_NIK not in repr(result)


def test_clean_logs_pass() -> None:
    assert check_logs(logs("GET /menu 200", "POST /order 201"), SINCE, 1000).status is Status.PASS


def test_no_entries_in_window_is_not_assessed() -> None:
    assert check_logs(logs(), SINCE, 1000).status is Status.NOT_ASSESSED


def test_reaching_the_limit_is_noted() -> None:
    result = check_logs(logs("GET / 200", "GET / 200"), SINCE, limit=2)
    assert result.status is Status.PASS
    assert "limit reached" in result.details["note"]
