import os
from datetime import UTC, date, datetime, timedelta

import psycopg
import pytest

from pdp_guardian.connectors.base import Resource, ResourceKind
from pdp_guardian.connectors.sqlurl import SqlUrlConnector, _text, _utc

FAKE_NIKS = ("3201010101900001", "3201014505920002", "3273012208850003")


def test_default_name_never_contains_credentials() -> None:
    connector = SqlUrlConnector("postgresql://admin:s3cret@db.internal:5432/kopi")
    assert connector.name == "postgres://db.internal/kopi"
    assert "s3cret" not in connector.name and "admin" not in connector.name


def test_name_override_and_mysql_scheme() -> None:
    assert SqlUrlConnector("mysql+pymysql://u:p@h/app", name="cloudsql://x/app/").name == (
        "cloudsql://x/app"
    )


def test_unknown_scheme_is_rejected() -> None:
    with pytest.raises(ValueError, match="source URL"):
        SqlUrlConnector("sqlite:///x.db")


def test_files_and_logs_are_not_supported() -> None:
    connector = SqlUrlConnector("postgresql://localhost/kopi")
    bucket = Resource("gs://b", ResourceKind.BUCKET, None)
    with pytest.raises(ValueError):
        next(iter(connector.scan_files(bucket, 100)))
    with pytest.raises(ValueError):
        next(iter(connector.scan_logs(bucket, datetime.now(UTC), 10)))


def test_bytes_render_as_bytea_hex() -> None:
    assert _text(b"\x01\xab") == "\\x01ab"
    assert _text(320101) == "320101"


def test_timestamps_become_utc() -> None:
    assert _utc(datetime(2024, 1, 1)) == datetime(2024, 1, 1, tzinfo=UTC)
    assert _utc(date(2024, 1, 1)) == datetime(2024, 1, 1, tzinfo=UTC)
    assert _utc(None) is None


# Integration tests: PDP_TEST_POSTGRES_URL must point at a throwaway database as a
# superuser; the fixture drops and recreates its schemas.
POSTGRES_URL = os.environ.get("PDP_TEST_POSTGRES_URL")
needs_postgres = pytest.mark.skipif(not POSTGRES_URL, reason="PDP_TEST_POSTGRES_URL not set")

NOW = datetime(2026, 10, 24, 9, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def source() -> str:
    assert POSTGRES_URL
    statements = [
        "DROP SCHEMA IF EXISTS public, crm CASCADE",
        "CREATE SCHEMA public",
        "CREATE SCHEMA crm",
        "CREATE EXTENSION IF NOT EXISTS pgcrypto",
        """CREATE TABLE customers (
            id serial PRIMARY KEY, nik text, nama text, nik_enc bytea,
            created_at timestamp, active boolean)""",
        "CREATE TABLE crm.leads (no_hp text)",
        "CREATE TABLE empty_table (nik text, created_at timestamptz)",
        "CREATE TABLE big (v text)",
        "INSERT INTO big SELECT 'row ' || g FROM generate_series(1, 20000) g",
        "ANALYZE big",
    ]
    with psycopg.connect(POSTGRES_URL, autocommit=True, options="-c TimeZone=UTC") as conn:
        for statement in statements:
            conn.execute(statement)
        for i, nik in enumerate(FAKE_NIKS):
            conn.execute(
                "INSERT INTO customers (nik, nama, nik_enc, created_at, active)"
                " VALUES (%s, %s, digest(%s, 'sha256'), %s, true)",
                (nik, f"Pelanggan {i}", nik, NOW - timedelta(days=300 * i)),
            )
        conn.execute("INSERT INTO customers (nik) VALUES (NULL)")
        conn.execute("INSERT INTO crm.leads VALUES ('081234567890')")
    return POSTGRES_URL


@needs_postgres
def test_inventory_lists_tables_with_location(source: str) -> None:
    with SqlUrlConnector(source, name="cloudsql://kopi-senja/app", location="asia-southeast2") as c:
        resources = c.inventory()

    assert [r.uri for r in resources] == [
        "cloudsql://kopi-senja/app/crm.leads",
        "cloudsql://kopi-senja/app/big",
        "cloudsql://kopi-senja/app/customers",
        "cloudsql://kopi-senja/app/empty_table",
    ]
    assert {(r.kind, r.location) for r in resources} == {(ResourceKind.TABLE, "asia-southeast2")}


@needs_postgres
def test_scan_tables_samples_non_null_values(source: str) -> None:
    with SqlUrlConnector(source, name="db") as c:
        c.inventory()
        customers = Resource("db/customers", ResourceKind.TABLE, None)
        samples = {s.column: s for s in c.scan_tables(customers, sample=100)}

    # Timestamps and booleans cannot hold the identifiers we detect, so they are skipped.
    assert set(samples) == {"id", "nik", "nama", "nik_enc"}
    assert samples["nik"].values == FAKE_NIKS
    assert samples["nik"].sampled_rows == 4
    assert all(v.startswith("\\x") and len(v) == 66 for v in samples["nik_enc"].values)


@needs_postgres
def test_large_tables_are_sampled(source: str) -> None:
    with SqlUrlConnector(source, name="db") as c:
        c.inventory()
        (sample,) = c.scan_tables(Resource("db/big", ResourceKind.TABLE, None), sample=100)
    assert 0 < len(sample.values) <= 100


@needs_postgres
def test_timestamp_stats(source: str) -> None:
    with SqlUrlConnector(source, name="db") as c:
        c.inventory()
        customers = Resource("db/customers", ResourceKind.TABLE, None)
        stats = c.timestamp_stats(customers, "created_at", NOW - timedelta(days=365))

    assert (stats.row_count, stats.rows_before_cutoff, stats.null_rows) == (4, 1, 1)
    assert stats.oldest == NOW - timedelta(days=600)


@needs_postgres
def test_timestamp_stats_on_empty_table(source: str) -> None:
    with SqlUrlConnector(source, name="db") as c:
        c.inventory()
        empty = Resource("db/empty_table", ResourceKind.TABLE, None)
        stats = c.timestamp_stats(empty, "created_at", NOW)
    assert (stats.row_count, stats.rows_before_cutoff, stats.oldest) == (0, 0, None)


@needs_postgres
def test_unknown_column_or_table_is_rejected(source: str) -> None:
    with SqlUrlConnector(source, name="db") as c:
        c.inventory()
        customers = Resource("db/customers", ResourceKind.TABLE, None)
        with pytest.raises(ValueError, match="no column"):
            c.timestamp_stats(customers, "created_at; DROP TABLE customers", NOW)
        with pytest.raises(ValueError, match="inventory"):
            c.timestamp_stats(Resource("db/nope", ResourceKind.TABLE, None), "x", NOW)


@needs_postgres
def test_session_is_read_only(source: str) -> None:
    with SqlUrlConnector(source, name="db", statement_timeout_ms=1234) as c:
        assert c._query("SHOW default_transaction_read_only") == [("on",)]
        assert c._query("SHOW statement_timeout") == [("1234ms",)]
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
            c._query("CREATE TEMP TABLE scratch (x int)")
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
            c._query("DELETE FROM customers")
