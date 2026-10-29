"""Any Postgres or MySQL database, reached through a connection URL.

Read-only by construction: every session is put in read-only transaction mode
with a statement timeout before the first query, and only SELECTs are issued
(no temp tables). Use a read-only DB user as well; this is defense in depth.

Resource URIs never contain credentials: ``<name>/<table>``, where ``name``
defaults to ``postgres://<host>/<database>`` and can be overridden so that the
same database scanned locally and on GCP yields the same URIs as declaration.yaml.
"""

from collections.abc import Iterator
from datetime import UTC, date, datetime
from typing import Any
from urllib.parse import unquote, urlsplit

import psycopg
import pymysql
from psycopg import sql

from pdp_guardian.connectors.base import (
    ColumnSample,
    FileSample,
    LogSample,
    Resource,
    ResourceKind,
    TimestampStats,
)

DEFAULT_STATEMENT_TIMEOUT_MS = 30_000

# Values longer than this are cut before detection; identifiers are far shorter.
_MAX_VALUE_CHARS = 1024

# Column types that cannot hold the personal data the detectors look for.
_SKIPPED_TYPES = frozenset(
    {
        "boolean",
        "date",
        "datetime",
        "interval",
        "time",
        "time with time zone",
        "time without time zone",
        "timestamp",
        "timestamp with time zone",
        "timestamp without time zone",
        "uuid",
        "year",
    }
)

_PG_SYSTEM_SCHEMAS = ("pg_catalog", "information_schema")


class SqlUrlConnector:
    """Connector for one database. Lists and samples base tables in every user schema."""

    def __init__(
        self,
        url: str,
        *,
        name: str | None = None,
        location: str | None = None,
        statement_timeout_ms: int = DEFAULT_STATEMENT_TIMEOUT_MS,
    ) -> None:
        parts = urlsplit(url)
        scheme = parts.scheme.split("+", 1)[0]
        if scheme in ("postgres", "postgresql"):
            self._dialect = "postgres"
        elif scheme == "mysql":
            self._dialect = "mysql"
        else:
            raise ValueError("source URL must start with postgresql:// or mysql://")
        database = unquote(parts.path.lstrip("/"))
        self.name = (
            name or f"{self._dialect}://{parts.hostname or 'localhost'}/{database}"
        ).rstrip("/")
        self.location = location
        self._url = url
        self._parts = parts
        self._timeout_ms = statement_timeout_ms
        self._conn: Any = None
        self._tables: dict[str, tuple[str, str]] = {}  # uri -> (schema, table)

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "SqlUrlConnector":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def inventory(self) -> list[Resource]:
        if self._dialect == "postgres":
            rows = self._query(
                "SELECT table_schema, table_name FROM information_schema.tables"
                " WHERE table_type = 'BASE TABLE' AND table_schema <> ALL(%s)"
                " AND table_schema NOT LIKE 'pg\\_%%' ORDER BY 1, 2",
                (list(_PG_SYSTEM_SCHEMAS),),
            )
        else:
            rows = self._query(
                "SELECT table_schema, table_name FROM information_schema.tables"
                " WHERE table_type = 'BASE TABLE' AND table_schema = DATABASE() ORDER BY 1, 2"
            )
        self._tables = {self._uri(schema, table): (schema, table) for schema, table in rows}
        return [Resource(uri, ResourceKind.TABLE, self.location) for uri in self._tables]

    def scan_tables(self, resource: Resource, sample: int) -> Iterator[ColumnSample]:
        schema, table = self._table(resource)
        columns = [(c, t) for c, t in self._columns(schema, table) if t not in _SKIPPED_TYPES]
        if not columns:
            return
        names = [c for c, _ in columns]
        rows = self._query(self._sample_sql(schema, table, names, sample), (sample,))
        for i, (column, sql_type) in enumerate(columns):
            values = tuple(_text(row[i]) for row in rows if row[i] is not None)
            yield ColumnSample(resource, column, sql_type, sampled_rows=len(rows), values=values)

    def scan_files(self, resource: Resource, max_bytes: int) -> Iterator[FileSample]:
        raise ValueError(f"{resource.uri}: sqlurl connector has no file resources")

    def scan_logs(self, resource: Resource, since: datetime, limit: int) -> Iterator[LogSample]:
        raise ValueError(f"{resource.uri}: sqlurl connector has no log resources")

    def timestamp_stats(self, resource: Resource, column: str, cutoff: datetime) -> TimestampStats:
        schema, table = self._table(resource)
        if column not in {c for c, _ in self._columns(schema, table)}:
            raise ValueError(f"{resource.uri}: no column {column!r}")
        query = (
            "SELECT count(*), count(*) - count({c}),"
            " coalesce(sum(CASE WHEN {c} < %s THEN 1 ELSE 0 END), 0), min({c}) FROM {t}"
        )
        if self._dialect == "postgres":
            statement: Any = sql.SQL(query).format(
                c=sql.Identifier(column), t=sql.Identifier(schema, table)
            )
        else:
            statement = query.format(c=_mysql_ident(column), t=_mysql_table(schema, table))
        ((row_count, null_rows, before, oldest),) = self._query(statement, (cutoff,))
        return TimestampStats(
            resource=resource,
            column=column,
            row_count=int(row_count),
            rows_before_cutoff=int(before),
            null_rows=int(null_rows),
            oldest=_utc(oldest),
        )

    def _uri(self, schema: str, table: str) -> str:
        default_schema = "public" if self._dialect == "postgres" else schema
        return f"{self.name}/{table if schema == default_schema else f'{schema}.{table}'}"

    def _table(self, resource: Resource) -> tuple[str, str]:
        if resource.kind is not ResourceKind.TABLE:
            raise ValueError(f"{resource.uri}: not a table")
        if not self._tables:
            self.inventory()
        try:
            return self._tables[resource.uri]
        except KeyError:
            raise ValueError(f"{resource.uri}: not in this database's inventory") from None

    def _columns(self, schema: str, table: str) -> list[tuple[str, str]]:
        rows = self._query(
            "SELECT column_name, data_type FROM information_schema.columns"
            " WHERE table_schema = %s AND table_name = %s ORDER BY ordinal_position",
            (schema, table),
        )
        return [(name, str(data_type).lower()) for name, data_type in rows]

    def _sample_sql(self, schema: str, table: str, columns: list[str], sample: int) -> Any:
        # HACKATHON: LIMIT without ORDER BY reads the physically first rows, which is
        # biased but deterministic (the demo needs identical results locally and on
        # Cloud Run). Large Postgres tables use TABLESAMPLE with a fixed seed instead.
        # Production would sample uniformly and report the sampling error.
        if self._dialect == "mysql":
            cols = ", ".join(_mysql_ident(c) for c in columns)
            return f"SELECT {cols} FROM {_mysql_table(schema, table)} LIMIT %s"
        ((estimate,),) = self._query(
            "SELECT greatest(reltuples, 0)::bigint FROM pg_class WHERE oid = to_regclass(%s)",
            (sql.Identifier(schema, table).as_string(self._connection()),),
        )
        statement = sql.SQL("SELECT {cols} FROM {t}").format(
            cols=sql.SQL(", ").join(map(sql.Identifier, columns)), t=sql.Identifier(schema, table)
        )
        if estimate > sample * 10:
            percent = min(100.0, 100.0 * sample * 3 / estimate)
            statement += sql.SQL(" TABLESAMPLE SYSTEM ({p}) REPEATABLE (42)").format(
                p=sql.Literal(percent)
            )
        return statement + sql.SQL(" LIMIT %s")

    def _query(self, statement: Any, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
        with self._connection().cursor() as cursor:
            cursor.execute(statement, params)
            return [tuple(row) for row in cursor.fetchall()]

    def _connection(self) -> Any:
        if self._conn is None:
            self._conn = self._connect()
        return self._conn

    def _connect(self) -> Any:
        if self._dialect == "postgres":
            conninfo = self._url.replace(self._parts.scheme, "postgresql", 1)
            return psycopg.connect(
                conninfo,
                autocommit=True,
                options=(
                    "-c default_transaction_read_only=on"
                    f" -c statement_timeout={self._timeout_ms} -c TimeZone=UTC"
                ),
            )
        # HACKATHON: the MySQL path is not exercised by tests against a live server.
        conn = pymysql.connect(
            host=self._parts.hostname or "localhost",
            port=self._parts.port or 3306,
            user=unquote(self._parts.username or ""),
            password=unquote(self._parts.password or ""),
            database=unquote(self._parts.path.lstrip("/")),
            autocommit=True,
        )
        with conn.cursor() as cursor:
            cursor.execute("SET SESSION TRANSACTION READ ONLY")
            cursor.execute("SET SESSION MAX_EXECUTION_TIME = %s", (self._timeout_ms,))
            cursor.execute("SET time_zone = '+00:00'")
        return conn


def _text(value: Any) -> str:
    if isinstance(value, bytes | bytearray | memoryview):
        text = "\\x" + bytes(value).hex()  # Postgres bytea notation, e.g. pgcrypto output
    else:
        text = str(value)
    return text[:_MAX_VALUE_CHARS]


def _utc(value: datetime | date | None) -> datetime | None:
    # HACKATHON: `timestamp without time zone` is read as UTC (the session runs with
    # TimeZone=UTC). Columns that store local time (e.g. WIB) are off by the UTC offset,
    # which is negligible against retention periods in days. Production would make the
    # column's zone part of the declaration.
    if value is None:
        return None
    if not isinstance(value, datetime):
        return datetime(value.year, value.month, value.day, tzinfo=UTC)
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _mysql_ident(name: str) -> str:
    return "`" + name.replace("`", "``") + "`"


def _mysql_table(schema: str, table: str) -> str:
    return f"{_mysql_ident(schema)}.{_mysql_ident(table)}"
