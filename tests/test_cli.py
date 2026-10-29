import os
import re
from pathlib import Path

import psycopg
import pytest

from pdp_guardian.cli import main

FAKE_NIKS = ("3201010101900001", "3201014505920002")

DECLARATION = """\
organization: PT Kopi Senja (demo)
categories:
  - id: customer_identity
    data_types: [NIK, NAME]
    purpose: "KYC for loyalty program"
    retention_days: 730
    locations:
      - resource: cloudsql://kopi-senja/app/customers
        timestamp_column: created_at
"""


@pytest.fixture
def declaration(tmp_path: Path) -> str:
    path = tmp_path / "declaration.yaml"
    path.write_text(DECLARATION, encoding="utf-8")
    return str(path)


def test_gcp_connector_fails_instead_of_pretending(declaration: str, capsys) -> None:
    assert main(["scan", "--declaration", declaration, "--connector", "gcp"]) == 2
    assert "not implemented yet" in capsys.readouterr().err


def test_sqlurl_requires_a_source(declaration: str, monkeypatch, capsys) -> None:
    monkeypatch.delenv("PDP_SOURCE_URL", raising=False)
    assert main(["scan", "--declaration", declaration, "--connector", "sqlurl"]) == 1
    assert "--source-url" in capsys.readouterr().err


def test_invalid_declaration_is_reported(tmp_path: Path, capsys) -> None:
    path = tmp_path / "declaration.yaml"
    path.write_text(DECLARATION.replace("NAME", "SSN"), encoding="utf-8")
    args = ["scan", "--declaration", str(path), "--connector", "sqlurl", "--source-url", "x://"]
    assert main(args) == 1
    assert "unknown data type 'SSN'" in capsys.readouterr().err


def test_report_on_empty_store(tmp_path: Path, capsys) -> None:
    assert main(["report", "--latest", "--evidence-url", f"sqlite:///{tmp_path / 'e.db'}"]) == 1


def test_scan_requires_declaration() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["scan", "--connector", "sqlurl"])
    assert exc.value.code == 2


def test_unknown_connector_is_rejected() -> None:
    with pytest.raises(SystemExit):
        main(["scan", "--declaration", "d.yaml", "--connector", "aws"])


# End to end against a throwaway Postgres database (dropped and recreated).
POSTGRES_URL = os.environ.get("PDP_TEST_POSTGRES_URL")


@pytest.mark.skipif(not POSTGRES_URL, reason="PDP_TEST_POSTGRES_URL not set")
def test_scan_encrypt_rescan_report(declaration: str, tmp_path: Path, capsys) -> None:
    assert POSTGRES_URL
    with psycopg.connect(POSTGRES_URL, autocommit=True) as conn:
        conn.execute("DROP SCHEMA IF EXISTS public, crm CASCADE")
        conn.execute("CREATE SCHEMA public")
        conn.execute("CREATE TABLE customers (nik text, created_at timestamptz)")
        for nik in FAKE_NIKS:
            conn.execute("INSERT INTO customers VALUES (%s, now() - interval '900 days')", (nik,))

    evidence = f"sqlite:///{tmp_path / 'evidence.db'}"
    scan = [
        "scan", "--declaration", declaration, "--connector", "sqlurl",
        "--source-url", POSTGRES_URL, "--source-name", "cloudsql://kopi-senja/app",
        "--location", "asia-southeast2", "--evidence-url", evidence,
    ]  # fmt: skip

    assert main(scan) == 0
    first = capsys.readouterr().out
    assert re.search(r"PP 33/2026 Pasal 123\s+Gagal cek", first)
    assert re.search(r"PP 33/2026 Pasal 75 & 86\s+Gagal cek", first)
    assert "Rantai hash: valid" in first

    with psycopg.connect(POSTGRES_URL, autocommit=True) as conn:
        conn.execute("UPDATE customers SET nik = encode(sha256(nik::bytea), 'hex')")

    assert main(scan) == 0
    second = capsys.readouterr().out
    assert re.search(r"PP 33/2026 Pasal 123\s+Lolos cek", second)
    assert "C1 cloudsql://kopi-senja/app/customers [nik]: FAIL → PASS" in second

    assert main(["report", "--latest", "--evidence-url", evidence]) == 0
    report = capsys.readouterr().out
    assert "kekuatan enkripsinya tidak dinilai" in report
    for output in (first, second, report):
        for nik in FAKE_NIKS:
            assert nik not in output
