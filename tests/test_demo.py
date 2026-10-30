"""The demo scenario itself: seed -> scan -> encrypt nik -> re-scan.

These tests pin what the audience sees, so a change elsewhere cannot silently
break the showcase. The Postgres ones need PDP_TEST_POSTGRES_URL (a throwaway
database: its public schema is dropped and reseeded).
"""

import os
from datetime import UTC, datetime
from pathlib import Path

import psycopg
import pytest
from fastapi.testclient import TestClient
from lokal import is_valid_nik

from pdp_guardian.checks import ARTICLES, Status, aggregate, article_for
from pdp_guardian.connectors.sqlurl import SqlUrlConnector
from pdp_guardian.declaration import load_declaration
from pdp_guardian.engine import run_checks
from pdp_guardian.evidence import EvidenceRepository
from pdp_guardian.web import create_app
from pdp_guardian.web.summary import article_slug

DEMO = Path(__file__).resolve().parent.parent / "demo"
POSTGRES_URL = os.environ.get("PDP_TEST_POSTGRES_URL")
needs_postgres = pytest.mark.skipif(not POSTGRES_URL, reason="PDP_TEST_POSTGRES_URL not set")

CUSTOMERS = "cloudsql://kopi-senja/app/customers"
LEADS = "cloudsql://kopi-senja/app/marketing_leads"


def test_declaration_loads_and_omits_marketing_leads() -> None:
    declaration = load_declaration(DEMO / "declaration.yaml")
    assert declaration.organization == "PT Kopi Senja (demo)"
    assert set(declaration.declared_types()) == {CUSTOMERS}


def test_reset_script_is_executable() -> None:
    assert os.access(DEMO / "reset.sh", os.X_OK)


def seed() -> None:
    assert POSTGRES_URL
    with psycopg.connect(POSTGRES_URL, autocommit=True) as conn:
        conn.execute("DROP SCHEMA IF EXISTS public, crm CASCADE")
        conn.execute("CREATE SCHEMA public")
        conn.execute((DEMO / "seed.sql").read_text(encoding="utf-8"))


def migrate() -> None:
    assert POSTGRES_URL
    with psycopg.connect(POSTGRES_URL, autocommit=True) as conn:
        conn.execute((DEMO / "migrate_encrypt_nik.sql").read_text(encoding="utf-8"))


def scan():
    assert POSTGRES_URL
    declaration = load_declaration(DEMO / "declaration.yaml")
    with SqlUrlConnector(
        POSTGRES_URL, name="cloudsql://kopi-senja/app", location="asia-southeast2"
    ) as source:
        return run_checks(source, declaration, datetime.now(UTC))


def articles(results) -> dict[str, Status]:
    return {
        article.label: aggregate(
            r.status for r in results if article_for(r.check_id).label == article.label
        )
        for article in ARTICLES
    }


@needs_postgres
def test_seeded_niks_are_synthetic_but_structurally_valid() -> None:
    seed()
    with psycopg.connect(POSTGRES_URL) as conn:
        niks = [row[0] for row in conn.execute("SELECT nik FROM customers")]
    assert len(niks) == len(set(niks)) == 200
    assert all(is_valid_nik(nik) for nik in niks)


@needs_postgres
def test_first_scan_fails_three_articles() -> None:
    seed()
    results = scan()
    by_key = {(r.check_id, r.resource, r.locator): r for r in results}

    assert articles(results) == {
        "PP 33/2026 Pasal 123": Status.FAIL,
        "PP 33/2026 Pasal 75 & 86": Status.FAIL,
        "PP 33/2026 Pasal 74": Status.FAIL,
        "UU PDP Pasal 56": Status.PASS,
    }
    c1 = by_key[("C1", CUSTOMERS, "nik")]
    assert c1.counts["NIK"] == c1.counts["scanned"] == 200
    c2 = by_key[("C2", CUSTOMERS, "customer_identity:created_at")]
    assert (c2.counts["rows_before_cutoff"], c2.counts["row_count"]) == (11, 200)
    c3 = by_key[("C3", LEADS, "*")]
    assert c3.status is Status.FAIL
    assert c3.details["undeclared_types"] == "EMAIL, NAME, PHONE"
    # Everything the customer table holds is declared, and nothing is missing.
    assert by_key[("C3", CUSTOMERS, "*")].status is Status.PASS
    assert "declared_not_found" not in by_key[("C3", CUSTOMERS, "*")].details
    # orders holds no personal data, so it produces no record at all.
    assert not [r for r in results if r.resource.endswith("/orders")]


@needs_postgres
def test_encrypting_nik_flips_only_pasal_123() -> None:
    seed()
    before = scan()
    migrate()
    after = scan()

    assert articles(after) == articles(before) | {"PP 33/2026 Pasal 123": Status.PASS}
    (c1,) = [r for r in after if r.check_id == "C1"]
    assert c1.details["note"] == "encryption strength not assessed"
    assert c1.counts["opaque"] == 200


@needs_postgres
def test_migration_refuses_to_run_twice() -> None:
    seed()
    migrate()
    with pytest.raises(psycopg.errors.RaiseException, match="reset.sh"):
        migrate()


@needs_postgres
def test_dashboard_shows_the_demo_without_raw_values(tmp_path: Path) -> None:
    seed()
    with psycopg.connect(POSTGRES_URL) as conn:
        raw = [
            value
            for sql in (
                "SELECT nik FROM customers",
                "SELECT nama FROM customers",
                "SELECT no_hp FROM customers",
                "SELECT alamat FROM customers",
                "SELECT nama FROM marketing_leads",
                "SELECT no_hp FROM marketing_leads",
                "SELECT email FROM marketing_leads",
            )
            for (value,) in conn.execute(sql)
        ]
    url = f"sqlite:///{tmp_path / 'evidence.db'}"
    with EvidenceRepository(url) as store:
        first = store.append_scan(scan())
        migrate()
        second = store.append_scan(scan())

    app = TestClient(create_app(url, demo=True))
    paths = ["/", f"/scans/{first.scan_id}"]
    paths += [f"/scans/{second.scan_id}/pasal/{article_slug(a)}" for a in ARTICLES]
    paths += [f"/evidence/{r.evidence_id}" for r in first.records + second.records]
    pages = [app.get(path).text for path in paths]

    assert "C1" in pages[0] and "Gagal cek → Lolos cek" in pages[0]
    for html in pages:
        for value in raw:
            assert value not in html
