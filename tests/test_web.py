import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from pdp_guardian.checks import ARTICLES, CheckResult, Status
from pdp_guardian.evidence import EvidenceRepository
from pdp_guardian.web import create_app
from pdp_guardian.web.summary import article_slug, find_article, summarize_scan

CUSTOMERS = "cloudsql://kopi-senja/app/customers"
LEADS = "cloudsql://kopi-senja/app/marketing_leads"
FAKE_NIK = "3201010101900001"  # synthetic; must never reach a page
FIRST = datetime(2026, 10, 24, 9, 0, tzinfo=UTC)
SECOND = datetime(2026, 10, 24, 9, 5, tzinfo=UTC)
FORBIDDEN = ("compliant", "patuh", "certified")


def c1(status: Status) -> CheckResult:
    masked = ("3201********0001",) if status is Status.FAIL else ()
    counts = {"scanned": 200, "opaque": 0 if status is Status.FAIL else 200}
    counts["NIK"] = 200 if status is Status.FAIL else 0
    details = {"data_types": "NIK"} if status is Status.FAIL else {}
    return CheckResult("C1", CUSTOMERS, "nik", status, "sampled 200", counts, masked, details)


def scan(c1_status: Status) -> list[CheckResult]:
    return [
        c1(c1_status),
        CheckResult(
            "C2",
            CUSTOMERS,
            "customer_identity:created_at",
            Status.FAIL,
            "aggregate over created_at",
            {"retention_days": 730, "row_count": 200, "rows_before_cutoff": 11, "null_rows": 0},
            details={"category": "customer_identity", "oldest": "2024-02-15T00:00:00+00:00"},
        ),
        CheckResult(
            "C3",
            LEADS,
            "*",
            Status.FAIL,
            "compared types",
            {"found_types": 3, "declared_types": 0, "undeclared_types": 3},
            ("Y*** S***",),
            {"undeclared_types": "EMAIL, NAME, PHONE"},
        ),
    ]


@pytest.fixture
def store_url(tmp_path: Path) -> str:
    return f"sqlite:///{tmp_path / 'evidence.db'}"


def client(url: str, demo: bool = True) -> TestClient:
    return TestClient(create_app(url, demo=demo))


def seeded(url: str, *statuses: Status) -> list:
    with EvidenceRepository(url) as store:
        return [
            store.append_scan(scan(status), scanned_at=at)
            for status, at in zip(statuses, (FIRST, SECOND), strict=False)
        ]


def article_card(html: str, label: str) -> str:
    """The summary card of one article."""
    start = html.index(f'<h2 class="card__label">{label}</h2>')
    return html[start : html.index("</article>", start)]


# Summary


def test_empty_store_explains_how_to_start(tmp_path: Path) -> None:
    path = tmp_path / "missing.db"
    page = client(f"sqlite:///{path}").get("/")
    assert page.status_code == 200
    assert "Belum ada scan" in page.text
    assert not path.exists()  # the dashboard never creates the store


def test_store_with_schema_but_no_scan_is_empty(store_url: str) -> None:
    EvidenceRepository(store_url).close()
    assert "Belum ada scan" in client(store_url).get("/").text


def test_summary_shows_every_article_with_its_status(store_url: str) -> None:
    seeded(store_url, Status.FAIL)
    html = client(store_url).get("/").text
    assert "Gagal cek" in article_card(html, "PP 33/2026 Pasal 123")
    assert "Gagal cek" in article_card(html, "PP 33/2026 Pasal 75 &amp; 86")
    assert "Gagal cek" in article_card(html, "PP 33/2026 Pasal 74")
    # No record for Pasal 56 in this scan: no default pass.
    pasal_56 = article_card(html, "UU PDP Pasal 56")
    assert "Belum dinilai" in pasal_56 and "Lolos cek" not in pasal_56
    assert "Tidak ada record evidence di scan ini." in pasal_56


def test_check_without_records_is_shown_as_not_assessed(store_url: str) -> None:
    seeded(store_url, Status.PASS)
    card = article_card(client(store_url).get("/").text, "PP 33/2026 Pasal 123")
    c4 = card[card.index(">C4<") :]
    assert "Belum dinilai" in c4[: c4.index("</li>")]
    assert "tidak ada sumber yang diperiksa" in c4


def test_rescan_shows_the_flip_and_the_chain_growing(store_url: str) -> None:
    first, second = seeded(store_url, Status.FAIL, Status.PASS)
    html = client(store_url).get("/").text
    assert "Lolos cek" in article_card(html, "PP 33/2026 Pasal 123")
    assert "Gagal cek → Lolos cek" in html
    assert "Regresi" not in html.split('id="perubahan"')[1].split("Riwayat scan")[0]
    assert "Rantai hash valid · 6 record diverifikasi ulang" in html
    assert "EV-000004</a> …" in html and "total rantai 6 record" in html
    assert first.scan_id in html and second.scan_id in html  # history


def test_pass_to_fail_is_flagged_as_regression(store_url: str) -> None:
    seeded(store_url, Status.PASS, Status.FAIL)
    html = client(store_url).get("/").text
    assert "1 regresi" in html
    assert "<strong>Regresi</strong> · \n  Lolos cek → Gagal cek" in html
    assert "row--regression" in html


def test_older_scan_is_viewable_and_marked(store_url: str) -> None:
    first, _ = seeded(store_url, Status.FAIL, Status.PASS)
    html = client(store_url).get(f"/scans/{first.scan_id}").text
    assert "bukan scan terbaru" in html
    assert "Gagal cek" in article_card(html, "PP 33/2026 Pasal 123")
    assert "Ini scan pertama di rantai" in html


def test_demo_banner_and_disclaimer(store_url: str) -> None:
    seeded(store_url, Status.FAIL)
    html = client(store_url).get("/").text
    assert "DEMO – data sintetis" in html
    assert "Temuan untuk ditinjau DPO" in html
    assert "rujukan pasal belum diverifikasi" in html
    assert "DEMO – data sintetis" not in client(store_url, demo=False).get("/").text


# Drill-down


def test_article_page_lists_its_evidence(store_url: str) -> None:
    (appended,) = seeded(store_url, Status.FAIL)
    slug = article_slug(ARTICLES[0])
    page = client(store_url).get(f"/scans/{appended.scan_id}/pasal/{slug}")
    assert page.status_code == 200
    c1_record = appended.records[0]
    assert c1_record.evidence_id in page.text
    assert "3201********0001" in page.text
    assert "Petunjuk perbaikan" in page.text
    assert c1_record.hash[:16] in page.text and c1_record.prev_hash[:16] in page.text
    # Only this article's records.
    assert appended.records[1].evidence_id not in page.text


def test_evidence_page_shows_the_whole_record(store_url: str) -> None:
    _, second = seeded(store_url, Status.FAIL, Status.PASS)
    record = second.records[0]  # C1, FAIL -> PASS
    html = client(store_url).get(f"/evidence/{record.evidence_id}").text
    assert record.method in html
    assert record.hash in html and record.prev_hash in html
    assert "/evidence/EV-000003" in html  # previous record
    assert "✓ Hash record ini cocok dengan isinya." in html
    assert "✓ prev_hash tersambung ke EV-000003." in html
    assert "Nilai / entri diperiksa" in html and ">200<" in html
    assert "Gagal cek → Lolos cek" in html


def test_first_record_links_to_genesis(store_url: str) -> None:
    seeded(store_url, Status.FAIL)
    html = client(store_url).get("/evidence/EV-000001").text
    assert "tersambung ke awal rantai (genesis)" in html


def test_tampered_chain_is_shown_as_invalid(store_url: str, tmp_path: Path) -> None:
    seeded(store_url, Status.FAIL, Status.PASS)
    with sqlite3.connect(tmp_path / "evidence.db") as conn:
        conn.execute("DROP TRIGGER evidence_no_update")
        conn.execute("UPDATE evidence SET status = 'PASS' WHERE seq = 2")

    app = client(store_url)
    html = app.get("/").text
    assert "Rantai hash TIDAK VALID mulai EV-000002" in html
    assert "isi record tidak cocok dengan hash-nya" in html
    assert "Rantai hash valid" not in html
    assert "✗ Hash record ini TIDAK cocok" in app.get("/evidence/EV-000002").text


@pytest.mark.parametrize(
    "path",
    ["/scans/nope", "/scans/nope/pasal/uu-pdp-pasal-56", "/evidence/EV-000099", "/evidence/x"],
)
def test_unknown_pages_are_404(store_url: str, path: str) -> None:
    seeded(store_url, Status.FAIL)
    page = client(store_url).get(path)
    assert page.status_code == 404
    assert "tidak ada di evidence store" in page.text


def test_unknown_article_slug_is_404(store_url: str) -> None:
    (appended,) = seeded(store_url, Status.FAIL)
    assert client(store_url).get(f"/scans/{appended.scan_id}/pasal/pasal-1").status_code == 404


def test_unreachable_store_is_503_without_details() -> None:
    page = client("postgresql://pdpg:secret@127.0.0.1:1/evidence").get("/")
    assert page.status_code == 503
    assert "OperationalError" in page.text
    assert "secret" not in page.text


def test_healthz(store_url: str) -> None:
    assert client(store_url).get("/healthz").json() == {"status": "ok"}


# Content rules on every page


def test_pages_never_claim_a_verdict_or_show_raw_values(store_url: str) -> None:
    first, second = seeded(store_url, Status.FAIL, Status.PASS)
    app = client(store_url)
    paths = ["/", f"/scans/{first.scan_id}"]
    paths += [f"/scans/{second.scan_id}/pasal/{article_slug(a)}" for a in ARTICLES]
    paths += [f"/evidence/{r.evidence_id}" for r in first.records + second.records]
    for path in paths:
        page = app.get(path)
        assert page.status_code == 200, path
        text = re.sub(r"<[^>]+>", " ", page.text).lower()
        for word in FORBIDDEN:
            assert word not in text, (path, word)
        assert FAKE_NIK not in page.text


# View model


def test_article_slugs_are_unique_and_resolvable() -> None:
    slugs = [article_slug(a) for a in ARTICLES]
    assert len(set(slugs)) == len(slugs)
    assert article_slug(ARTICLES[1]) == "pp-33-2026-pasal-75-86"
    assert all(find_article(slug) is article for slug, article in zip(slugs, ARTICLES, strict=True))
    assert find_article("pasal-1") is None


def test_summary_copies_statuses_and_aggregates(store_url: str) -> None:
    (appended,) = seeded(store_url, Status.FAIL)
    summary = summarize_scan(appended.records, appended.diff)
    by_label = {a.article.label: a for a in summary.articles}
    pasal_123 = by_label["PP 33/2026 Pasal 123"]
    assert pasal_123.status is Status.FAIL
    assert [(c.check_id, c.status, c.records) for c in pasal_123.checks] == [
        ("C1", Status.FAIL, 1),
        ("C4", Status.NOT_ASSESSED, 0),
    ]
    assert by_label["UU PDP Pasal 56"].status is Status.NOT_ASSESSED


def test_summary_needs_records() -> None:
    with pytest.raises(ValueError):
        summarize_scan([], [])
