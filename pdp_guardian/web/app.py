"""Dashboard: per-article summary with drill-down to evidence (FastAPI + Jinja2).

Read-only against the evidence store and nothing else. It renders only what is
stored there (counts, masked samples, hashes), so raw values never reach it.
Every page re-verifies the hash chain before showing anything.
"""

import os
import re
import sqlite3
from importlib.metadata import version
from pathlib import Path

import psycopg
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from pdp_guardian.evidence import (
    DEFAULT_EVIDENCE_URL,
    ChainCheck,
    EvidenceRecord,
    EvidenceRepository,
    verify_chain,
)
from pdp_guardian.narrate import DISCLAIMER, STATUS_LABELS, narrate
from pdp_guardian.web import labels
from pdp_guardian.web.summary import (
    change_for,
    check_record,
    find_article,
    group_by_scan,
    summarize_scan,
)

HERE = Path(__file__).parent
EVIDENCE_ID = re.compile(r"EV-(\d{6,})")


def create_app(evidence_url: str | None = None, demo: bool | None = None) -> FastAPI:
    """``evidence_url`` defaults to env PDP_EVIDENCE_URL; ``demo`` to env PDP_DEMO != "0"."""
    url = evidence_url or os.environ.get("PDP_EVIDENCE_URL", DEFAULT_EVIDENCE_URL)
    # HACKATHON: the synthetic-data banner is on unless PDP_DEMO=0. Production would take
    # the organization and its demo flag from the evidence store instead.
    show_demo = os.environ.get("PDP_DEMO", "1") != "0" if demo is None else demo

    app = FastAPI(title="PDP Guardian", docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=HERE / "templates")
    templates.env.globals |= {
        "DISCLAIMER": DISCLAIMER,
        "STATUS_LABELS": STATUS_LABELS,
        "VERSION": version("pdp-guardian"),
        "change_for": change_for,
        "chain_reason": labels.chain_reason,
        "count_label": labels.count_label,
        "detail_label": labels.detail_label,
        "narrate": narrate,
        "status_class": labels.status_class,
    }
    templates.env.filters["wib"] = labels.wib

    def render(
        request: Request,
        name: str,
        chain: ChainCheck | None,
        status_code: int = 200,
        **context: object,
    ) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            name,
            {"demo": show_demo, "chain": chain, **context},
            status_code=status_code,
        )

    def not_found(request: Request, chain: ChainCheck | None, message: str) -> HTMLResponse:
        return render(request, "error.html", chain, 404, title="Tidak ditemukan", message=message)

    def read_chain(store: EvidenceRepository) -> list[EvidenceRecord]:
        # HACKATHON: reads the whole chain on every page to re-verify it; fine for demo-sized
        # stores. Production would verify incrementally from a stored checkpoint.
        return store.records() if store.initialized() else []

    def scan_page(request: Request, scan_id: str | None) -> HTMLResponse:
        with EvidenceRepository(url, read_only=True) as store:
            chain = read_chain(store)
            scans = group_by_scan(chain)
            diffs = {sid: store.diff(sid) for sid in scans}
        check = verify_chain(chain)
        if not scans:
            return render(request, "empty.html", check)
        scan_id = scan_id or next(reversed(scans))
        if scan_id not in scans:
            return not_found(request, check, f"Scan {scan_id} tidak ada di evidence store.")
        history = [summarize_scan(scans[sid], diffs[sid]) for sid in reversed(scans)]
        current = next(s for s in history if s.scan_id == scan_id)
        return render(
            request,
            "scan.html",
            check,
            scan=current,
            history=history,
            is_latest=current is history[0],
            total=len(chain),
        )

    @app.get("/", response_class=HTMLResponse)
    def latest(request: Request) -> HTMLResponse:
        return scan_page(request, None)

    @app.get("/scans/{scan_id}", response_class=HTMLResponse)
    def scan(request: Request, scan_id: str) -> HTMLResponse:
        return scan_page(request, scan_id)

    @app.get("/scans/{scan_id}/pasal/{slug}", response_class=HTMLResponse)
    def article(request: Request, scan_id: str, slug: str) -> HTMLResponse:
        with EvidenceRepository(url, read_only=True) as store:
            chain = read_chain(store)
            records = [r for r in chain if r.scan_id == scan_id]
            diff = store.diff(scan_id) if records else []
        check = verify_chain(chain)
        found = find_article(slug)
        if not records or found is None:
            return not_found(request, check, "Scan atau pasal ini tidak ada di evidence store.")
        summary = summarize_scan(records, diff)
        return render(
            request,
            "article.html",
            check,
            scan=summary,
            item=next(a for a in summary.articles if a.article == found),
        )

    @app.get("/evidence/{evidence_id}", response_class=HTMLResponse)
    def evidence(request: Request, evidence_id: str) -> HTMLResponse:
        with EvidenceRepository(url, read_only=True) as store:
            chain = read_chain(store)
            by_seq = {r.seq: r for r in chain}
            match = EVIDENCE_ID.fullmatch(evidence_id)
            record = by_seq.get(int(match.group(1))) if match else None
            diff = store.diff(record.scan_id) if record else []
        check = verify_chain(chain)
        if record is None:
            return not_found(request, check, f"Evidence {evidence_id} tidak ada di evidence store.")
        previous, following = by_seq.get(record.seq - 1), by_seq.get(record.seq + 1)
        summary = summarize_scan([r for r in chain if r.scan_id == record.scan_id], diff)
        return render(
            request,
            "evidence.html",
            check,
            record=record,
            previous=previous,
            following=following,
            own=check_record(record, previous),
            scan=summary,
            item=next(a for a in summary.articles if a.article.label == record.article),
            entry=change_for(record, diff),
        )

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.exception_handler(psycopg.Error)
    @app.exception_handler(sqlite3.Error)
    def store_unavailable(request: Request, exc: Exception) -> HTMLResponse:
        # Class name only: driver messages can quote connection details.
        return render(
            request,
            "error.html",
            None,
            503,
            title="Evidence store tidak dapat dibaca",
            message=f"Koneksi atau kueri ke evidence store gagal ({type(exc).__name__}).",
        )

    return app
