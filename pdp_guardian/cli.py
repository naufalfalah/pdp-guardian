"""Command-line entry point: `pdp-guardian scan`, `pdp-guardian report`, `pdp-guardian web`.

Output is Bahasa Indonesia (it is UI copy) and only ever contains counts and
masked samples, never raw values.
"""

import argparse
import os
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from importlib.metadata import version

import psycopg

from pdp_guardian.checks import ARTICLES, C1_PLAINTEXT_RATIO, aggregate
from pdp_guardian.connectors.sqlurl import SqlUrlConnector
from pdp_guardian.declaration import DeclarationError, load_declaration
from pdp_guardian.engine import ScanConfig, run_checks
from pdp_guardian.evidence import (
    DEFAULT_EVIDENCE_URL,
    DiffEntry,
    EvidenceRecord,
    EvidenceRepository,
)
from pdp_guardian.narrate import DISCLAIMER, STATUS_LABELS, narrate


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pdp-guardian",
        description="Per-article UU PDP / PP 33/2026 evidence from databases, storage, and logs.",
    )
    parser.add_argument("--version", action="version", version=version("pdp-guardian"))
    commands = parser.add_subparsers(dest="command", required=True)

    evidence_url = {
        "default": os.environ.get("PDP_EVIDENCE_URL", DEFAULT_EVIDENCE_URL),
        "help": "evidence store: sqlite:///path.db or postgresql://... (env PDP_EVIDENCE_URL)",
    }

    scan = commands.add_parser("scan", help="scan sources and append evidence records")
    scan.add_argument("--declaration", required=True, help="path to declaration.yaml")
    scan.add_argument("--connector", required=True, choices=["gcp", "sqlurl"])
    scan.add_argument(
        "--source-url",
        default=os.environ.get("PDP_SOURCE_URL"),
        help="sqlurl: postgresql://... or mysql://... of a read-only user (env PDP_SOURCE_URL)",
    )
    scan.add_argument(
        "--source-name",
        help="sqlurl: URI prefix for resources, to match declaration.yaml "
        "(e.g. cloudsql://kopi-senja/app)",
    )
    scan.add_argument("--location", help="sqlurl: region of the database, e.g. asia-southeast2")
    scan.add_argument("--sample-rows", type=int, default=ScanConfig().sample_rows)
    scan.add_argument("--evidence-url", **evidence_url)

    report = commands.add_parser("report", help="print evidence from a scan")
    which = report.add_mutually_exclusive_group()
    which.add_argument("--latest", action="store_true", help="the most recent scan (default)")
    which.add_argument("--scan", metavar="SCAN_ID", help="a specific scan")
    report.add_argument("--evidence-url", **evidence_url)

    web = commands.add_parser("web", help="serve the dashboard (read-only on the evidence store)")
    web.add_argument("--evidence-url", **evidence_url)
    web.add_argument("--host", default="127.0.0.1", help="use 0.0.0.0 in a container")
    web.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            return _scan(args)
        if args.command == "web":
            return _web(args)
        return _report(args)
    except (DeclarationError, ValueError) as exc:
        print(f"pdp-guardian {args.command}: {exc}", file=sys.stderr)
        return 1
    except psycopg.Error as exc:
        print(
            f"pdp-guardian {args.command}: database error ({type(exc).__name__})", file=sys.stderr
        )
        return 1


def _scan(args: argparse.Namespace) -> int:
    if args.connector == "gcp":
        # Fail loudly so nothing looks like a scan result.
        print("pdp-guardian scan: connector gcp is not implemented yet", file=sys.stderr)
        return 2
    if not args.source_url:
        raise ValueError("--source-url (or PDP_SOURCE_URL) is required for --connector sqlurl")

    declaration = load_declaration(args.declaration)
    config = ScanConfig(
        sample_rows=args.sample_rows,
        plaintext_ratio=float(os.environ.get("C1_PLAINTEXT_RATIO", C1_PLAINTEXT_RATIO)),
    )
    now = datetime.now(UTC)
    with SqlUrlConnector(args.source_url, name=args.source_name, location=args.location) as source:
        results = run_checks(source, declaration, now, config)

    with EvidenceRepository(args.evidence_url) as store:
        appended = store.append_scan(results, scanned_at=now)
        chain = store.verify()

    records = appended.records
    print(f"Scan {appended.scan_id} — {declaration.organization}")
    if records:
        print(
            f"{len(records)} record evidence: {records[0].evidence_id} … {records[-1].evidence_id}"
        )
    _print_chain(chain.valid, chain.checked, chain.first_invalid)
    print()
    _print_articles(records)
    print()
    _print_diff(appended.diff)
    print(f"\n{DISCLAIMER}")
    return 0


def _report(args: argparse.Namespace) -> int:
    with EvidenceRepository(args.evidence_url) as store:
        scan_id = args.scan or store.latest_scan_id()
        if scan_id is None:
            print("Belum ada scan di evidence store.", file=sys.stderr)
            return 1
        records = store.records(scan_id)
        if not records:
            raise ValueError(f"no scan {scan_id!r} in the evidence store")
        diff = store.diff(scan_id)
        chain = store.verify()

    print(f"Scan {scan_id} — {records[0].scanned_at:%Y-%m-%d %H:%M:%S} UTC")
    _print_chain(chain.valid, chain.checked, chain.first_invalid)
    print()
    _print_articles(records)
    for article in ARTICLES:
        in_article = [r for r in records if r.article == article.label]
        if not in_article:
            continue
        print(f"\n== {article.label} — {article.title}")
        for record in in_article:
            _print_record(record)
    print()
    _print_diff(diff)
    print(f"\n{DISCLAIMER}")
    return 0


def _web(args: argparse.Namespace) -> int:
    import uvicorn  # only the dashboard needs the server

    from pdp_guardian.web import create_app

    uvicorn.run(create_app(args.evidence_url), host=args.host, port=args.port)
    return 0


def _print_chain(valid: bool, checked: int, first_invalid: int | None) -> None:
    if valid:
        print(f"Rantai hash: valid ({checked} record)")
    else:
        print(f"Rantai hash: TIDAK VALID mulai record seq {first_invalid}")


def _print_articles(records: Sequence[EvidenceRecord]) -> None:
    print("Ringkasan per pasal:")
    for article in ARTICLES:
        statuses = [r.status for r in records if r.article == article.label]
        label = STATUS_LABELS[aggregate(statuses)]
        verify = "" if article.verified else "  [rujukan pasal belum diverifikasi]"
        print(f"  {article.label:<26} {label:<15} ({len(statuses)} record){verify}")


def _print_record(record: EvidenceRecord) -> None:
    story = narrate(record)
    print(f"- {record.evidence_id} {record.check_id} {STATUS_LABELS[record.status]}: {story.title}")
    print(f"  {story.summary}")
    if story.remediation:
        print(f"  Perbaikan: {story.remediation}")
    if record.masked_samples:
        print(f"  Contoh (disamarkan): {', '.join(record.masked_samples)}")
    print(f"  Metode: {record.method}")
    print(f"  hash {record.hash[:16]}… prev {record.prev_hash[:16]}…")


def _print_diff(diff: Sequence[DiffEntry]) -> None:
    if not diff:
        print("Perubahan dari scan sebelumnya: tidak ada (atau ini scan pertama).")
        return
    print("Perubahan dari scan sebelumnya:")
    for entry in diff:
        before = entry.before.value if entry.before else "-"
        after = entry.after.value if entry.after else "-"
        flag = "  ⚠ REGRESI" if entry.regression else ""
        where = entry.resource if entry.locator == "*" else f"{entry.resource} [{entry.locator}]"
        print(f"  {entry.check_id} {where}: {before} → {after}{flag}")


if __name__ == "__main__":
    sys.exit(main())
