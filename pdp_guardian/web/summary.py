"""What the dashboard shows, built from evidence records. No HTTP, no templates.

Statuses are read from the records and combined with ``checks.aggregate``, the
same way the CLI report does. Nothing here decides or changes a status.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from pdp_guardian.checks import ARTICLES, CHECK_ARTICLES, CHECK_TITLES, Status, aggregate
from pdp_guardian.checks.articles import Article
from pdp_guardian.evidence import GENESIS_HASH, DiffEntry, EvidenceRecord, compute_hash


@dataclass(frozen=True, slots=True)
class CheckSummary:
    check_id: str
    title: str
    status: Status  # NOT_ASSESSED when the scan produced no record for this check
    records: int


@dataclass(frozen=True, slots=True)
class ArticleSummary:
    article: Article
    slug: str
    status: Status
    checks: tuple[CheckSummary, ...]
    records: tuple[EvidenceRecord, ...]
    changes: tuple[DiffEntry, ...]

    @property
    def regressions(self) -> int:
        return sum(entry.regression for entry in self.changes)


@dataclass(frozen=True, slots=True)
class ScanSummary:
    scan_id: str
    scanned_at: datetime
    first_seq: int
    last_seq: int
    articles: tuple[ArticleSummary, ...]
    diff: tuple[DiffEntry, ...]

    @property
    def regressions(self) -> int:
        return sum(entry.regression for entry in self.diff)


@dataclass(frozen=True, slots=True)
class RecordCheck:
    """One record's own link in the chain, recomputed for the evidence page."""

    hash_matches: bool  # sha256(prev_hash + payload) equals the stored hash
    links_to_previous: bool  # prev_hash equals the previous record's hash (or genesis)


def article_slug(article: Article) -> str:
    """URL-safe article id: "PP 33/2026 Pasal 75 & 86" -> "pp-33-2026-pasal-75-86"."""
    return re.sub(r"[^a-z0-9]+", "-", article.label.lower()).strip("-")


def find_article(slug: str) -> Article | None:
    return next((a for a in ARTICLES if article_slug(a) == slug), None)


def summarize_scan(records: Sequence[EvidenceRecord], diff: Sequence[DiffEntry]) -> ScanSummary:
    """Per-article view of one scan. ``records`` must all belong to that scan."""
    if not records:
        raise ValueError("a scan summary needs at least one record")
    articles = []
    for article in ARTICLES:
        in_article = tuple(r for r in records if r.article == article.label)
        checks = tuple(
            CheckSummary(
                check_id=check_id,
                title=CHECK_TITLES[check_id],
                status=aggregate(r.status for r in in_article if r.check_id == check_id),
                records=sum(r.check_id == check_id for r in in_article),
            )
            for check_id, label in CHECK_ARTICLES.items()
            if label == article.label
        )
        articles.append(
            ArticleSummary(
                article=article,
                slug=article_slug(article),
                status=aggregate(r.status for r in in_article),
                checks=checks,
                records=in_article,
                changes=tuple(e for e in diff if e.article == article.label),
            )
        )
    return ScanSummary(
        scan_id=records[0].scan_id,
        scanned_at=records[0].scanned_at,
        first_seq=records[0].seq,
        last_seq=records[-1].seq,
        articles=tuple(articles),
        diff=tuple(diff),
    )


def group_by_scan(chain: Sequence[EvidenceRecord]) -> dict[str, list[EvidenceRecord]]:
    """Records per scan, oldest scan first (dicts keep insertion order)."""
    scans: dict[str, list[EvidenceRecord]] = {}
    for record in chain:
        scans.setdefault(record.scan_id, []).append(record)
    return scans


def check_record(record: EvidenceRecord, previous: EvidenceRecord | None) -> RecordCheck:
    expected_prev = previous.hash if previous else GENESIS_HASH
    return RecordCheck(
        hash_matches=compute_hash(record.prev_hash, record.payload()) == record.hash,
        links_to_previous=record.prev_hash == expected_prev,
    )


def change_for(record: EvidenceRecord, diff: Sequence[DiffEntry]) -> DiffEntry | None:
    """The diff entry for this record's (check, resource, locator), if its status changed."""
    return next(
        (e for e in diff if (e.check_id, e.resource, e.locator) == record.key),
        None,
    )
