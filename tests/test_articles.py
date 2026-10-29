import pytest

from pdp_guardian.checks import (
    ARTICLES,
    CHECK_ARTICLES,
    CHECK_TITLES,
    Status,
    aggregate,
    article_for,
)

P, F, R, N = Status.PASS, Status.FAIL, Status.NEEDS_REVIEW, Status.NOT_ASSESSED


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        ([P, P], P),
        ([P, F, R, N], F),
        ([P, R, N], R),
        ([P, N], N),
        ([N], N),
        ([], N),  # no evidence is never a pass
    ],
)
def test_aggregate(statuses: list[Status], expected: Status) -> None:
    assert aggregate(statuses) is expected


def test_every_check_maps_to_a_listed_article() -> None:
    labels = {article.label for article in ARTICLES}
    assert set(CHECK_ARTICLES) == set(CHECK_TITLES) == {"C1", "C2", "C3", "C4", "C5"}
    assert set(CHECK_ARTICLES.values()) == labels


def test_c1_and_c4_share_pasal_123() -> None:
    assert article_for("C1") is article_for("C4")
    assert article_for("C1").label == "PP 33/2026 Pasal 123"


def test_references_are_unverified_until_checked_against_official_text() -> None:
    # Flip `verified` in articles.py only after reading the official PP 33/2026 text.
    assert not any(article.verified for article in ARTICLES)
