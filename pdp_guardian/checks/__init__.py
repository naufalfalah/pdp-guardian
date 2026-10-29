"""Rule engine: pure functions from detector output and the declaration to statuses."""

from pdp_guardian.checks.articles import ARTICLES, CHECK_ARTICLES, CHECK_TITLES, article_for
from pdp_guardian.checks.c1_plaintext import C1_PLAINTEXT_RATIO, check_plaintext
from pdp_guardian.checks.c2_retention import check_retention, retention_cutoff
from pdp_guardian.checks.c3_ropa import check_ropa
from pdp_guardian.checks.c4_logs import C4_WINDOW_DAYS, check_logs, log_window_start
from pdp_guardian.checks.c5_region import check_region
from pdp_guardian.checks.model import WHOLE_RESOURCE, CheckResult, Status, aggregate

__all__ = [
    "ARTICLES",
    "C1_PLAINTEXT_RATIO",
    "C4_WINDOW_DAYS",
    "CHECK_ARTICLES",
    "CHECK_TITLES",
    "WHOLE_RESOURCE",
    "CheckResult",
    "Status",
    "aggregate",
    "article_for",
    "check_logs",
    "check_plaintext",
    "check_region",
    "check_retention",
    "check_ropa",
    "log_window_start",
    "retention_cutoff",
]
