from pdp_guardian.checks import Status, check_ropa
from pdp_guardian.connectors.base import Finding, Resource, ResourceKind
from pdp_guardian.declaration import Category, Declaration, Location

CUSTOMERS = Resource("cloudsql://kopi-senja/app/customers", ResourceKind.TABLE, "asia-southeast2")
LEADS = Resource("cloudsql://kopi-senja/app/marketing_leads", ResourceKind.TABLE, "asia-southeast2")
EXPORTS = Resource("gs://kopi-senja-exports", ResourceKind.BUCKET, "us")
LOGS = Resource("logging://kopi-senja/app", ResourceKind.LOG, "asia-southeast2")

DECLARATION = Declaration(
    organization="PT Kopi Senja (demo)",
    categories=(
        Category(
            "customer_identity",
            ("NIK", "NAME"),
            "KYC",
            730,
            (Location(CUSTOMERS.uri, "created_at"),),
        ),
    ),
)


def finding(resource: Resource, data_type: str, hits: int = 3, *masked: str) -> Finding:
    return Finding(resource, "col", data_type, hits, 10, masked)


def by_resource(results):
    return {r.resource: r for r in results}


def test_declared_data_passes() -> None:
    results = check_ropa(DECLARATION, [CUSTOMERS.uri], [finding(CUSTOMERS, "NIK")])
    result = by_resource(results)[CUSTOMERS.uri]
    assert result.status is Status.PASS
    assert result.check_id == "C3"


def test_undeclared_resource_fails() -> None:
    results = check_ropa(
        DECLARATION,
        [CUSTOMERS.uri, LEADS.uri],
        [finding(CUSTOMERS, "NIK"), finding(LEADS, "PHONE", 3, "0812****7890")],
    )
    result = by_resource(results)[LEADS.uri]
    assert result.status is Status.FAIL
    assert result.details["undeclared_types"] == "PHONE"
    assert result.masked_samples == ("0812****7890",)


def test_undeclared_type_at_declared_resource_fails() -> None:
    results = check_ropa(
        DECLARATION, [CUSTOMERS.uri], [finding(CUSTOMERS, "NIK"), finding(CUSTOMERS, "PHONE")]
    )
    result = by_resource(results)[CUSTOMERS.uri]
    assert result.status is Status.FAIL
    assert result.details["undeclared_types"] == "PHONE"


def test_declared_but_not_found_is_a_warning_not_a_fail() -> None:
    results = check_ropa(DECLARATION, [CUSTOMERS.uri], [finding(CUSTOMERS, "NIK")])
    result = by_resource(results)[CUSTOMERS.uri]
    assert result.status is Status.PASS
    assert result.details["declared_not_found"] == "NAME"


def test_declared_resource_that_was_not_scanned_is_not_assessed() -> None:
    results = check_ropa(DECLARATION, [], [])
    assert by_resource(results)[CUSTOMERS.uri].status is Status.NOT_ASSESSED


def test_zero_hit_findings_are_not_discoveries() -> None:
    results = check_ropa(DECLARATION, [CUSTOMERS.uri, LEADS.uri], [finding(LEADS, "PHONE", 0)])
    assert LEADS.uri not in by_resource(results)


def test_buckets_count_and_logs_do_not() -> None:
    results = check_ropa(
        DECLARATION,
        [CUSTOMERS.uri, EXPORTS.uri, LOGS.uri],
        [finding(EXPORTS, "NIK"), finding(LOGS, "NIK")],
    )
    resources = by_resource(results)
    assert resources[EXPORTS.uri].status is Status.FAIL
    assert LOGS.uri not in resources
