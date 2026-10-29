"""One scan: connector -> inventory -> detection -> checks C1-C5.

Platform-agnostic: it only talks to the ``Connector`` protocol. Raw values live
inside the ``for`` loops below and are dropped as soon as ``detect`` has turned
them into counts and masked samples.

A failing connector call never aborts the scan and never becomes a PASS: it
yields NOT_ASSESSED, recording only the exception's class name, because driver
error messages can quote values.
"""

from dataclasses import dataclass
from datetime import datetime

from pdp_guardian.checks import (
    C1_PLAINTEXT_RATIO,
    C4_WINDOW_DAYS,
    WHOLE_RESOURCE,
    CheckResult,
    Status,
    c1_plaintext,
    c4_logs,
    check_logs,
    check_plaintext,
    check_region,
    check_retention,
    check_ropa,
    log_window_start,
    retention_cutoff,
)
from pdp_guardian.connectors.base import Connector, Finding, Resource, ResourceKind
from pdp_guardian.declaration import Declaration
from pdp_guardian.detect import LOG_LOCATOR, scan_column, scan_file, scan_logs


@dataclass(frozen=True, slots=True)
class ScanConfig:
    sample_rows: int = 1000
    max_bytes: int = 1_000_000
    log_limit: int = 1000
    log_window_days: int = C4_WINDOW_DAYS
    plaintext_ratio: float = C1_PLAINTEXT_RATIO


def run_checks(
    connector: Connector,
    declaration: Declaration,
    now: datetime,
    config: ScanConfig | None = None,
) -> list[CheckResult]:
    config = config or ScanConfig()
    results: list[CheckResult] = []
    findings: list[Finding] = []
    scanned: set[str] = set()

    inventory = connector.inventory()
    for resource in inventory:
        try:
            if resource.kind is ResourceKind.TABLE:
                resource_results, resource_findings = _scan_table(connector, resource, config)
            elif resource.kind is ResourceKind.BUCKET:
                resource_results, resource_findings = _scan_bucket(connector, resource, config)
            else:
                resource_results, resource_findings = _scan_log(connector, resource, now, config)
        except Exception as exc:
            results.append(_scan_failed(resource, exc))
            continue
        scanned.add(resource.uri)
        results += resource_results
        findings += resource_findings

    results += _retention(connector, declaration, inventory, now)
    results += check_ropa(declaration, scanned, findings)

    found_types: dict[Resource, set[str]] = {}
    for finding in findings:
        if finding.hits > 0:
            found_types.setdefault(finding.resource, set()).add(finding.data_type)
    for resource, types in found_types.items():
        region = check_region(resource, types)
        if region is not None:
            results.append(region)

    return sorted(results, key=lambda r: (r.check_id, r.resource, r.locator))


def _scan_table(
    connector: Connector, resource: Resource, config: ScanConfig
) -> tuple[list[CheckResult], list[Finding]]:
    results, findings = [], []
    for sample in connector.scan_tables(resource, config.sample_rows):
        scan = scan_column(sample)
        findings += scan.findings
        result = check_plaintext(scan, config.plaintext_ratio)
        if result is not None:
            results.append(result)
    return results, findings


def _scan_bucket(
    connector: Connector, resource: Resource, config: ScanConfig
) -> tuple[list[CheckResult], list[Finding]]:
    findings: list[Finding] = []
    for sample in connector.scan_files(resource, config.max_bytes):
        findings += scan_file(sample).findings
    return [], findings


def _scan_log(
    connector: Connector, resource: Resource, now: datetime, config: ScanConfig
) -> tuple[list[CheckResult], list[Finding]]:
    since = log_window_start(now, config.log_window_days)
    scan = scan_logs(resource, connector.scan_logs(resource, since, config.log_limit))
    return [check_logs(scan, since, config.log_limit)], list(scan.findings)


def _retention(
    connector: Connector, declaration: Declaration, inventory: list[Resource], now: datetime
) -> list[CheckResult]:
    by_uri = {resource.uri: resource for resource in inventory}
    results = []
    for category in declaration.categories:
        for location in category.locations:
            resource = by_uri.get(location.resource)
            if location.timestamp_column is None:
                results.append(check_retention(category, location, None, now))
            elif resource is None:
                results.append(
                    check_retention(
                        category, location, None, now, unavailable="resource not in inventory"
                    )
                )
            else:
                try:
                    stats = connector.timestamp_stats(
                        resource, location.timestamp_column, retention_cutoff(category, now)
                    )
                except Exception as exc:
                    results.append(
                        check_retention(
                            category, location, None, now, unavailable=type(exc).__name__
                        )
                    )
                else:
                    results.append(check_retention(category, location, stats, now))
    return results


def _scan_failed(resource: Resource, exc: Exception) -> CheckResult:
    """NOT_ASSESSED for the check a resource of this kind would have produced."""
    if resource.kind is ResourceKind.LOG:
        check_id, locator = c4_logs.CHECK_ID, LOG_LOCATOR
    else:
        # Buckets produce no per-resource check of their own; C3 and C5 then treat the
        # resource as not scanned. C1 records the failure so it is visible as evidence.
        check_id, locator = c1_plaintext.CHECK_ID, WHOLE_RESOURCE
    return CheckResult(
        check_id=check_id,
        resource=resource.uri,
        locator=locator,
        status=Status.NOT_ASSESSED,
        method=f"{resource.kind} scan failed; partial results were discarded",
        details={"error": type(exc).__name__},
    )
