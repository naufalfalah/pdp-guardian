"""declaration.yaml: the DPO's records of processing and retention periods.

The file is the contract between the DPO and the rule engine, so it is validated
strictly: unknown keys, unknown data types, and malformed values all raise
``DeclarationError`` naming the offending path. Nothing is silently ignored.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from pdp_guardian.detect import DATA_TYPES


class DeclarationError(ValueError):
    """The declaration file is invalid. The message names the offending path."""


@dataclass(frozen=True, slots=True)
class Location:
    resource: str  # must match a connector's Resource.uri
    timestamp_column: str | None = None  # needed by C2; None makes C2 NOT_ASSESSED


@dataclass(frozen=True, slots=True)
class Category:
    id: str
    data_types: tuple[str, ...]
    purpose: str
    retention_days: int
    locations: tuple[Location, ...]


@dataclass(frozen=True, slots=True)
class Declaration:
    organization: str
    categories: tuple[Category, ...]

    def declared_types(self) -> dict[str, frozenset[str]]:
        """Data types declared per resource URI, across all categories."""
        declared: dict[str, set[str]] = {}
        for category in self.categories:
            for location in category.locations:
                declared.setdefault(location.resource, set()).update(category.data_types)
        return {uri: frozenset(types) for uri, types in declared.items()}


def load_declaration(path: str | Path) -> Declaration:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise DeclarationError(f"{path}: cannot read ({exc.strerror})") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise DeclarationError(f"{path}: not valid YAML ({exc})") from exc
    return parse_declaration(data)


def parse_declaration(data: Any) -> Declaration:
    root = _mapping(data, "declaration", required={"organization", "categories"})
    categories = _list(root["categories"], "categories")
    if not categories:
        raise DeclarationError("categories: must list at least one category")

    parsed = tuple(_category(item, f"categories[{i}]") for i, item in enumerate(categories))
    seen: set[str] = set()
    for i, category in enumerate(parsed):
        if category.id in seen:
            raise DeclarationError(f"categories[{i}].id: duplicate category id {category.id!r}")
        seen.add(category.id)

    return Declaration(
        organization=_string(root["organization"], "organization"),
        categories=parsed,
    )


def _category(data: Any, path: str) -> Category:
    fields = {"id", "data_types", "purpose", "retention_days", "locations"}
    item = _mapping(data, path, required=fields)

    data_types = _list(item["data_types"], f"{path}.data_types")
    if not data_types:
        raise DeclarationError(f"{path}.data_types: must list at least one data type")
    for i, data_type in enumerate(data_types):
        if data_type not in DATA_TYPES:
            raise DeclarationError(
                f"{path}.data_types[{i}]: unknown data type {data_type!r}; "
                f"expected one of {', '.join(DATA_TYPES)}"
            )
    if len(set(data_types)) != len(data_types):
        raise DeclarationError(f"{path}.data_types: duplicate data type")

    retention = item["retention_days"]
    # bool is an int subclass: `retention_days: yes` must not mean 1 day.
    if not isinstance(retention, int) or isinstance(retention, bool) or retention <= 0:
        raise DeclarationError(f"{path}.retention_days: must be a positive whole number of days")

    locations = _list(item["locations"], f"{path}.locations")
    if not locations:
        raise DeclarationError(f"{path}.locations: must list at least one location")
    parsed = tuple(_location(loc, f"{path}.locations[{i}]") for i, loc in enumerate(locations))
    resources = [location.resource for location in parsed]
    if len(set(resources)) != len(resources):
        raise DeclarationError(f"{path}.locations: duplicate resource")

    return Category(
        id=_string(item["id"], f"{path}.id"),
        data_types=tuple(data_types),
        purpose=_string(item["purpose"], f"{path}.purpose"),
        retention_days=retention,
        locations=parsed,
    )


def _location(data: Any, path: str) -> Location:
    item = _mapping(data, path, required={"resource"}, optional={"timestamp_column"})
    column = item.get("timestamp_column")
    return Location(
        resource=_string(item["resource"], f"{path}.resource"),
        timestamp_column=None if column is None else _string(column, f"{path}.timestamp_column"),
    )


def _mapping(
    data: Any, path: str, required: set[str], optional: frozenset[str] | set[str] = frozenset()
) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise DeclarationError(f"{path}: expected a mapping")
    missing = required - data.keys()
    if missing:
        raise DeclarationError(f"{path}: missing {', '.join(sorted(missing))}")
    unknown = data.keys() - required - optional
    if unknown:
        raise DeclarationError(f"{path}: unknown key {', '.join(sorted(map(str, unknown)))}")
    return data


def _list(data: Any, path: str) -> list[Any]:
    if not isinstance(data, list):
        raise DeclarationError(f"{path}: expected a list")
    return data


def _string(data: Any, path: str) -> str:
    if not isinstance(data, str) or not data.strip():
        raise DeclarationError(f"{path}: expected a non-empty string")
    return data.strip()
