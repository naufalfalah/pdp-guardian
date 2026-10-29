import copy
from pathlib import Path

import pytest

from pdp_guardian.declaration import (
    DeclarationError,
    Location,
    load_declaration,
    parse_declaration,
)

VALID = {
    "organization": "PT Kopi Senja (demo)",
    "categories": [
        {
            "id": "customer_identity",
            "data_types": ["NIK", "NAME", "PHONE", "ADDRESS"],
            "purpose": "KYC for loyalty program",
            "retention_days": 730,
            "locations": [
                {
                    "resource": "cloudsql://kopi-senja/app/customers",
                    "timestamp_column": "created_at",
                },
                {"resource": "gs://kopi-senja-exports"},
            ],
        }
    ],
}

YAML = """\
organization: PT Kopi Senja (demo)
categories:
  - id: customer_identity
    data_types: [NIK, NAME, PHONE, ADDRESS]
    purpose: "KYC for loyalty program"
    retention_days: 730
    locations:
      - resource: cloudsql://kopi-senja/app/customers
        timestamp_column: created_at
"""


def mutated(change) -> dict:
    data = copy.deepcopy(VALID)
    change(data)
    return data


def test_load_yaml(tmp_path: Path) -> None:
    path = tmp_path / "declaration.yaml"
    path.write_text(YAML, encoding="utf-8")

    declaration = load_declaration(path)

    assert declaration.organization == "PT Kopi Senja (demo)"
    (category,) = declaration.categories
    assert category.data_types == ("NIK", "NAME", "PHONE", "ADDRESS")
    assert category.retention_days == 730
    assert category.locations == (Location("cloudsql://kopi-senja/app/customers", "created_at"),)


def test_timestamp_column_is_optional() -> None:
    declaration = parse_declaration(VALID)
    assert declaration.categories[0].locations[1].timestamp_column is None


def test_declared_types_merge_categories_per_resource() -> None:
    def add_category(d: dict) -> None:
        d["categories"].append(
            {
                "id": "marketing",
                "data_types": ["EMAIL"],
                "purpose": "newsletter",
                "retention_days": 365,
                "locations": [{"resource": "gs://kopi-senja-exports"}],
            }
        )

    declared = parse_declaration(mutated(add_category)).declared_types()
    assert declared["gs://kopi-senja-exports"] == {"NIK", "NAME", "PHONE", "ADDRESS", "EMAIL"}


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda d: d["categories"][0]["data_types"].append("SSN"), r"data_types\[4\]: unknown"),
        (lambda d: d["categories"][0]["data_types"].append("nik"), "unknown data type 'nik'"),
        (lambda d: d["categories"][0].update(retention_days=0), "retention_days"),
        (lambda d: d["categories"][0].update(retention_days="730"), "retention_days"),
        (lambda d: d["categories"][0].update(retention_days=True), "retention_days"),
        (lambda d: d["categories"][0].update(retention=730), "unknown key retention"),
        (lambda d: d["categories"][0]["locations"][0].update(ts="x"), "unknown key ts"),
        (lambda d: d["categories"][0].pop("purpose"), "missing purpose"),
        (lambda d: d["categories"][0].update(locations=[]), "at least one location"),
        (lambda d: d["categories"][0].update(data_types=[]), "at least one data type"),
        (lambda d: d.update(categories=[]), "at least one category"),
        (lambda d: d["categories"].append(copy.deepcopy(d["categories"][0])), "duplicate category"),
        (lambda d: d["categories"][0]["data_types"].append("NIK"), "duplicate data type"),
        (lambda d: d.update(organization=""), "organization"),
    ],
)
def test_invalid_declarations_fail_loudly(change, message: str) -> None:
    with pytest.raises(DeclarationError, match=message):
        parse_declaration(mutated(change))


def test_not_a_mapping() -> None:
    with pytest.raises(DeclarationError, match="expected a mapping"):
        parse_declaration(["organization"])


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(DeclarationError, match="cannot read"):
        load_declaration(tmp_path / "missing.yaml")


def test_invalid_yaml(tmp_path: Path) -> None:
    path = tmp_path / "declaration.yaml"
    path.write_text("organization: [unclosed", encoding="utf-8")
    with pytest.raises(DeclarationError, match="not valid YAML"):
        load_declaration(path)
