import pytest

from pdp_guardian.checks import Status, check_region
from pdp_guardian.connectors.base import Resource, ResourceKind


def bucket(location: str | None) -> Resource:
    return Resource("gs://kopi-senja-exports", ResourceKind.BUCKET, location)


@pytest.mark.parametrize("location", ["asia-southeast2", "ASIA-SOUTHEAST2", "ap-southeast-3"])
def test_indonesian_region_passes(location: str) -> None:
    result = check_region(bucket(location), ["NIK"])
    assert result.status is Status.PASS
    assert result.check_id == "C5"


@pytest.mark.parametrize("location", ["us", "asia", "asia-southeast1", "eu"])
def test_outside_indonesia_needs_review_never_fails(location: str) -> None:
    result = check_region(bucket(location), ["NIK", "NAME"])
    assert result.status is Status.NEEDS_REVIEW
    assert result.details == {"data_types": "NAME, NIK", "location": location}


def test_unknown_location_needs_review() -> None:
    result = check_region(bucket(None), ["NIK"])
    assert result.status is Status.NEEDS_REVIEW
    assert result.details["note"] == "location unknown"


def test_resource_without_personal_data_does_not_apply() -> None:
    assert check_region(bucket("us"), []) is None
