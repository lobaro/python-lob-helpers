import pytest

from lob_hlpr import (  # Adjust the import path as necessary
    FirmwareID,
    FirmwareVersion,
)


def test_valid_firmware_id_with_variants():
    """Tests if the firmware ID can be created with variants."""
    id_str = (
        "app-nrf9160-wmbus v0.24.1-9-g8ad003f+hw3.alt_phy TZ2 (Mar 11 2024 13:57:40)"
    )
    firmware_id = FirmwareID(id_str)
    assert firmware_id.name == "app-nrf9160-wmbus"
    assert isinstance(firmware_id.version, FirmwareVersion)
    assert firmware_id.version.version_string == "0.24.1-9-g8ad003f"
    assert firmware_id.variants == ["hw3", "alt_phy"]
    assert firmware_id.built == "2024-03-11T13:57:40"


def test_valid_firmware_id_with_origin_pass():
    """Tests if the firmware ID can be created with 'origin' in the version string."""
    id_str = "app-nrf91-origin+0.3.7+hw4 TZ3 (Mar  5 2025 08:36:26)"
    firmware_id = FirmwareID(id_str)
    assert firmware_id.name == "app-nrf91-origin"
    assert isinstance(firmware_id.version, FirmwareVersion)
    assert firmware_id.version.version_string == "0.3.7"
    assert firmware_id.variants == ["hw4"]
    assert firmware_id.built == "2025-03-05T08:36:26"


def test_valid_firmware_id_unknown():
    """Tests if the firmware ID can be created with 'unknown' in the version string."""
    id_str = "app-nrf9160-wmbus v0.0.0-unknown+hw3 TZ2 (Oct 12 2023 10:45:49)"
    firmware_id = FirmwareID(id_str)
    assert firmware_id.name == "app-nrf9160-wmbus"
    assert isinstance(firmware_id.version, FirmwareVersion)
    assert firmware_id.version.version_string == "0.0.0-unknown"
    assert firmware_id.variants == ["hw3"]
    assert firmware_id.built == "2023-10-12T10:45:49"


def test_valid_firmware_id_without_variants():
    """Tests if the firmware ID can be created without variants."""
    id_str = "Lobaro v1.2.3 (Jan 01 2021 00:00:00)"
    firmware_id = FirmwareID(id_str)
    assert firmware_id.name == "Lobaro"
    assert isinstance(firmware_id.version, FirmwareVersion)
    assert firmware_id.version.version_string == "1.2.3"
    assert firmware_id.variants == []
    assert firmware_id.built == "2021-01-01T00:00:00"


def test_valid_firmware_without_date():
    """Tests if the firmware ID can be created without variants."""
    id_str = "Lobaro v1.2.3"
    firmware_id = FirmwareID(id_str)
    assert firmware_id.name == "Lobaro"
    assert isinstance(firmware_id.version, FirmwareVersion)
    assert firmware_id.version.version_string == "1.2.3"
    assert firmware_id.variants == []
    assert firmware_id.built is None


def test_firmware_id_with_invalid_date():
    """Tests if the firmware ID can be created with an invalid date format."""
    id_str = "Lobaro v1.2.3+hw3 (Invalid Date Format)"
    with pytest.raises(ValueError):
        FirmwareID(id_str)


def test_firmware_id_with_incomplete_string():
    """Tests if the firmware ID can be created with an incomplete string."""
    id_str = "Lobaro v1.2"
    with pytest.raises(ValueError):
        FirmwareID(id_str)


def test_firmware_id_with_no_version():
    """Tests if the firmware ID can be created without a version."""
    id_str = "Lobaro v (Jan 01 2021 00:00:00)"
    with pytest.raises(ValueError):
        FirmwareID(id_str)


def test_firmware_id_with_no_name():
    """Tests if the firmware ID can be created without a name."""
    id_str = " v1.2.3 (Jan 01 2021 00:00:00)"
    with pytest.raises(ValueError):
        FirmwareID(id_str)
