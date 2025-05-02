import pytest

from lob_hlpr import FirmwareVersion


def test_valid_version():
    """Test with a valid version string."""
    version = FirmwareVersion("1.2.3-4-gabc123-dirty")
    assert version.major == 1
    assert version.minor == 2
    assert version.patch == 3
    assert version.commits == 4
    assert version.commit == "abc123"
    assert version.dirty is True
    assert version.unknown is False


def test_valid_version_with_unknown():
    """Test with a version string that includes 'unknown'."""
    version = FirmwareVersion("1.2.3-unknown")
    assert version.major == 1
    assert version.minor == 2
    assert version.patch == 3
    assert version.commits == 0
    assert version.commit is None
    assert version.dirty is False
    assert version.unknown is True


def test_version_without_optional_parts():
    """Test with a version string that does not include optional parts."""
    version = FirmwareVersion("1.2.3")
    assert version.major == 1
    assert version.minor == 2
    assert version.patch == 3
    assert version.commits == 0
    assert version.commit is None
    assert version.dirty is False
    assert version.unknown is False


def test_invalid_version():
    """Test with an invalid version string."""
    with pytest.raises(ValueError):
        FirmwareVersion("invalid.version.string")


def test_empty_version():
    """Test with an empty version string."""
    with pytest.raises(ValueError):
        FirmwareVersion("")


def test_partial_version():
    """Test with a partial version string."""
    # Assuming partial versions are not allowed and should raise an error
    with pytest.raises(ValueError):
        FirmwareVersion("1.2")
