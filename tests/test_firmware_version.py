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


def test_pre_release_rc():
    """Test with a semver pre-release tag like rc.2."""
    version = FirmwareVersion("0.13.1-rc.2")
    assert version.major == 0
    assert version.minor == 13
    assert version.patch == 1
    assert version.pre_release == "rc.2"
    assert version.commits == 0
    assert version.commit is None
    assert version.dirty is False
    assert version.unknown is False


def test_pre_release_alpha():
    """Test with a semver pre-release tag like alpha.1."""
    version = FirmwareVersion("1.0.0-alpha.1")
    assert version.pre_release == "alpha.1"
    assert version.major == 1
    assert version.minor == 0
    assert version.patch == 0


def test_pre_release_with_commits():
    """Test a pre-release version that also has commit distance info."""
    version = FirmwareVersion("0.13.1-rc.2-3-gabcdef")
    assert version.pre_release == "rc.2"
    assert version.commits == 3
    assert version.commit == "abcdef"


def test_pre_release_none_for_plain_version():
    """Ensure pre_release is None for versions without a pre-release tag."""
    version = FirmwareVersion("1.2.3")
    assert version.pre_release is None


def test_unknown_not_treated_as_pre_release():
    """Ensure -unknown is captured in the unknown flag, not as pre_release."""
    version = FirmwareVersion("1.2.3-unknown")
    assert version.unknown is True
    assert version.pre_release is None


def test_dirty_not_treated_as_pre_release():
    """Ensure -dirty is captured in the dirty flag, not as pre_release."""
    version = FirmwareVersion("1.2.3-dirty")
    assert version.dirty is True
    assert version.pre_release is None
