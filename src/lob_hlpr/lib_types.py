import re
from dataclasses import dataclass
from datetime import datetime


@dataclass
class FirmwareVersion:
    """Represents a firmware version, parsing all components used by Lobaro firmware.

    Raises:
        ValueError: If the provided version string does not match the expected format.
    """

    version_string: str
    """The complete version string to be parsed."""

    major: int = 0
    """Major version number."""

    minor: int = 0
    """Minor version number."""

    patch: int = 0
    """Patch version number."""

    commits: int = 0
    """Number of commits since the last version tag."""

    commit: str | None = None
    """Commit hash associated with this version."""

    dirty: bool = False
    """Indicates if there are uncommitted changes in the source."""

    unknown: bool = False
    """Flag for any unknown additional information in the version string."""

    _VERSION_REGEX = re.compile(
        r"(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)"
        r"(?:-(?P<commits>\d+)-g(?P<commit>[0-9a-f]+))?"
        r"(?P<dirty>-dirty)?(?P<unknown>-unknown)?"
    )
    """Precompiled regex for parsing all parts of a version string."""

    def __post_init__(self):
        """Parses the version string and updates the object's attributes accordingly.

        This method is automatically called after the data class has been initialized.
        """
        m = self._VERSION_REGEX.match(self.version_string)
        try:
            self.major = int(m.group("major"))
            self.minor = int(m.group("minor"))
            self.patch = int(m.group("patch"))
            self.commits = int(m.group("commits") or 0)
            self.commit = m.group("commit")
            self.dirty = bool(m.group("dirty"))
            self.unknown = bool(m.group("unknown"))
        except (AttributeError, ValueError, TypeError, IndexError, KeyError) as exc:
            raise ValueError(
                f"Invalid version string: '{self.version_string}'"
            ) from exc


@dataclass
class FirmwareID:
    """Represents a firmware id, parsing all components used by Lobaro firmware.

    Raises:
        ValueError: If the provided id does not match the expected format.
    """

    id_string: str
    """The complete firmware identifier string to be parsed."""

    name: str | None = None
    """The name of the firmware."""

    version: FirmwareVersion | None = None
    """The version of the firmware."""

    variants: list[str] | None = None
    """A list of all variants of the firmware, e.g. ['hw3', 'alt_phy']."""

    built: str | None = None
    """The build date of firmware, e.g. 'Jan 01 2021 00:00:00'"""

    _IDENTIFIER_RE = re.compile(
        # Name group, non-greedy match up to the first space
        r"^(?P<name>.+?)\s+"
        # Version group, matches a semantic versioning pattern
        r"v(?P<version>[0-9]+(?:\.[0-9]+){2}(?:-[\w]+)?(?:-\d+-g[0-9a-f]+)?)"
        # Optional variant group, matches anything after a '+' until a space or end
        r"(?:\+(?P<variant>[^\s]+))?"
        # Optional additional group,
        # matches before parentheses if not directly next to variant
        r"(?:\s+(?P<additional>[^\(\)]+?))?"
        # Date group, matches everything inside the parentheses, made entirely optional
        r"(?:\s*\((?P<date>.+?)\))?$",
    )
    """Precompiled regex for parsing all parts of a firmware identifier string."""

    def __post_init__(self):
        """Parses the firmware identifier string and updates attributes accordingly."""
        try:
            m = self._IDENTIFIER_RE.match(self.id_string)
            groups = m.groupdict()
            self.name = groups["name"]
            self.version = FirmwareVersion(groups["version"])
            self.variants = groups["variant"].split(".") if groups["variant"] else []
            built = groups.get("date", None)
            if built:
                self.built = datetime.strptime(built, "%b %d %Y %H:%M:%S").isoformat()
        except (AttributeError, ValueError, TypeError, IndexError, KeyError) as exc:
            raise ValueError(
                f"Invalid firmware identifier string: '{self.id_string}'"
            ) from exc
