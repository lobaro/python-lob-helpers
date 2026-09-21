"""Base for driver configuration sections."""

from dataclasses import dataclass, field, fields
from typing import Any


@dataclass
class DriverCfg:
    """Configuration of a single tool, forwardable to its constructor.

    The fields are exactly the driver's constructor keyword arguments. If a
    value does not fit the constructor, the constructor is what changes, so a
    section can never drift away from the tool it describes.

    Deliberately independent of any configuration file format. A config class
    picks these up as nested sections, but a section is equally usable alone::

        >>> @dataclass
        ... class PpkCfg(DriverCfg):
        ...     port: str | None = None
        ...     voltage: float | None = None
        >>> PpkCfg(port="/dev/ttyUSB0").as_kwargs()
        {'port': '/dev/ttyUSB0'}
    """

    extra: dict[str, Any] = field(default_factory=dict)
    """Undocumented keyword arguments passed straight to the driver.

    Escape hatch for a driver option this configuration has not been taught
    yet, and for one-off debugging sessions. Nothing here is validated: an
    unknown key raises ``TypeError`` from the driver constructor, which is the
    intended feedback.
    """

    def as_kwargs(self, **overrides: Any) -> dict[str, Any]:
        """Returns the constructor keyword arguments for this tool.

        Precedence, lowest first: the declared fields, then :attr:`extra`,
        then *overrides*. ``None`` is dropped at every layer so the driver's
        own default or autodiscovery applies, keeping the "None means use the
        known default" contract.

        Args:
            **overrides: Values that win over the declared fields and
                :attr:`extra`, e.g. a command line argument.

        Returns:
            The keyword arguments to build the driver with.

        Example:
            >>> @dataclass
            ... class LaserCfg(DriverCfg):
            ...     host: str = "127.0.0.1"
            ...     port: int = 3000
            >>> cfg = LaserCfg(extra={"timeout": 2.0})
            >>> cfg.as_kwargs(port=4000)
            {'host': '127.0.0.1', 'port': 4000, 'timeout': 2.0}
        """
        kwargs = {
            f.name: getattr(self, f.name) for f in fields(self) if f.name != "extra"
        }
        kwargs = {k: v for k, v in kwargs.items() if v is not None}
        kwargs.update(self.extra)
        kwargs.update({k: v for k, v in overrides.items() if v is not None})
        return kwargs
