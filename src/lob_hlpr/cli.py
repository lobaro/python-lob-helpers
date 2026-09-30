"""Helpers for building the command line interfaces of the Lobaro tools."""

import argparse
import logging
import warnings
from collections.abc import Sequence
from typing import Any

_LOGGER = logging.getLogger(__name__)

# Actions whose value DeprecatedAliasAction can store the same way. Others such
# as append or count build on the previous value, which the alias would lose.
_ALIASABLE_ACTIONS = (None, "store", "store_true", "store_false", "store_const")


class DeprecatedAliasAction(argparse.Action):
    """Store a value like the option it replaces, but say it is out of date.

    Rarely used directly, :func:`add_renamed_argument` wires it up.
    """

    def __init__(self, option_strings: Sequence[str], dest: str, **kwargs: Any):
        """Take the replacement flag out of the keywords argparse does not know."""
        self.use_instead: str = kwargs.pop("use_instead", dest)
        super().__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        """Warn about the old spelling, then store as the current one would."""
        message = f"{option_string} is deprecated, use {self.use_instead} instead."
        warnings.warn(message, DeprecationWarning, stacklevel=2)
        # Logging rather than print, and visible without a configured handler
        # because logging falls back to writing warnings to stderr.
        _LOGGER.warning(message)
        # nargs == 0 means a flag such as store_true, which carries its value in
        # const instead of on the command line.
        setattr(namespace, self.dest, self.const if self.nargs == 0 else values)


def add_renamed_argument(
    parser: argparse.ArgumentParser,
    *flags: str,
    deprecated: str | Sequence[str],
    **kwargs: Any,
) -> argparse.Action:
    """Add an option and keep earlier spellings of it working.

    The old spellings write to the same destination as the current one, so
    nothing downstream has to know they exist. They are hidden from ``--help``
    and warn when used, both as a :class:`DeprecationWarning` and as a log
    record, so a user sees the message even before logging is configured.

    Args:
        parser: The parser to extend.
        flags: The current flags, for example ``"--log-level"``.
        deprecated: Old flag or flags that should still work, for example
            ``"--loglevel"``.
        kwargs: Passed through to :meth:`argparse.ArgumentParser.add_argument`.

    Returns:
        The action for the current option.

    Raises:
        ValueError: For ``required=True``, which argparse checks per spelling
            so the old one could never satisfy it, and for actions other than
            the store ones, such as ``append`` or ``count``.

    Example:
        >>> parser = argparse.ArgumentParser()
        >>> _ = add_renamed_argument(
        ...     parser, "--log-level", deprecated="--loglevel", default="WARNING"
        ... )
        >>> parser.parse_args(["--loglevel", "DEBUG"]).log_level
        'DEBUG'
    """
    if kwargs.get("required"):
        raise ValueError("A renamed option cannot be required")
    if kwargs.get("action") not in _ALIASABLE_ACTIONS:
        raise ValueError(f"A renamed option cannot use action={kwargs['action']!r}")
    action = parser.add_argument(*flags, **kwargs)
    # argparse's own default for these is not None, so only forward the ones the
    # current option actually set.
    inherited: dict[str, Any] = {
        name: value
        for name, value in (
            ("nargs", action.nargs),
            ("const", action.const),
            ("type", action.type),
            ("choices", action.choices),
        )
        if value is not None
    }
    old_flags = [deprecated] if isinstance(deprecated, str) else list(deprecated)
    for old_flag in old_flags:
        parser.add_argument(
            old_flag,
            action=DeprecatedAliasAction,
            use_instead=action.option_strings[0],
            dest=action.dest,
            # Never supply a default, that is the current option's job. Without
            # this the alias would overwrite it with None.
            default=argparse.SUPPRESS,
            required=False,
            help=argparse.SUPPRESS,
            **inherited,
        )
    return action
