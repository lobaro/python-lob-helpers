## lob-hlpr

Simple python based helpers for lobaro tools.

This package does not have any dependencies and should easily integrate into
other packages.

## Renaming a command line option

`add_renamed_argument` adds an option and keeps earlier spellings of it working,
so a rename does not break anyone's scripts:

```python
import argparse
from lob_hlpr import add_renamed_argument

parser = argparse.ArgumentParser()
add_renamed_argument(parser, "--log-level", deprecated="--loglevel", default="WARNING")

parser.parse_args(["--loglevel", "DEBUG"]).log_level  # "DEBUG", with a warning
```

The old spelling writes to the same destination as the current one, so the rest
of the program never learns it exists and no fixup step is needed after parsing.
It is hidden from `--help` and warns when used, both as a `DeprecationWarning`
and as a log record, so a user sees it even before logging is configured.

Pass a list to `deprecated` for an option that has been renamed more than once.
Options that take no value, such as `action="store_true"`, work too.

## Installation

This package should be available in `pypi` and can be installed with `pip` or
as a dependency.

## Contributing

This package is really only meant for Lobaro, however, other may find it useful
and can contribute to it.
Before doing so read
[contributing guide](https://github.com/astral-sh/uv/blob/main/CONTRIBUTING.md)
to get started.
