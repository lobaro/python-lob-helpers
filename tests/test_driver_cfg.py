"""Tests for the DriverCfg base."""

from dataclasses import dataclass

import pytest

from lob_hlpr import DriverCfg


@dataclass
class _ExampleCfg(DriverCfg):
    """A tool with one optional and one defaulted argument."""

    port: str | None = None
    baudrate: int = 115200
    verbose: bool = False


def test_defaults_drop_none():
    """None means "use the driver default" and is not passed on."""
    assert _ExampleCfg().as_kwargs() == {"baudrate": 115200, "verbose": False}


def test_false_is_kept():
    """Only None is dropped, a falsy value is a real setting."""
    assert _ExampleCfg(verbose=False).as_kwargs()["verbose"] is False


def test_declared_fields_are_passed():
    """Every declared field reaches the driver."""
    assert _ExampleCfg(port="/dev/ttyUSB0").as_kwargs() == {
        "port": "/dev/ttyUSB0",
        "baudrate": 115200,
        "verbose": False,
    }


def test_extra_is_merged_but_not_itself_a_kwarg():
    """Extra is forwarded key by key, never as an ``extra=`` argument."""
    kwargs = _ExampleCfg(extra={"parity": "N"}).as_kwargs()
    assert kwargs["parity"] == "N"
    assert "extra" not in kwargs


def test_extra_wins_over_declared_fields():
    """A debugging session can override a documented value."""
    assert (
        _ExampleCfg(baudrate=9600, extra={"baudrate": 921600}).as_kwargs()["baudrate"]
        == 921600
    )


def test_overrides_win_over_extra():
    """An explicit argument beats both the field and extra."""
    cfg = _ExampleCfg(baudrate=9600, extra={"baudrate": 921600})
    assert cfg.as_kwargs(baudrate=4800)["baudrate"] == 4800


def test_none_override_does_not_clear_a_field():
    """An unset optional argument must not wipe a configured value."""
    cfg = _ExampleCfg(port="/dev/ttyUSB0")
    assert cfg.as_kwargs(port=None)["port"] == "/dev/ttyUSB0"


def test_extra_defaults_are_independent():
    """Each instance gets its own extra dict."""
    first, second = _ExampleCfg(), _ExampleCfg()
    first.extra["parity"] = "N"
    assert second.extra == {}


def test_kwargs_build_the_driver():
    """The whole point: the result is directly usable as **kwargs."""

    class _Driver:
        def __init__(self, port=None, baudrate=9600, verbose=False, parity="E"):
            self.port, self.baudrate = port, baudrate
            self.verbose, self.parity = verbose, parity

    cfg = _ExampleCfg(port="/dev/ttyUSB0", extra={"parity": "N"})
    driver = _Driver(**cfg.as_kwargs())
    assert (driver.port, driver.baudrate, driver.parity) == (
        "/dev/ttyUSB0",
        115200,
        "N",
    )


def test_unknown_extra_key_raises_from_the_driver():
    """An unknown extra is not swallowed, it fails where it is used."""

    class _Driver:
        def __init__(self, port=None, baudrate=9600, verbose=False):
            pass

    cfg = _ExampleCfg(extra={"nonsense": 1})
    with pytest.raises(TypeError):
        _Driver(**cfg.as_kwargs())


def test_none_in_extra_is_dropped():
    """Extra follows the same contract, a None there is not a setting."""
    assert "timeout" not in _ExampleCfg(extra={"timeout": None}).as_kwargs()


def test_extra_none_does_not_unset_a_field():
    """A None in extra leaves the declared value alone."""
    cfg = _ExampleCfg(baudrate=9600, extra={"baudrate": None})
    assert cfg.as_kwargs()["baudrate"] == 9600


def test_subclass_may_declare_a_required_argument():
    """Extra is keyword only, so it does not block a required field."""

    @dataclass
    class _RequiredCfg(DriverCfg):
        port: str

    assert _RequiredCfg("/dev/ttyUSB0").as_kwargs() == {"port": "/dev/ttyUSB0"}
