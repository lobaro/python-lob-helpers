"""Tests for renaming a command line option without breaking the old spelling."""

import argparse
import logging

import pytest

from lob_hlpr import add_renamed_argument


@pytest.fixture
def parser():
    """A parser with a renamed option that takes a value."""
    parser = argparse.ArgumentParser("test", exit_on_error=False)
    add_renamed_argument(
        parser, "--log-level", deprecated="--loglevel", default="WARNING"
    )
    return parser


def test_current_spelling_is_stored(parser):
    """The new flag behaves like any other option."""
    assert parser.parse_args(["--log-level", "DEBUG"]).log_level == "DEBUG"


def test_deprecated_spelling_lands_in_the_same_place(parser):
    """Callers read one attribute and never learn which spelling was used."""
    with pytest.deprecated_call():
        args = parser.parse_args(["--loglevel", "DEBUG"])
    assert args.log_level == "DEBUG"


def test_default_survives_the_alias(parser):
    """The alias must not overwrite the default with an empty value."""
    assert parser.parse_args([]).log_level == "WARNING"


def test_current_spelling_does_not_warn(parser, recwarn):
    """Only the old spelling is worth complaining about."""
    parser.parse_args(["--log-level", "DEBUG"])
    assert not recwarn.list


def test_the_last_flag_given_wins(parser):
    """Mixing spellings is odd but should not need a precedence rule."""
    with pytest.deprecated_call():
        args = parser.parse_args(["--loglevel", "DEBUG", "--log-level", "INFO"])
    assert args.log_level == "INFO"


def test_deprecated_spelling_is_hidden_from_help(parser):
    """The old flag still works but should not be advertised."""
    help_text = parser.format_help()
    assert "--log-level" in help_text
    assert "--loglevel" not in help_text


def test_the_warning_names_both_spellings(parser):
    """A warning the user cannot act on is not worth printing."""
    with pytest.warns(DeprecationWarning) as warnings_raised:
        parser.parse_args(["--loglevel", "DEBUG"])
    message = str(warnings_raised[0].message)
    assert "--loglevel" in message
    assert "--log-level" in message


def test_the_warning_is_logged_too(parser, caplog):
    """A DeprecationWarning alone is hidden by default, a user sees nothing."""
    with caplog.at_level(logging.WARNING), pytest.deprecated_call():
        parser.parse_args(["--loglevel", "DEBUG"])
    assert "--loglevel is deprecated" in caplog.text


def test_the_value_is_converted_like_the_current_option():
    """The alias has to apply the same type, not hand back a string."""
    parser = argparse.ArgumentParser("test")
    add_renamed_argument(parser, "--retry-count", deprecated="--retrycount", type=int)
    with pytest.deprecated_call():
        assert parser.parse_args(["--retrycount", "3"]).retry_count == 3


def test_a_flag_without_a_value_can_be_renamed():
    """store_true carries its value in const rather than on the command line."""
    parser = argparse.ArgumentParser("test")
    add_renamed_argument(parser, "--no-gui", deprecated="--nogui", action="store_true")
    assert parser.parse_args([]).no_gui is False
    with pytest.deprecated_call():
        assert parser.parse_args(["--nogui"]).no_gui is True


def test_several_old_spellings_can_be_kept_alive():
    """An option renamed twice should not need two helpers."""
    parser = argparse.ArgumentParser("test")
    add_renamed_argument(
        parser, "--log-level", deprecated=["--loglevel", "--log_level"]
    )
    with pytest.deprecated_call():
        assert parser.parse_args(["--log_level", "DEBUG"]).log_level == "DEBUG"
    with pytest.deprecated_call():
        assert parser.parse_args(["--loglevel", "INFO"]).log_level == "INFO"


def test_a_short_flag_can_be_added_alongside():
    """Tools differ on whether the short flag is free to use."""
    parser = argparse.ArgumentParser("test")
    add_renamed_argument(parser, "--one-cmd", "-o", deprecated="--onecmd")
    assert parser.parse_args(["-o", "info"]).one_cmd == "info"
    with pytest.deprecated_call():
        assert parser.parse_args(["--onecmd", "info"]).one_cmd == "info"


def test_choices_are_enforced_for_the_old_spelling_too():
    """An alias that skips validation would be a hole in the interface."""
    parser = argparse.ArgumentParser("test", exit_on_error=False)
    add_renamed_argument(
        parser, "--mode", deprecated="--Mode", choices=["fast", "slow"]
    )
    with pytest.raises(argparse.ArgumentError):
        parser.parse_args(["--Mode", "sideways"])
