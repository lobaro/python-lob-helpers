import logging
from dataclasses import dataclass

import pytest

from lob_hlpr import LobHlpr as hlp


def test_parse_dmc_pass():
    """Test passing branches of the parse_dmc function."""
    assert hlp.parse_dmc("MPP-OR023282_1-00002") == (
        "MPP-OR023282",
        "1",
        "00002",
        None,
    )
    assert hlp.parse_dmc("MPP-M0011554-OR023282_1-00002") == (
        "MPP-OR023282",
        "1",
        "00002",
        "M0011554",
    )


def test_parse_dmc_fail():
    """Test failing branches of the parse_dmc function."""
    with pytest.raises(IndexError):
        hlp.parse_dmc("MPP-OR023282_1")


# A bit of looking through a hex file and manual parsing allows me to provide
# the following data for testing.
HEX_STRINGS = [
    """:020000040000FA

:100400003E3D3D484558494E464F3D3D3E6170702A
:100410002D6D6375626F6F742D6E72663931363073
:100420002D7365632076312E332E302B4D422054B0
:100430005A32202853657020203920323032312042
:1004400031323A32383A3533293C3D3D48455849F6
:070450004E464F3D3D3C000C
:00000001FF""",
    """:020000040000FA
:10C800003E3D3D484558494E464F3D3D3E61707066
:10C810002D626F6F742D6E7266393136302D7365EF
:10C82000632076312E382E3220545A322028466525
:10C830006220203820323032332031373A30333AD8
:10C840003337293C3D3D484558494E464F3D3D3CD8
:00000001FF""",
    """:020000040000FA
:100800003E3D3D484558494E464F3D3D3E61707026
:100810002D6E7266393136302D776D6275732076A4
:10082000302E32332E362B68773320545A3220281C
:100830004A616E20323720323032342031343A323D
:10084000303A3436293C3D3D484558494E464F3DA7
:100850003D3C7365637572653D312E382E303B70BB
:10086000696E3D4D4200FFFFFFFFFFFFFFFFFFFFEF
:00000001FF""",
    """:020000040000FA
:100400003E3D3D484558494E464F3D3D3E6170702A
:100410002D6D6375626F6F742D6E72663931363073
:100420002D7365632076312E332E302B4D422054B0
:100430005A32202853657020203920323032312042
:1004400031323A32383A3533293C3D3D48455849F6
:070450004E464F3D3D3C000C
:10C800003E3D3D484558494E464F3D3D3E61707066
:10C810002D626F6F742D6E7266393136302D7365EF
:10C82000632076312E382E3220545A322028466525
:10C830006220203820323032332031373A30333AD8
:10C840003337293C3D3D484558494E464F3D3D3CD8
:020000040000FA
:100800003E3D3D484558494E464F3D3D3E61707026
:100810002D6E7266393136302D776D6275732076A4
:10082000302E32332E362B68773320545A3220281C
:100830004A616E20323720323032342031343A323D
:10084000303A3436293C3D3D484558494E464F3DA7
:100850003D3C7365637572653D312E382E303B70BB
:10086000696E3D4D4200FFFFFFFFFFFFFFFFFFFFEF
:020000021200EA
:00000001FF""",
]


@pytest.mark.parametrize(
    "hex_str,expected",
    [
        (
            HEX_STRINGS[0],
            ["app-mcuboot-nrf9160-sec v1.3.0+MB TZ2 (Sep  9 2021 12:28:53)"],
        ),
        (HEX_STRINGS[1], ["app-boot-nrf9160-sec v1.8.2 TZ2 (Feb  8 2023 17:03:37)"]),
        (HEX_STRINGS[2], ["app-nrf9160-wmbus v0.23.6+hw3 TZ2 (Jan 27 2024 14:20:46)"]),
        (
            HEX_STRINGS[3],
            [
                "app-mcuboot-nrf9160-sec v1.3.0+MB TZ2 (Sep  9 2021 12:28:53)",
                "app-boot-nrf9160-sec v1.8.2 TZ2 (Feb  8 2023 17:03:37)",
                "app-nrf9160-wmbus v0.23.6+hw3 TZ2 (Jan 27 2024 14:20:46)",
            ],
        ),
    ],
)
def test_extract_identifier_valid_hex(hex_str, expected):
    """Test extract_identifier_from_hexfile with valid HEXINFO."""
    identifier = hlp.extract_identifier_from_hexfile(hex_str)
    print(identifier)
    for exp in expected:
        assert exp in identifier


def test_extract_identifier_invalid_hex():
    """Test extract_identifier_from_hexfile with invalid HEXINFO."""
    # Hex string with invalid HEXINFO
    hex_str = "garbage data"
    with pytest.raises(ValueError):
        hlp.extract_identifier_from_hexfile(hex_str)

    hex_str = ":0102030405"
    with pytest.raises(ValueError):
        hlp.extract_identifier_from_hexfile(hex_str)


def test_extract_identifier_no_hexinfo():
    """Test extract_identifier_from_hexfile with no HEXINFO."""
    # Hex string without HEXINFO, just for structure demonstration
    hex_str = """:020000040000FA
:10C000000102030405060708090A0B0C0D0E0F1011
:00000001FF"""
    with pytest.raises(ValueError):
        hlp.extract_identifier_from_hexfile(hex_str)


def test_log_print_passes(tmp_path, capsys):
    """Test log_print function with valid inputs."""
    test_logger = logging.getLogger("test_logger")
    test_logger.setLevel("INFO")
    test_logger.info("Will not show up in logs")
    test_file = tmp_path / "test.log"
    hlp.lob_print(str(test_file), "Test message")
    test_logger.info("Will show in logs after lob_print")
    captured = capsys.readouterr()
    assert "Test message" in captured.out
    assert test_file.exists()
    with open(test_file) as f:
        log_content = f.read()
        assert "Test message" in log_content
        assert "Will show in logs after lob_print" in log_content
        assert "Will not show up in logs" not in log_content


def test_as_clean_dict_passes():
    """Test as_clean_dict function with valid inputs."""

    @dataclass
    class NestedTestClass:
        nested_key: str | None = None

    @dataclass
    class TestClass:
        strkey: str | None = None
        intkey: int | None = None
        boolkey: bool | None = None
        listkey: list | None = None
        dictkey: dict | None = None
        nested: NestedTestClass | None = None

    dclass = TestClass()

    assert hlp.ascleandict(dclass) == {}

    dclass.strkey = ""
    dclass.intkey = 0
    dclass.listkey = []
    dclass.dictkey = {}
    dclass.boolkey = False
    dclass.nested = NestedTestClass()
    assert hlp.ascleandict(dclass) == {"intkey": 0, "strkey": "", "boolkey": False}

    assert hlp.ascleandict(dclass, remove_false=True) == {"intkey": 0, "strkey": ""}


def test_unix_timestamp():
    """Test unix_timestamp function."""
    timestamp = hlp.unix_timestamp()
    # Test if it is greater than the timestamp of writing the test
    assert timestamp > 1732266521241
    # and less than 100 years from now
    assert timestamp < 1732266521241 + 100 * 365 * 24 * 3600 * 1000


def test_format_unix_timestamp():
    """Test format_unix_timestamp function."""
    timestamp = hlp.format_unix_timestamp(1732266521241)
    # Test if it is in the correct format
    assert timestamp == "2024-11-22_10-08-41" or timestamp == "2024-11-22_09-08-41"
