import json
import logging
import logging.handlers
import threading
from concurrent.futures import ThreadPoolExecutor
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
    with pytest.raises(ValueError):
        hlp.parse_dmc("PP-OR023282_1")


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
    hlp.lob_print(str(test_file), "Another test message")
    hlp.lob_print(str(test_file), "red message", color="red")
    hlp.lob_print(str(test_file), "yellow message", color="yellow")
    hlp.lob_print(str(test_file), "green message", color="green")
    hlp.lob_print(str(test_file), "normal message", color="doesn't matter")
    test_logger.info("Will show in logs after lob_print")
    captured = capsys.readouterr()
    assert "Test message" in captured.out
    # Check that only one "Another test message" is in the output
    assert captured.out.count("Another test message") == 1
    assert test_file.exists()
    assert captured.out.count("red message") == 1
    with open(test_file) as f:
        log_content = f.read()
        assert "Test message" in log_content
        assert "Will show in logs after lob_print" in log_content
        assert "Will not show up in logs" not in log_content
        # Check that only one "Another test message" is in the output
        assert log_content.count("Another test message") == 1


def test_log_print_multiline(tmp_path, capsys):
    """Multiline messages are split into one log record per line.

    The console output must be unchanged (print handles newlines natively),
    while the log file must contain each line as a separate entry so that
    log parsers and grep work without special handling.
    """
    test_file = tmp_path / "multiline.log"
    hlp.lob_print(str(test_file), "line one\nline two\nline three")

    captured = capsys.readouterr()
    # Console retains the original newlines via print
    assert "line one\nline two\nline three" in captured.out

    log_content = test_file.read_text()
    # Each line is a separate log record — no embedded newlines in any record
    log_lines = [ln for ln in log_content.splitlines() if ln.strip()]
    assert any("line one" in ln for ln in log_lines)
    assert any("line two" in ln for ln in log_lines)
    assert any("line three" in ln for ln in log_lines)
    # None of the individual log records should span multiple lines
    assert not any("\n" in ln for ln in log_lines)


def test_log_print_concurrent(tmp_path):
    """lob_print is safe to call from multiple threads simultaneously.

    Concurrent callers sharing the same log_path must result in exactly one
    RotatingFileHandler attached to root_logger and each message written
    exactly once to the log file.
    """
    test_file = tmp_path / "concurrent.log"
    n_threads = 20
    barrier = threading.Barrier(n_threads)

    def worker(i):
        # All threads reach the barrier before any of them calls lob_print,
        # maximising the chance of a real race on handler setup.
        barrier.wait()
        hlp.lob_print(str(test_file), f"msg-{i:04d}")

    with ThreadPoolExecutor(max_workers=n_threads) as pool:
        futures = [pool.submit(worker, i) for i in range(n_threads)]
        for f in futures:
            f.result()  # re-raises any exception from the thread

    root_logger = logging.getLogger()
    file_handlers = [
        h
        for h in root_logger.handlers
        if isinstance(h, logging.handlers.RotatingFileHandler)
        and h.baseFilename == str(test_file.resolve())
    ]
    assert len(file_handlers) == 1, (
        f"Expected exactly 1 RotatingFileHandler, got {len(file_handlers)}"
    )

    log_content = test_file.read_text()
    for i in range(n_threads):
        count = log_content.count(f"msg-{i:04d}")
        assert count == 1, f"msg-{i:04d} appeared {count} times in log (expected 1)"


def test_ascleandict_rejects_non_dataclass():
    """Test that ascleandict raises TypeError for non-dataclass inputs."""
    with pytest.raises(TypeError):
        hlp.ascleandict({"key": "value"})
    with pytest.raises(TypeError):
        hlp.ascleandict([1, 2, 3])
    with pytest.raises(TypeError):
        hlp.ascleandict("string")
    with pytest.raises(TypeError):
        hlp.ascleandict(42)
    # Dataclass type (not instance) must also be rejected
    with pytest.raises(TypeError):
        hlp.ascleandict(dataclass)


def test_as_clean_dict_passes():
    """Test as_clean_dict function with valid inputs."""

    @dataclass
    class MoreNestedTestClass:
        listkey: list | None = None
        dictkey: dict | None = None

    @dataclass
    class NestedTestClass:
        more_nested: MoreNestedTestClass | None = None

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
    dclass.nested.more_nested = MoreNestedTestClass(dictkey={}, listkey=[])
    assert hlp.ascleandict(dclass) == {"intkey": 0, "strkey": "", "boolkey": False}
    assert "nested" not in hlp.ascleandict(dclass)

    assert hlp.ascleandict(dclass, remove_false=True) == {"intkey": 0, "strkey": ""}

    @dataclass
    class DataWithList:
        items: list
        name: str

    data2 = DataWithList(
        items=[{"value": 1, "empty_dict": {}}, {"value": 2, "none_val": None}, [], {}],
        name="test",
    )
    result2 = hlp.ascleandict(data2)
    assert result2 == {"name": "test", "items": [{"value": 1}, {"value": 2}]}


def test_ascleandict_non_picklable_field():
    """Test that ascleandict handles non-picklable fields (e.g. thread locks).

    dataclasses.asdict() calls copy.deepcopy() on non-dataclass values, which
    fails for objects containing thread locks with:
      TypeError: cannot pickle '_thread.lock' object
    The custom converter must pass such values through without copying them.
    """
    import _thread
    import threading

    @dataclass
    class WithLock:
        name: str
        lock: _thread.LockType

    lock = threading.Lock()
    data = WithLock(name="test", lock=lock)
    result = hlp.ascleandict(data)

    with pytest.raises(TypeError):
        json.dumps(result)
    assert result["name"] == "test"
    assert result["lock"] is lock

    result_json = hlp.ascleandict(data, json_serializable=True)
    json.dumps(result_json)  # Should not raise TypeError


def test_ascleandict_tuple_and_namedtuple():
    """Test that tuple fields are returned as plain tuples, not the original subclass.

    type(obj)(items) fails for namedtuples because their constructor requires
    positional keyword arguments, not a single iterable.
    """
    from collections import namedtuple

    Point = namedtuple("Point", ["x", "y"])

    @dataclass
    class WithTuples:
        coords: tuple
        point: tuple
        name: str

    data = WithTuples(coords=(1, 2, 3), point=Point(x=4, y=5), name="test")
    result = hlp.ascleandict(data)
    assert result["name"] == "test"
    assert result["coords"] == (1, 2, 3)
    assert isinstance(result["coords"], tuple)
    # namedtuple is a tuple subclass — must come back as a plain tuple
    assert result["point"] == (4, 5)
    assert type(result["point"]) is tuple


def test_ascleandict_json_serializable_non_string_keys():
    """Test that json_serializable=True converts non-string dict keys to str.

    JSON only supports string keys. A dict with e.g. integer or tuple keys
    would raise TypeError on json.dumps even if all values are serializable.
    """
    import uuid
    from datetime import datetime

    @dataclass
    class WithComplexKeys:
        data: dict

    dt_key = datetime(2026, 4, 8)
    uuid_key = uuid.UUID("12345678-1234-5678-1234-567812345678")
    data = WithComplexKeys(
        data={
            42: "int key",
            (1, 2): "tuple key",
            dt_key: "datetime key",
            uuid_key: "uuid key",
        }
    )

    result = hlp.ascleandict(data, json_serializable=True)
    # All keys must be strings
    assert all(isinstance(k, str) for k in result["data"])
    assert result["data"]["42"] == "int key"
    assert result["data"]["(1, 2)"] == "tuple key"
    assert result["data"][str(dt_key)] == "datetime key"
    assert result["data"][str(uuid_key)] == "uuid key"
    json.dumps(result)  # Must not raise


def test_ascleandict_nested_cleanup_multiple_passes():
    """Test that ascleandict removes cascading empty nested structures."""

    @dataclass
    class DeepNested:
        value: str | None = None

    @dataclass
    class MidLevel:
        deep: DeepNested | None = None
        data: dict | None = None

    @dataclass
    class TopLevel:
        mid: MidLevel | None = None
        name: str = "test"

    # Create data where cleaning cascades:
    # - DeepNested.value = None gets removed
    # - MidLevel.deep becomes {} and gets removed
    # - MidLevel.data is already {} and gets removed
    # - MidLevel itself might become {} and gets removed
    data = TopLevel(
        name="test",
        mid=MidLevel(
            deep=DeepNested(value=None),  # Becomes {}
            data={"inner": None},  # Becomes {}
        ),
    )
    result = hlp.ascleandict(data)
    # The while loop should run multiple times, executing line 190
    assert result == {"name": "test"}


def test_ascleandict_circular_reference_in_list():
    """Test that ascleandict handles a circular list reference without crashing."""

    @dataclass
    class Node:
        items: list

    circular_list: list = []
    circular_list.append(circular_list)  # List references itself
    node = Node(items=circular_list)

    result = hlp.ascleandict(node)
    # The circular entry is replaced with a sentinel string, not empty, so kept
    assert result["items"] == ["<circular ref: list>"]


def test_ascleandict_circular_reference_in_dict():
    """Test that ascleandict handles a circular dict reference without crashing."""

    @dataclass
    class Container:
        data: dict

    circular_dict: dict = {}
    circular_dict["self"] = circular_dict  # Dict references itself
    container = Container(data=circular_dict)

    result = hlp.ascleandict(container)
    assert result["data"]["self"] == "<circular ref: dict>"


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


def test_fw_id_from_fw_file_passes():
    """Test FirmwareID from firmware file."""
    # Test with a valid firmware file
    test_file = "tests/files/fw-test-file.hex"
    res = hlp.fw_id_from_fw_file(test_file, contains="app-nrf9160-wmbus")
    assert res.name is not None
    assert "app-nrf9160-wmbus" in res.name


def test_fw_id_from_fw_file_fail():
    """Test FirmwareID from firmware file."""
    # Test with a valid firmware file
    test_file = "tests/files/fw-test-file.hex"
    with pytest.raises(ValueError):
        hlp.fw_id_from_fw_file(test_file, contains="non-existing")
    with pytest.raises(ValueError):
        hlp.fw_id_from_fw_file(test_file)
