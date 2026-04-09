import binascii
import json
import logging
import logging.handlers
import os
import re
import threading
from dataclasses import fields, is_dataclass
from datetime import datetime
from typing import Any

from lob_hlpr.lib_types import FirmwareID


def enable_windows_ansi_support():  # pragma: no cover
    """Try to enable ANSI escape sequence support on Windows.

    Works on Windows 10+.
    """
    if os.name != "nt":
        return True  # Non-Windows always supports ANSI

    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32

        # Enable Virtual Terminal Processing
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE = -11
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            new_mode = (
                mode.value | 0x0004
            )  # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            if kernel32.SetConsoleMode(handle, new_mode):
                return True
    except Exception:
        pass

    return False


# Determine if ANSI colors will work
_USE_COLOR = enable_windows_ansi_support()

# Lock protecting the one-time setup of rotating file handlers in lob_print
_log_handler_lock = threading.Lock()


class LobHlpr:
    """Helper functions for Lobaro tools."""

    @staticmethod
    def sn_vid_pid_to_regex(
        sn: str | None = None, vid: str | None = None, pid: str | None = None
    ):
        r"""Convert serial number, VID and PID to regex.

        This is a convenience function for serial.tools.list_ports.grep.
        Some examples of output that one would get is:
        port: /dev/ttyUSB0,
        desc: CP2102 USB to UART Bridge Controller -
            CP2102 USB to UART Bridge Controller,
        hwid: USB VID:PID=10C4:EA60 SER=KW-0001 LOCATION=1-1

        Args:
            sn (str): The serial number to search for.
            vid (str): The VID to search for.
            pid (str): The PID to search for.

        Returns:
            str: The regex string.

        Examples:
            >>> tst = LobHlpr.sn_vid_pid_to_regex
            >>> print(tst(sn="KW-0001", vid="10C4", pid="EA60"))
            VID:PID=10C4:EA60.+SER=KW\-0001
            >>> print(tst(sn="KW-0001"))
            VID:PID=.*:.*.+SER=KW\-0001
            >>> print(tst(pid="EA60", vid="10C4"))
            VID:PID=10C4:EA60.+SER=.*
            >>> print(tst(sn="KW-0001", vid="10C4"))
            VID:PID=10C4:.*.+SER=KW\-0001
            >>> print(tst(sn="KW-0001", pid="EA60"))
            VID:PID=.*:EA60.+SER=KW\-0001
            >>> print(tst(sn="SPECIAL-.*"))
            VID:PID=.*:.*.+SER=SPECIAL\-\.\*
        """
        if sn is None:
            sn = ".*"
        else:
            sn = re.escape(sn)
        return f"VID:PID={vid or '.*'}:{pid or '.*'}.+SER={sn}"

    @staticmethod
    def _print_color(*args, color=None, **kwargs):
        """Print with color if supported."""
        # ANSI color codes
        RESET = "\033[0m"
        RED = "\033[31m"
        GREEN = "\033[32m"
        YELLOW = "\033[33m"
        if color is None or not _USE_COLOR:
            print(*args, flush=True, **kwargs)
            return
        text = kwargs.get("sep", " ").join(str(a) for a in args)
        color = color.lower()
        code = None
        if "red" == color:
            code = RED
        elif "green" == color:
            code = GREEN
        elif "yellow" == color:
            code = YELLOW
        if code is not None:
            print(f"{code}{text}{RESET}", flush=True, **kwargs)
        else:
            print(text, flush=True, **kwargs)

    @staticmethod
    def lob_print(log_path: str, *args, **kwargs):
        """Print to the console and log to a file.

        The log file is rotated when it reaches 256MB and the last two
        log files are kept. This can write all log messages to the log file
        only if the log handlers are set (i.e. basicConfig loglevel is Debug).

        Args:
            log_path: The path to the log file.
            *args: Arguments to print.
            **kwargs: Additional keyword arguments.
                color (str, optional): If provided, prints the message in color
                    to the console. Supported values are "red", "green", and "yellow".
                    If colors are not supported by the terminal, output will be
                    uncolored.
        """
        color = kwargs.pop("color", None)
        sep = kwargs.pop("sep", " ")
        kwargs.pop("end", None)  # consumed by print, not meaningful for logging
        LobHlpr._print_color(*args, color=color, sep=sep, **kwargs)

        # get the directory from the log_path
        log_dir = os.path.dirname(log_path)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        logger = logging.getLogger("lob_hlpr")
        logger.propagate = False  # Prevent propagation to root logger
        logger.setLevel(logging.INFO)
        root_logger = logging.getLogger()

        abs_log_path = os.path.abspath(log_path)
        with _log_handler_lock:
            # Re-check inside the lock to avoid a TOCTOU race when multiple
            # threads call lob_print concurrently with the same log_path.
            has_file_handler = any(
                isinstance(h, logging.handlers.RotatingFileHandler)
                and h.baseFilename == abs_log_path
                for h in root_logger.handlers
            )

            if not has_file_handler:
                ch = logging.handlers.RotatingFileHandler(
                    log_path, maxBytes=268435456, backupCount=2
                )

                formatter = logging.Formatter(
                    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
                )

                ch.setFormatter(formatter)

                # Add to root_logger so all other loggers inherit it via
                # propagation.  Also add directly to logger because logger has
                # propagate=False, so it would not reach root_logger otherwise.
                root_logger.addHandler(ch)
                logger.addHandler(ch)

        message = sep.join(str(a) for a in args)
        logger.info("%s", message)

    @staticmethod
    def ascleandict(
        dclass: object,
        remove_false: bool = False,
        json_serializable: bool = False,
    ) -> dict[str, Any]:
        """Convert a dataclass to a dictionary and remove None values.

        Args:
            dclass: The dataclass instance to convert.
            remove_false: If True, also remove boolean fields that are False.
            json_serializable: If True, convert all non-serializable types to strings.

        Returns:
            dict: The cleaned dictionary without empty values.

        Raises:
            TypeError: If dclass is not a dataclass instance.
        """
        if not is_dataclass(dclass) or isinstance(dclass, type):
            raise TypeError(
                f"ascleandict() should be called on dataclass instances, "
                f"not {type(dclass)!r}"
            )

        def _keep(v) -> bool:
            if v is None:
                return False
            if isinstance(v, (list, dict)) and not v:
                return False
            if remove_false and v is False:
                return False
            return True

        def _convert(obj: object) -> Any:
            if is_dataclass(obj) and not isinstance(obj, type):
                result = {}
                for f in fields(obj):
                    converted = _convert(getattr(obj, f.name))
                    if _keep(converted):
                        result[f.name] = converted
                return result
            if isinstance(obj, dict):
                result = {}
                for k, v in obj.items():
                    converted = _convert(v)
                    if _keep(converted):
                        key = (
                            str(k)
                            if json_serializable and not isinstance(k, str)
                            else k
                        )
                        result[key] = converted
                return result
            if isinstance(obj, (list, tuple)):
                items = [_convert(item) for item in obj]
                items = [item for item in items if _keep(item)]
                return tuple(items) if isinstance(obj, tuple) else items
            if json_serializable:
                try:
                    json.dumps(obj)
                except (TypeError, OverflowError):
                    return str(obj)
            return obj

        return _convert(dclass)

    @staticmethod
    def unix_timestamp() -> int:
        """Unix timestamp - milliseconds since 1970.

        Example: 1732266521241
        """
        return int(datetime.now().timestamp() * 1000)

    @staticmethod
    def format_unix_timestamp(timestamp) -> str:
        """Formatted unix timestamp.

        Example: 2024-11-22_10-18-24
        """
        return datetime.fromtimestamp(timestamp / 1000).strftime("%Y-%m-%d_%H-%M-%S")

    @staticmethod
    def parse_dmc(dmc):
        """Parse the dmc scanned by the barcode scanner for the PCB.

        Example input from scanner MPP-OR019504_1-00781 or MPP-M0011554-OR019504_1-00781

        Args:
            dmc (str): The scanned dmc, digital manufacturer code.

        Returns:
            Tuple[str, str, str, str]: The erp_prod_number, batch_number,
                pcba_serial_number, article_number.
        """
        article_number = None
        chunks: list[str] = dmc.split("-")
        if len(chunks) == 4:
            # This: MPP-M0011554-OR019504_1-00781
            article_number = chunks.pop(1)
            # Changes to MPP-OR019504_1-00781
        if chunks[0] != "MPP":
            raise ValueError(f"Invalid DMC format: {dmc}, must start with MPP")
        # We want the OR019504 part
        erp_prod_number = chunks[0] + "-" + re.split("_", chunks[1])[0]

        # Now we want the 1 part
        batch_number = re.split("_", chunks[1])[1]

        # Now we want the 00781 part
        pcba_serial_number = chunks[2]

        return erp_prod_number, batch_number, pcba_serial_number, article_number

    @staticmethod
    def extract_identifier_from_hexfile(hex_str: str):
        """Extract the identifier from a hex file.

        Args:
            hex_str (str): The hex file to search in.

        Returns:
            list: The identifiers found in the hex file.
        """
        r = re.compile(r"^:([0-9a-fA-F]{10,})")
        segments = []
        segment = bytearray()
        segment_address = None
        for idx, line in enumerate(hex_str.split("\n")):
            line = line.replace("\r", "")
            if line == "":
                continue
            m = r.match(line)
            if not m:
                raise ValueError(f"Invalid line {idx} in hexfile: {line}")
            b = binascii.unhexlify(m.group(1))
            if len(b) != b[0] + 5:
                raise ValueError(f"Invalid line in hexfile: {line}")
            addr = int.from_bytes(b[1:3], byteorder="big")
            rec_type = b[3]
            data = b[4:-1]
            if rec_type == 0x04:
                # Extended address
                # (higher 2 bytes of address for following data records)
                extended_address = int.from_bytes(data, byteorder="big")
            elif rec_type == 0x00:
                # Data record
                full_address = (extended_address << 16) | addr
                if segment_address is None:
                    segment_address = full_address
                    segment = bytearray(data)
                elif full_address == segment_address + len(segment):
                    segment.extend(data)
                else:
                    segments.append((segment_address, segment))
                    segment = bytearray(data)
                    segment_address = full_address
            elif rec_type == 0x01:
                # End of file
                segments.append((segment_address, segment))

        identifiers = []
        hexinfo_regex = re.compile(b">==HEXINFO==>(.*?)<==HEXINFO==<")
        for seg in segments:
            mat = hexinfo_regex.search(seg[1])
            if mat:
                identifiers.append(mat.groups()[0].decode())
        if len(identifiers) == 0:
            raise ValueError("No firmware identifier found in hexfile")
        return identifiers

    @staticmethod
    def fw_id_from_fw_file(fw_file: str, contains: str | None = None) -> FirmwareID:
        """Extract the firmware identifier from a firmware file.

        Args:
            fw_file (str): The path to the firmware file.
            contains (str): Optional filter to make sure result contains.

        Returns:
            FirmwareID: The firmware identifier.

        Raises:
            ValueError: If no or too many firmware identifier is found in the file.
        """
        with open(fw_file) as f:
            hex_str = f.read()
        identifiers = LobHlpr.extract_identifier_from_hexfile(hex_str)
        if contains:
            identifiers = [i for i in identifiers if contains in i]
        if not identifiers:
            raise ValueError(f"No firmware identifier found in {fw_file}")
        if len(identifiers) > 1:
            raise ValueError(
                f"Multiple firmware identifiers found in {fw_file}: {identifiers}"
            )
        return FirmwareID(identifiers[0])
