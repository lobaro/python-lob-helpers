import binascii
import logging
import logging.handlers
import os
import re
from dataclasses import asdict
from datetime import datetime

from lob_hlpr.lib_types import FirmwareID


class LobHlpr:
    """Helper functions for Lobaro tools."""

    LOB_PRINT_LOG_PATH = None

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
    def lob_print(log_path: str | None, *args, **kwargs):
        """Print to the console and log to a file.

        The log file is rotated when it reaches 256MB and the last two
        log files are kept. This can write all log messages to the log file
        only if the log handlers are set (i.e. basicConfig loglevel is Debug).
        """
        print(*args, flush=True, **kwargs)
        if log_path is None and LobHlpr.LOB_PRINT_LOG_PATH is None:
            return
        # get the directory from the log_path
        log_dir = os.path.dirname(log_path)
        os.makedirs(log_dir, exist_ok=True)
        logger = logging.getLogger("lob_hlpr")
        # Check to see if the file handler was already set up for root logger
        logger.propagate = False  # Prevent propagation to root logger
        logger.setLevel(logging.INFO)
        root_logger = logging.getLogger()

        # Check if our file handler is already attached to root logger
        has_file_handler = any(
            isinstance(h, logging.handlers.RotatingFileHandler)
            and h.baseFilename == os.path.abspath(log_path)
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

            # Add handler to root logger so all loggers inherit it
            root_logger.addHandler(ch)
            logger.addHandler(ch)

        logger.info(*args, **kwargs)

    @staticmethod
    def ascleandict(dclass, remove_false=False):
        """Convert a dataclass to a dictionary and remove None values."""
        return asdict(
            dclass,
            dict_factory=lambda x: {
                k: v
                for (k, v) in x
                if (v is not None)
                and not (isinstance(v, list) and len(v) == 0)
                and not (isinstance(v, dict) and len(v) == 0)
                and not (remove_false and (isinstance(v, bool) and v is False))
            },
        )

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
        # We want the OR019504 part
        erp_prod_number = chunks[0] + "-" + re.split("_", chunks[1])[0]

        # Now we want the 1 part
        batch_number = re.split("_", chunks[1])[1]

        # Now we want the 00781 part
        pcba_serial_number = chunks[2]

        return erp_prod_number, batch_number, pcba_serial_number, article_number

    @staticmethod
    def verify_dmc_prefix(dmc: str, allowed_prefixes: list[str]) -> str:
        """Verify if the DMC starts with an allowed prefix.

        If it does, cut any repeated scans
        (e.g. MPP-OR019504_1-00781MPP-OR019504_1-00781)
        to one DMC and return it, otherwise return an empty string.

        Args:
            dmc (str): The scanned DMC, digital manufacturer code.
            allowed_prefixes (list[str]): List of allowed DMC prefixes.

        Returns:
            str: The (first) DMC if it starts with an allowed prefix,
                otherwise an empty string.
        """
        if not allowed_prefixes:
            # No prefixes configured, so no check needed
            LobHlpr.lob_print(
                LobHlpr.LOB_PRINT_LOG_PATH,
                "No DMC prefixes configured, skipping prefix check.",
            )
            return dmc
        for prefix in allowed_prefixes:
            if dmc.startswith(prefix):
                return dmc
        LobHlpr.lob_print(
            LobHlpr.LOB_PRINT_LOG_PATH,
            f"DMC {dmc} does not start with any of the allowed prefixes: "
            f"{allowed_prefixes}",
        )
        return ""

    @staticmethod
    def verify_dmc_customer(dmc: str, allowed_suffix: list[str]) -> bool:
        """Verify if the DMC is allowed for the current customer config.

        This is done by checking if the article number ends with letter(s),
        and if customer letter(s) are configured, it must match an allowed string.

        Args:
            dmc (str): The scanned DMC, digital manufacturer code.
            allowed_suffix (list[str]): List of allowed customer article suffixes.

        Returns:
            bool: True if the DMC is valid for the customer, False otherwise.
        """
        _, _, serial_no, article_no = LobHlpr.parse_dmc(dmc)
        # serial no should be all digits,
        # otherwise it may contain the nrf 2did as well
        if not serial_no.isdigit():
            LobHlpr.lob_print(
                LobHlpr.LOB_PRINT_LOG_PATH,
                f"Serial number {serial_no} in DMC {dmc} is not all digits!",
            )
            return False
        if not allowed_suffix:
            # No customer letters configured, so no check needed
            LobHlpr.lob_print(
                LobHlpr.LOB_PRINT_LOG_PATH,
                "No customer letters configured, skipping customer check.",
            )
            return True
        if not article_no:
            # No article number to check
            LobHlpr.lob_print(
                LobHlpr.LOB_PRINT_LOG_PATH,
                "No article number found in DMC, skipping customer check.",
            )
            return True
        if not article_no[-1].isalpha():
            # No letters at the end, so no customer letters to check
            LobHlpr.lob_print(
                LobHlpr.LOB_PRINT_LOG_PATH,
                f"No customer letters in article number {article_no}, "
                f"skipping customer check.",
            )
            return True
        article_cust_letters = re.match(r".*([^0-9\W]+)$", article_no)
        cust_letters = article_cust_letters.group(1)  # type: ignore[union-attr]
        if cust_letters not in allowed_suffix:
            LobHlpr.lob_print(
                LobHlpr.LOB_PRINT_LOG_PATH,
                f"Customer letters {cust_letters} in article number {article_no} "
                f"are not allowed, must be one of {allowed_suffix}.",
            )
            return False
        LobHlpr.lob_print(
            LobHlpr.LOB_PRINT_LOG_PATH,
            f"Customer letters {cust_letters} in article number {article_no} "
            f"are allowed, continuing.",
        )
        return True

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
