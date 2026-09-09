import hashlib
import ipaddress
import re
from dataclasses import dataclass
from typing import Callable, Iterator, Optional, Tuple

from wappalyzer.models import Endpoint, TargetOccurrence

MAX_TARGET_LINE_BYTES = 1024

_READ_CHUNK_BYTES = 64 * 1024
_UTF8_BOM = b"\xef\xbb\xbf"
_IPV4_TARGET = re.compile(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3}):([0-9]+)")
_IPV6_TARGET = re.compile(r"\[([^\[\]]+)\]:([0-9]+)")


@dataclass(frozen=True)
class TargetFileSummary:
    file_sha256: str
    byte_count: int
    physical_line_count: int
    ignored_line_count: int
    occurrence_count: int
    valid_occurrence_count: int
    invalid_occurrence_count: int


class _LineAccumulator:
    def __init__(self, byte_offset: int) -> None:
        self.byte_offset = byte_offset
        self.payload_byte_count = 0
        self.payload = bytearray()
        self.pending_carriage_return = False
        self.hasher = hashlib.sha256()

    def update_hash(self, chunk: memoryview, start: int, end: int) -> None:
        self.hasher.update(chunk[start:end])

    def consume_fragment(self, chunk: memoryview, start: int, end: int) -> None:
        if start == end:
            return

        if self.pending_carriage_return:
            self._retain_byte(13)
            self.pending_carriage_return = False

        if chunk[end - 1] == 13:
            end -= 1
            self.pending_carriage_return = True

        self._retain(chunk, start, end)

    def finish_terminated(self) -> None:
        self.pending_carriage_return = False

    def finish_unterminated(self) -> None:
        if self.pending_carriage_return:
            self._retain_byte(13)
            self.pending_carriage_return = False

    def _retain(self, chunk: memoryview, start: int, end: int) -> None:
        length = end - start
        self.payload_byte_count += length
        available = MAX_TARGET_LINE_BYTES - len(self.payload)
        retained = min(length, max(0, available))
        if retained:
            self.payload.extend(chunk[start : start + retained])

    def _retain_byte(self, value: int) -> None:
        self.payload_byte_count += 1
        if len(self.payload) < MAX_TARGET_LINE_BYTES:
            self.payload.append(value)


def _chunk_view(chunk: object) -> memoryview:
    if not isinstance(chunk, (bytes, bytearray, memoryview)):
        raise TypeError("target source must provide binary chunks")

    try:
        return memoryview(chunk).cast("B")
    except TypeError as error:
        raise TypeError("target source chunks must be contiguous bytes") from error


def _source_chunks(source: object) -> Iterator[memoryview]:
    read = getattr(source, "read", None)
    if callable(read):
        while True:
            chunk = _chunk_view(read(_READ_CHUNK_BYTES))
            if not chunk:
                return
            yield chunk

    try:
        chunks = iter(source)  # type: ignore[arg-type]
    except TypeError as error:
        raise TypeError("target source must be a binary file or iterable of chunks") from error

    for chunk in chunks:
        view = _chunk_view(chunk)
        if view:
            yield view


def _port(value: str) -> Optional[int]:
    try:
        port = int(value)
    except ValueError:
        return None
    return port if 1 <= port <= 65535 else None


def _parse_endpoint(value: str) -> Optional[Endpoint]:
    ipv4_match = _IPV4_TARGET.fullmatch(value)
    if ipv4_match is not None:
        address, port_text = ipv4_match.groups()
        octets = address.split(".")
        if any(len(octet) > 1 and octet.startswith("0") for octet in octets):
            return None
        if any(int(octet) > 255 for octet in octets):
            return None

        port = _port(port_text)
        if port is None:
            return None
        return Endpoint(address=str(ipaddress.IPv4Address(address)), port=port)

    ipv6_match = _IPV6_TARGET.fullmatch(value)
    if ipv6_match is None:
        return None

    address, port_text = ipv6_match.groups()
    if "%" in address:
        return None

    port = _port(port_text)
    if port is None:
        return None

    try:
        normalized_address = str(ipaddress.IPv6Address(address))
    except ValueError:
        return None
    return Endpoint(address=normalized_address, port=port)


def _classify_line(
    line: _LineAccumulator,
) -> Tuple[bool, Optional[Endpoint]]:
    if line.payload_byte_count > MAX_TARGET_LINE_BYTES:
        return False, None

    payload = bytes(line.payload)
    if line.byte_offset == 0 and payload.startswith(_UTF8_BOM):
        payload = payload[len(_UTF8_BOM) :]
    if _UTF8_BOM in payload or b"\x00" in payload:
        return False, None

    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return False, None

    text = text.strip()
    if not text or text.startswith("#"):
        return True, None
    return False, _parse_endpoint(text)


def _find_newline(chunk: memoryview, start: int) -> int:
    for index in range(start, len(chunk)):
        if chunk[index] == 10:
            return index
    return -1


def ingest_targets(
    source: object,
    sink: Callable[[TargetOccurrence], object],
) -> TargetFileSummary:
    if not callable(sink):
        raise TypeError("target sink must be callable")

    file_hasher = hashlib.sha256()
    byte_count = 0
    physical_line_count = 0
    ignored_line_count = 0
    occurrence_count = 0
    valid_occurrence_count = 0
    invalid_occurrence_count = 0
    line = _LineAccumulator(byte_offset=0)

    def finish_line(terminated: bool) -> None:
        nonlocal ignored_line_count
        nonlocal invalid_occurrence_count
        nonlocal occurrence_count
        nonlocal valid_occurrence_count

        if terminated:
            line.finish_terminated()
        else:
            line.finish_unterminated()

        ignored, endpoint = _classify_line(line)
        if ignored:
            ignored_line_count += 1
            return

        occurrence = TargetOccurrence(
            sequence=occurrence_count,
            line_number=physical_line_count,
            byte_offset=line.byte_offset,
            line_digest=line.hasher.hexdigest(),
            endpoint=endpoint,
        )
        sink(occurrence)
        occurrence_count += 1
        if endpoint is None:
            invalid_occurrence_count += 1
        else:
            valid_occurrence_count += 1

    for chunk in _source_chunks(source):
        chunk_offset = byte_count
        file_hasher.update(chunk)
        byte_count += len(chunk)
        fragment_start = 0

        while fragment_start < len(chunk):
            newline = _find_newline(chunk, fragment_start)
            if newline < 0:
                line.update_hash(chunk, fragment_start, len(chunk))
                line.consume_fragment(chunk, fragment_start, len(chunk))
                break

            line.update_hash(chunk, fragment_start, newline + 1)
            line.consume_fragment(chunk, fragment_start, newline)
            physical_line_count += 1
            finish_line(terminated=True)

            fragment_start = newline + 1
            line = _LineAccumulator(byte_offset=chunk_offset + fragment_start)

    if byte_count > line.byte_offset:
        physical_line_count += 1
        finish_line(terminated=False)

    return TargetFileSummary(
        file_sha256=file_hasher.hexdigest(),
        byte_count=byte_count,
        physical_line_count=physical_line_count,
        ignored_line_count=ignored_line_count,
        occurrence_count=occurrence_count,
        valid_occurrence_count=valid_occurrence_count,
        invalid_occurrence_count=invalid_occurrence_count,
    )
