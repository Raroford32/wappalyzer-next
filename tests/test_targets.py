import hashlib
import io

import pytest

from wappalyzer.models import Endpoint, TargetOccurrence
from wappalyzer.targets import MAX_TARGET_LINE_BYTES, TargetFileSummary, _port, ingest_targets


def _sha256(value):
    return hashlib.sha256(value).hexdigest()


class BoundedReadFile(io.BytesIO):
    """A binary file that rejects whole-file and line-sized reads."""

    def __init__(self, value):
        super().__init__(value)
        self.read_sizes = []

    def __iter__(self):
        raise AssertionError("ingestion must not rely on file line iteration")

    def read(self, size=-1):
        if size <= 0:
            raise AssertionError("ingestion must use bounded reads")
        self.read_sizes.append(size)
        return super().read(min(size, 7))

    def readline(self, size=-1):
        raise AssertionError("ingestion must not buffer a physical line")

    def readlines(self, hint=-1):
        raise AssertionError("ingestion must not materialize all lines")


class GuardedChunks:
    def __init__(self, chunks, maximum_reads):
        self._chunks = iter(chunks)
        self.maximum_reads = maximum_reads
        self.reads = 0

    def __iter__(self):
        return self

    def __next__(self):
        if self.reads >= self.maximum_reads:
            raise AssertionError("binary input was consumed ahead of emitted records")
        self.reads += 1
        return next(self._chunks)


def test_binary_file_is_read_incrementally_with_bom_crlf_and_outer_whitespace():
    lines = [
        b"\xef\xbb\xbf \t192.0.2.10:80 \r\n",
        b"  # ignored comment\r\n",
        b"\t \n",
        b" [2001:0DB8:0:0:0:0:0:10]:8443\t\n",
    ]
    raw = b"".join(lines)
    source = BoundedReadFile(raw)
    records = []

    summary = ingest_targets(source, records.append)

    assert source.read_sizes
    assert records == [
        TargetOccurrence(
            sequence=0,
            line_number=1,
            byte_offset=0,
            line_digest=_sha256(lines[0]),
            endpoint=Endpoint(address="192.0.2.10", port=80),
        ),
        TargetOccurrence(
            sequence=1,
            line_number=4,
            byte_offset=sum(map(len, lines[:3])),
            line_digest=_sha256(lines[3]),
            endpoint=Endpoint(address="2001:db8::10", port=8443),
        ),
    ]
    assert summary == TargetFileSummary(
        file_sha256=_sha256(raw),
        byte_count=len(raw),
        physical_line_count=4,
        ignored_line_count=2,
        occurrence_count=2,
        valid_occurrence_count=2,
        invalid_occurrence_count=0,
    )


def test_binary_chunk_iterator_may_split_bom_endpoints_and_crlf():
    raw = b"\xef\xbb\xbf192.0.2.1:80\r\n[2001:db8::1]:443"
    chunks = (
        raw[:1],
        raw[1:3],
        raw[3:18],
        raw[18:21],
        raw[21:30],
        raw[30:],
    )
    records = []

    summary = ingest_targets(iter(chunks), records.append)

    assert [record.endpoint for record in records] == [
        Endpoint(address="192.0.2.1", port=80),
        Endpoint(address="2001:db8::1", port=443),
    ]
    assert [record.byte_offset for record in records] == [0, raw.index(b"\n") + 1]
    assert summary.file_sha256 == _sha256(raw)
    assert summary.byte_count == len(raw)
    assert summary.physical_line_count == 2


def test_bom_is_accepted_only_as_the_first_bytes_of_the_file():
    lines = [
        b"\xef\xbb\xbf192.0.2.1:80\n",
        b"\xef\xbb\xbf192.0.2.2:80\n",
        b" \xef\xbb\xbf192.0.2.3:80\n",
        b"192.0.2.4:\xef\xbb\xbf80\n",
    ]
    records = []

    summary = ingest_targets(iter(lines), records.append)

    assert [record.endpoint for record in records] == [
        Endpoint(address="192.0.2.1", port=80),
        None,
        None,
        None,
    ]
    assert [record.line_digest for record in records] == [_sha256(line) for line in lines]
    assert summary.valid_occurrence_count == 1
    assert summary.invalid_occurrence_count == 3


def test_line_limit_and_validity_are_enforced_before_ignoring_comments_and_blanks():
    exact_endpoint = b"192.0.2.1:80" + b" " * (MAX_TARGET_LINE_BYTES - len(b"192.0.2.1:80"))
    exact_comment = b"#" + b"x" * (MAX_TARGET_LINE_BYTES - 1)
    exact_blank = b" " * MAX_TARGET_LINE_BYTES
    lines = [
        exact_endpoint + b"\r\n",
        exact_comment + b"\n",
        exact_blank + b"\n",
        b"#" + b"x" * MAX_TARGET_LINE_BYTES + b"\n",
        b" " * (MAX_TARGET_LINE_BYTES + 1) + b"\n",
        b"# invalid utf-8: \xff\n",
        b"  # nul follows: \x00\n",
    ]
    records = []

    summary = ingest_targets(iter(lines), records.append)

    assert MAX_TARGET_LINE_BYTES == 1024
    assert len(records) == 5
    assert records[0].endpoint == Endpoint(address="192.0.2.1", port=80)
    assert all(record.endpoint is None for record in records[1:])
    assert [record.line_number for record in records] == [1, 4, 5, 6, 7]
    assert [record.sequence for record in records] == list(range(5))
    assert [record.line_digest for record in records] == [
        _sha256(lines[index]) for index in (0, 3, 4, 5, 6)
    ]
    assert summary.ignored_line_count == 2
    assert summary.valid_occurrence_count == 1
    assert summary.invalid_occurrence_count == 4


@pytest.mark.parametrize(
    "raw",
    [
        b"example.com:80\n",
        b"http://192.0.2.1:80\n",
        b"https://[2001:db8::1]:443\n",
        b"192.0.2.0/24:80\n",
        b"192.0.2.1:80/path\n",
        b"user@192.0.2.1:80\n",
        b"192.0.2.1:80?query=value\n",
        b"192.0.2.1:80#fragment\n",
        b"[fe80::1%eth0]:80\n",
        b"2001:db8::1:443\n",
        b"01.2.3.4:80\n",
        b"192.0.2.1\n",
        b"192.0.2.1:\n",
        b"[2001:db8::1]\n",
        b"[2001:db8::1]:\n",
        b"192.0.2.1:0\n",
        b"192.0.2.1:65536\n",
        b"192.0.2.1:http\n",
        b"192.0.2.1:-1\n",
        b"192.0.2.1 :80\n",
        b"192.0.2.1: 80\n",
        b"[2001:db8::1] :443\n",
        b"[2001:db8::1]: 443\n",
        b"[2001:db8::1:443\n",
        b"2001:db8::1]:443\n",
        b"[2001:db8::1]443\n",
        b"192.0.2.1:80 # inline comments are invalid\n",
        b"256.0.0.1:80\n",
        b"[2001:db8::1]:0\n",
        b"[not-an-ip]:443\n",
    ],
)
def test_invalid_endpoint_grammar_emits_an_invalid_occurrence(raw):
    records = []

    summary = ingest_targets(iter((raw,)), records.append)

    assert records == [
        TargetOccurrence(
            sequence=0,
            line_number=1,
            byte_offset=0,
            line_digest=_sha256(raw),
            endpoint=None,
        )
    ]
    assert summary.occurrence_count == 1
    assert summary.valid_occurrence_count == 0
    assert summary.invalid_occurrence_count == 1


def test_valid_ipv4_and_bracketed_ipv6_are_normalized_and_duplicates_are_lossless():
    lines = [
        b"255.255.255.255:65535\n",
        b"[2001:0DB8:0000:0000:0000:0000:0000:0001]:1\n",
        b"[2001:db8::1]:443\n",
        b"[2001:0db8:0:0:0:0:0:1]:443\n",
    ]
    records = []

    summary = ingest_targets(iter(lines), records.append)

    assert [record.endpoint for record in records] == [
        Endpoint(address="255.255.255.255", port=65535),
        Endpoint(address="2001:db8::1", port=1),
        Endpoint(address="2001:db8::1", port=443),
        Endpoint(address="2001:db8::1", port=443),
    ]
    assert records[2] is not records[3]
    assert records[2].endpoint == records[3].endpoint
    assert [record.sequence for record in records] == [0, 1, 2, 3]
    assert summary.occurrence_count == 4
    assert summary.valid_occurrence_count == 4


def test_source_identity_uses_physical_lines_offsets_and_contiguous_occurrence_sequence():
    lines = [
        b"\n",
        b"192.0.2.1:80\r\n",
        b" # ignored\n",
        b"not-an-ip:80\n",
        b"[::1]:443",
    ]
    records = []

    summary = ingest_targets(iter(lines), records.append)

    assert [record.sequence for record in records] == [0, 1, 2]
    assert [record.line_number for record in records] == [2, 4, 5]
    assert [record.byte_offset for record in records] == [
        len(lines[0]),
        sum(map(len, lines[:3])),
        sum(map(len, lines[:4])),
    ]
    assert [record.line_digest for record in records] == [
        _sha256(lines[index]) for index in (1, 3, 4)
    ]
    assert [record.endpoint for record in records] == [
        Endpoint(address="192.0.2.1", port=80),
        None,
        Endpoint(address="::1", port=443),
    ]
    assert summary.physical_line_count == 5
    assert summary.ignored_line_count == 2


def test_invalid_utf8_nul_and_oversized_lines_retain_only_bounded_identity_metadata():
    lines = [
        b"\xffsecret-input\n",
        b"192.0.2.1:80\xe2\x82\n",
        b"192.0.2.1:80\x00secret-input\n",
        b"secret-input" + b"x" * MAX_TARGET_LINE_BYTES + b"\n",
    ]
    records = []

    ingest_targets(iter(lines), records.append)

    assert all(isinstance(record, TargetOccurrence) for record in records)
    assert all(record.endpoint is None for record in records)
    assert [record.line_digest for record in records] == [_sha256(line) for line in lines]
    for record in records:
        assert set(vars(record)) == {
            "sequence",
            "line_number",
            "byte_offset",
            "line_digest",
            "endpoint",
        }
        assert "secret-input" not in repr(record)


@pytest.mark.parametrize(
    ("raw", "physical_lines", "ignored_lines"),
    [
        (b"", 0, 0),
        (b"\xef\xbb\xbf\n  # one\r\n\t \n", 3, 3),
    ],
)
def test_empty_and_comment_only_inputs_have_a_complete_zero_occurrence_summary(
    raw,
    physical_lines,
    ignored_lines,
):
    records = []

    summary = ingest_targets(iter((raw,)) if raw else iter(()), records.append)

    assert records == []
    assert summary == TargetFileSummary(
        file_sha256=_sha256(raw),
        byte_count=len(raw),
        physical_line_count=physical_lines,
        ignored_line_count=ignored_lines,
        occurrence_count=0,
        valid_occurrence_count=0,
        invalid_occurrence_count=0,
    )


def test_record_sink_backpressure_prevents_eager_binary_input_consumption():
    class StopAfterFirstRecord(Exception):
        pass

    source = GuardedChunks(
        (
            b"192.0.2.1:80\n",
            b"192.0.2.2:80\n",
        ),
        maximum_reads=1,
    )
    records = []

    def stop_after_first(record):
        records.append(record)
        raise StopAfterFirstRecord

    with pytest.raises(StopAfterFirstRecord):
        ingest_targets(source, stop_after_first)

    assert source.reads == 1
    assert [record.endpoint for record in records] == [Endpoint(address="192.0.2.1", port=80)]


def test_port_parser_rejects_non_numeric_and_out_of_range_text():
    assert _port("not-a-port") is None
    assert _port("0") is None
    assert _port("65536") is None
    assert _port("443") == 443


@pytest.mark.parametrize(
    ("source", "message"),
    [
        pytest.param(
            object(),
            "target source must be a binary file or iterable of chunks",
            id="non-iterable",
        ),
        pytest.param(
            iter(("192.0.2.1:80\n",)),
            "target source must provide binary chunks",
            id="text-iterator",
        ),
        pytest.param(
            io.StringIO("192.0.2.1:80\n"),
            "target source must provide binary chunks",
            id="text-file",
        ),
        pytest.param(
            iter((memoryview(b"abcd")[::2],)),
            "target source chunks must be contiguous bytes",
            id="non-contiguous-memoryview",
        ),
    ],
)
def test_target_source_requires_binary_contiguous_chunks(source, message):
    with pytest.raises(TypeError, match=message):
        ingest_targets(source, lambda record: None)


def test_target_sink_must_be_callable():
    with pytest.raises(TypeError, match="target sink must be callable"):
        ingest_targets(iter(()), None)


def test_empty_chunks_are_ignored_without_ending_the_stream():
    records = []

    summary = ingest_targets(
        iter((b"", b"192.0.2.1:80\n", b"")),
        records.append,
    )

    assert [record.endpoint for record in records] == [Endpoint("192.0.2.1", 80)]
    assert summary.byte_count == len(b"192.0.2.1:80\n")
    assert summary.physical_line_count == 1


@pytest.mark.parametrize(
    ("chunks", "expected_endpoint"),
    [
        pytest.param(
            (b"192.0.2.1:80\r", b"x\n"),
            None,
            id="carriage-return-before-non-newline",
        ),
        pytest.param(
            (b"192.0.2.1:80\r",),
            Endpoint("192.0.2.1", 80),
            id="unterminated-carriage-return",
        ),
        pytest.param(
            (b" " * MAX_TARGET_LINE_BYTES + b"\r", b"x\n"),
            None,
            id="full-retention-buffer",
        ),
    ],
)
def test_split_and_unterminated_carriage_returns_follow_line_classification(
    chunks,
    expected_endpoint,
):
    records = []
    raw = b"".join(chunks)

    summary = ingest_targets(iter(chunks), records.append)

    assert records == [
        TargetOccurrence(
            sequence=0,
            line_number=1,
            byte_offset=0,
            line_digest=_sha256(raw),
            endpoint=expected_endpoint,
        )
    ]
    assert summary.physical_line_count == 1
    assert summary.valid_occurrence_count == int(expected_endpoint is not None)
    assert summary.invalid_occurrence_count == int(expected_endpoint is None)
