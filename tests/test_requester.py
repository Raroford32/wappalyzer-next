import logging

import requests

from wappalyzer.core import requester


class FakeResponse:
    def __init__(self, chunks):
        self.chunks = chunks
        self.closed = False
        self._content = b""
        self._content_consumed = False

    def iter_content(self, chunk_size):
        assert chunk_size > 0
        yield from self.chunks

    def close(self):
        self.closed = True


class FakeSession:
    def __init__(self, response):
        self.response = response
        self.kwargs = None

    def get(self, url, **kwargs):
        self.kwargs = {"url": url, **kwargs}
        return self.response


def test_request_defaults_to_verified_tls_and_bounded_timeouts():
    response = FakeResponse([b"hello", b" world"])
    session = FakeSession(response)

    result = requester.get_response(
        "https://example.test",
        timeout=7,
        session=session,
    )

    assert result._content == b"hello world"
    assert session.kwargs["verify"] is True
    assert session.kwargs["timeout"].connect_timeout == 5.0
    assert session.kwargs["timeout"].total == 7
    assert session.kwargs["stream"] is True


def test_response_size_limit_closes_connection(caplog):
    response = FakeResponse([b"1234", b"5678"])
    session = FakeSession(response)
    caplog.set_level(logging.DEBUG, logger=requester.__name__)

    result = requester.get_response(
        "https://example.test",
        max_bytes=4,
        session=session,
    )

    assert result is None
    assert response.closed
    assert "exceeded 4 bytes" in caplog.text


def test_stream_failure_closes_connection():
    class FailingResponse(FakeResponse):
        def iter_content(self, chunk_size):
            raise requests.exceptions.ConnectionError("stream failed")
            yield

    response = FailingResponse([])

    assert (
        requester.get_response(
            "https://example.test",
            session=FakeSession(response),
        )
        is None
    )
    assert response.closed


def test_total_timeout_applies_while_streaming(monkeypatch):
    response = FakeResponse([b"late"])
    timestamps = iter((0.0, 8.0))
    monkeypatch.setattr(requester.time, "monotonic", lambda: next(timestamps))

    assert (
        requester.get_response(
            "https://example.test",
            timeout=7,
            session=FakeSession(response),
        )
        is None
    )
    assert response.closed
