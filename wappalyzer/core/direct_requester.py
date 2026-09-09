import threading
import time
from dataclasses import dataclass
from typing import Optional, Tuple
from urllib.parse import urljoin, urlsplit

import requests

from wappalyzer.core.requester import get_response
from wappalyzer.core.transport import DestinationBlocked, EgressPolicy, RequestPurpose
from wappalyzer.models import Endpoint, EvidenceLimit, TLSMetadata, TLSTrust

DEFAULT_MAX_REDIRECTS = 10


@dataclass(frozen=True)
class DirectResponseOutcome:
    response: Optional[requests.Response]
    limits: Tuple[EvidenceLimit, ...] = ()


def _origin(url):
    parsed = urlsplit(url)
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
        return None
    try:
        port = parsed.port or (443 if parsed.scheme.casefold() == "https" else 80)
    except ValueError:
        return None
    return parsed.scheme.casefold(), parsed.hostname.casefold(), port


def _harden_session(session):
    session.trust_env = False
    session.auth = None
    session.cert = None
    session.cookies.clear()
    session.headers.clear()
    session.params.clear()
    session.proxies.clear()


class DirectResponseFetcher:
    def __init__(
        self,
        *,
        endpoint,
        tls,
        timeout,
        max_redirects=DEFAULT_MAX_REDIRECTS,
        policy=None,
        session_factory=requests.Session,
        monotonic=time.monotonic,
    ):
        if not isinstance(endpoint, Endpoint):
            raise TypeError("endpoint must be an Endpoint")
        if not isinstance(tls, TLSMetadata):
            raise TypeError("tls must be TLSMetadata")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("timeout must be positive")
        if (
            isinstance(max_redirects, bool)
            or not isinstance(max_redirects, int)
            or max_redirects < 0
        ):
            raise ValueError("max_redirects must be a non-negative integer")
        if not callable(session_factory):
            raise TypeError("session_factory must be callable")
        if not callable(monotonic):
            raise TypeError("monotonic must be callable")
        if policy is not None and not isinstance(policy, EgressPolicy):
            raise TypeError("policy must be an EgressPolicy or None")
        self.endpoint = endpoint
        self.tls = tls
        self.timeout = float(timeout)
        self.max_redirects = max_redirects
        self.policy = policy or EgressPolicy((endpoint,))
        self.session_factory = session_factory
        self.monotonic = monotonic
        self._limits = set()
        self._lock = threading.Lock()

    @property
    def limits(self):
        rank = {limit: index for index, limit in enumerate(EvidenceLimit)}
        with self._lock:
            return tuple(sorted(self._limits, key=rank.__getitem__))

    def _add_limit(self, limit):
        with self._lock:
            self._limits.add(limit)

    def fetch(self, url, cookie=None, timeout=None, max_bytes=None):
        effective_timeout = self.timeout if timeout is None else min(self.timeout, timeout)
        started = self.monotonic()
        current = url
        target_origin = _origin(url)
        session = self.session_factory()
        _harden_session(session)
        response = None
        try:
            for redirect_count in range(self.max_redirects + 1):
                purpose = RequestPurpose.DIRECT if redirect_count == 0 else RequestPurpose.REDIRECT
                try:
                    self.policy.authorize(current, purpose)
                except DestinationBlocked:
                    self._add_limit(EvidenceLimit.POLICY)
                    return DirectResponseOutcome(response, self.limits)
                remaining = effective_timeout - (self.monotonic() - started)
                if remaining <= 0:
                    self._add_limit(EvidenceLimit.TIMER)
                    return DirectResponseOutcome(response, self.limits)
                verify = not (
                    self.tls.trust is TLSTrust.UNTRUSTED and _origin(current) == target_origin
                )
                response = get_response(
                    current,
                    cookie,
                    timeout=remaining,
                    verify=verify,
                    max_bytes=max_bytes,
                    session=session,
                    allow_redirects=False,
                )
                if response is None:
                    return DirectResponseOutcome(None, self.limits)
                location = response.headers.get("Location")
                if response.status_code not in {301, 302, 303, 307, 308} or not location:
                    return DirectResponseOutcome(response, self.limits)
                if redirect_count == self.max_redirects:
                    self._add_limit(EvidenceLimit.REDIRECT)
                    return DirectResponseOutcome(response, self.limits)
                current = urljoin(response.url, location)
            raise AssertionError("redirect loop escaped its explicit bound")
        finally:
            session.close()

    def __call__(self, url, cookie=None, timeout=None, max_bytes=None, **_kwargs):
        return self.fetch(
            url,
            cookie=cookie,
            timeout=timeout,
            max_bytes=max_bytes,
        ).response


__all__ = [
    "DEFAULT_MAX_REDIRECTS",
    "DirectResponseFetcher",
    "DirectResponseOutcome",
]
