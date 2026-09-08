import os
import sys
import threading

import requests
from requests.adapters import HTTPAdapter


DEFAULT_CONNECT_TIMEOUT = float(os.getenv("WAPPALYZER_CONNECT_TIMEOUT", "5"))
DEFAULT_READ_TIMEOUT = float(os.getenv("WAPPALYZER_READ_TIMEOUT", "30"))
DEFAULT_MAX_BYTES = int(os.getenv("WAPPALYZER_MAX_RESPONSE_BYTES", str(10 * 1024 * 1024)))
VERIFY_TLS = os.getenv("WAPPALYZER_VERIFY_TLS", "1").lower() not in {"0", "false", "no"}
_state = threading.local()


def _new_session():
    session = requests.Session()
    pool_size = max(1, os.cpu_count() or 1)
    adapter = HTTPAdapter(
        pool_connections=pool_size,
        pool_maxsize=pool_size,
        max_retries=0,
        pool_block=True,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def get_session():
    session = getattr(_state, "session", None)

    if session is None:
        session = _new_session()
        _state.session = session

    return session


def get_response(
    url,
    cookie=None,
    timeout=None,
    verify=None,
    max_bytes=None,
    session=None,
    **kwargs,
):
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "deflate",
        "DNT": "1",
        "Sec-GPC": "1",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Priority": "u=0, i",
        "TE": "trailers",
    }
    try:
        if cookie:
            headers["Cookie"] = cookie

        request_timeout = timeout or (
            DEFAULT_CONNECT_TIMEOUT,
            DEFAULT_READ_TIMEOUT,
        )
        if isinstance(request_timeout, (int, float)):
            request_timeout = (min(DEFAULT_CONNECT_TIMEOUT, request_timeout), request_timeout)

        response = (session or get_session()).get(
            url,
            headers=headers,
            verify=VERIFY_TLS if verify is None else verify,
            timeout=request_timeout,
            stream=True,
            **kwargs,
        )
        limit = DEFAULT_MAX_BYTES if max_bytes is None else max_bytes
        content = bytearray()

        for chunk in response.iter_content(chunk_size=64 * 1024):
            content.extend(chunk)

            if len(content) > limit:
                response.close()
                raise requests.exceptions.RequestException(
                    f"Response exceeded {limit} bytes: {url}"
                )

        response._content = bytes(content)
        response._content_consumed = True
        return response
    except requests.exceptions.RequestException as e:
        print(e, file=sys.stderr)
        return None
