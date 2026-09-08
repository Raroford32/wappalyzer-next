from urllib.parse import urlparse

from wappalyzer.core.requester import get_response


def get_robots(url, timeout=None):
    parsed = urlparse(url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    r = get_response(robots_url, timeout=timeout)
    return r.text if r else ""
