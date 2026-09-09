from urllib.parse import urljoin


def get_scriptSrc(base_url, soup):
    if isinstance(soup, str):
        return []

    scriptSrc = []
    for script in soup.find_all("script"):
        src = script.get("src")
        if src:
            # Use urljoin to handle all types of URLs (absolute, protocol-relative, and path-relative)
            src = urljoin(base_url, src)
            scriptSrc.append(src)
    return scriptSrc
