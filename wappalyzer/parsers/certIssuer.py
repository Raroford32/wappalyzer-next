import socket
import ssl
from urllib.parse import urlparse


def get_certIssuer(response, timeout=5):
    parsed = urlparse(response.url)

    if parsed.scheme != "https" or not parsed.hostname:
        return ""

    port = parsed.port or 443

    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (parsed.hostname, port),
            timeout=timeout,
        ) as connection:
            with context.wrap_socket(
                connection,
                server_hostname=parsed.hostname,
            ) as tls_connection:
                certificate = tls_connection.getpeercert()

        for attributes in certificate.get("issuer", ()):
            for name, value in attributes:
                if name in {"organizationName", "commonName"}:
                    return value
    except (OSError, ssl.SSLError, ValueError):
        return ""

    return ""
