from collections.abc import Sequence
from ipaddress import AddressValueError, IPv6Address
from socket import gaierror, gethostbyname
from urllib.parse import urlparse

DEFAULT_ALLOWED_URL_SCHEMES: tuple[str, ...] = ("http", "https")


def _is_url_valid(
    url: str, valid_schemes: Sequence[str] | None = None, check_host: bool = True
) -> bool:
    if not isinstance(url, str):
        raise TypeError
    if not valid_schemes:
        valid_schemes = DEFAULT_ALLOWED_URL_SCHEMES

    parsed_url = urlparse(url)
    scheme: str = parsed_url.scheme
    netloc: str = parsed_url.netloc
    port: int | None = getattr(parsed_url, "port", None)

    if scheme not in valid_schemes:
        return False

    host_is_valid: bool = True
    if not netloc:
        host_is_valid = False
    if not check_host:
        return host_is_valid

    host: str = netloc.rsplit(f":{port}", 1)[0] if port else netloc
    if host[0] == "[" and host[-1] == "]":
        try:
            _ = IPv6Address(host[1:-1])
        except AddressValueError:
            host_is_valid = False
    else:
        try:
            _ = gethostbyname(host)
        except gaierror:
            host_is_valid = False

    return host_is_valid
