"""
Proxy utilities — parsing, connection error detection, and categorisation.
"""

import logging
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


class ProxyConnectionError(Exception):
    """Raised when a proxy-related network failure is detected."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


_PROXY_INDICATORS = (
    "proxy", "tunnel", "cannot connect to proxy", "proxy authentication required",
    "407", "socks", "connection refused", "connection reset", "connection aborted",
    "unable to connect", "max retries exceeded", "newconnectionerror",
    "proxyconnectionerror",
)


def is_proxy_error(exc: Exception, using_proxy: bool = True) -> Tuple[bool, Optional[str]]:
    """Return (True, message) if *exc* looks proxy-related.

    using_proxy=False forces (False, None): retry-exhaustion on a DIRECT
    connection (e.g. datacenter IP hard-dropped) is NOT a proxy failure.
    """
    if not using_proxy:
        return False, None
    err = str(exc).lower()
    cls_name = type(exc).__name__.lower()

    if "proxyerror" in cls_name or "connecttimeout" in cls_name:
        return True, categorize_proxy_error(exc)

    for indicator in _PROXY_INDICATORS:
        if indicator in err:
            return True, categorize_proxy_error(exc)

    return False, None


def categorize_proxy_error(exc: Exception) -> str:
    """Map a proxy exception to a user-friendly label."""
    err = str(exc).lower()
    if "remotedisconnected" in err or "remote end closed" in err:
        return "Proxy Disconnected"
    if "closed connection" in err:
        return "Proxy Connection Closed"
    if "timeout" in err or "timed out" in err:
        return "Proxy Timeout"
    if "refused" in err:
        return "Proxy Refused"
    if "reset" in err or "aborted" in err:
        return "Proxy Reset"
    if "authentication" in err or "407" in err:
        return "Proxy Auth Failed"
    if "unable to connect to proxy" in err:
        return "Proxy Unreachable"
    if "socks" in err:
        return "SOCKS Proxy Error"
    if "tunnel" in err:
        return "Proxy Tunnel Failed"
    if "max retries" in err:
        return "Proxy Failed"
    return "Proxy Error"


def parse_proxy(proxy_string: Optional[str]) -> Optional[str]:
    """Normalise any proxy format into ``scheme://[user:pass@]host:port``."""
    if not proxy_string:
        return None
    proxy_string = proxy_string.strip()
    if proxy_string.startswith(("http://", "https://", "socks4://", "socks5://")):
        return proxy_string
    if "@" in proxy_string:
        return f"http://{proxy_string}"
    parts = proxy_string.split(":")
    if len(parts) == 2:
        return f"http://{parts[0]}:{parts[1]}"
    if len(parts) == 4:
        host, port, user, passwd = parts
        return f"http://{user}:{passwd}@{host}:{port}"
    logger.warning(f"Unrecognised proxy format: {proxy_string}")
    return None


def _proxy_dict(gateway_config: Dict) -> Optional[Dict[str, str]]:
    """Return ``{'http': url, 'https': url}`` or *None*."""
    raw = gateway_config.get("proxy")
    if not raw:
        return None
    url = parse_proxy(raw)
    return {"http": url, "https": url} if url else None


def _handle_proxy_exc(exc: Exception, context: str):
    """Log and re-raise as ProxyConnectionError when applicable."""
    is_pe, _ = is_proxy_error(exc)
    if is_pe:
        msg = categorize_proxy_error(exc)
        logger.error(f"Proxy error in {context}: {msg}")
        raise ProxyConnectionError(msg) from exc
