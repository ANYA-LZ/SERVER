"""
HTTP session management — per-request session isolation, proxy support,
cloudscraper bypass, and gateway session creation.
"""

import logging
import uuid
import time
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests
import cloudscraper
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from core.proxy import parse_proxy, _proxy_dict, is_proxy_error, categorize_proxy_error, ProxyConnectionError

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 30
SESSION_MAX_AGE = timedelta(seconds=30)

_retry_strategy = Retry(
    total=2,
    backoff_factor=1,
    status_forcelist=[429, 502, 503, 504],
    allowed_methods=["POST", "GET"],
)


def _build_api_session(proxies: Optional[Dict] = None) -> requests.Session:
    """Create a requests.Session with retry adapters and optional proxy."""
    s = requests.Session()
    adapter = HTTPAdapter(max_retries=_retry_strategy, pool_maxsize=10)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    if proxies:
        s.proxies.update(proxies)
    return s


def _apply_cookies(session: requests.Session, gateway_config: Dict) -> None:
    """Inject gateway cookies into *session* unless version says otherwise."""
    if "without_cookies" in gateway_config.get("version", "").lower():
        return
    cookies_list = gateway_config.get("cookies", [])
    for c in cookies_list:
        name, value = c.get("name"), c.get("value")
        if name and value:
            session.cookies.set(name, value)


def _create_gateway_session(gateway_config: Dict, random_person: Dict) -> requests.Session:
    """Build a fresh session pre-loaded with headers, proxy, and cookies."""
    parsed = urlparse(gateway_config["url"])
    origin = f"{parsed.scheme}://{parsed.netloc}"

    if gateway_config.get("bypass_cloudscraper", False):
        session = cloudscraper.create_scraper()
    else:
        session = requests.Session()
        adapter = HTTPAdapter(pool_maxsize=5)
        session.mount("https://", adapter)
        session.mount("http://", adapter)

    proxy_url = parse_proxy(gateway_config.get("proxy"))
    using_proxy = False
    if proxy_url:
        session.proxies = {"http": proxy_url, "https": proxy_url}
        using_proxy = True
        logger.info(f"Session using proxy: {proxy_url}")

    session.headers.update({
        "User-Agent": random_person["user_agent"],
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0",
        "Origin": origin,
        "Referer": gateway_config["url"],
    })

    if "Adyen Charge" in gateway_config.get("gateway_type", ""):
        _apply_cookies(session, gateway_config)
        return session

    try:
        resp = session.get(origin, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        session.cookies.update(resp.cookies)
        _apply_cookies(session, gateway_config)
    except Exception as exc:
        if using_proxy:
            _handle_proxy_exc(exc, "session_creation")
        is_pe, _ = is_proxy_error(exc)
        if is_pe:
            raise ProxyConnectionError(categorize_proxy_error(exc)) from exc
        raise

    return session


def _handle_proxy_exc(exc: Exception, context: str):
    """Log and re-raise as ProxyConnectionError when applicable."""
    is_pe, _ = is_proxy_error(exc)
    if is_pe:
        msg = categorize_proxy_error(exc)
        logger.error(f"Proxy error in {context}: {msg}")
        raise ProxyConnectionError(msg) from exc


class SessionManager:
    """Creates and tracks per-request HTTP sessions to prevent cross-contamination."""

    def __init__(self):
        self._sessions: Dict[str, requests.Session] = {}
        self._timestamps: Dict[str, datetime] = {}
        self._lock = threading.Lock()

    @staticmethod
    def create_request_id() -> str:
        return f"req_{uuid.uuid4().hex[:12]}_{int(time.time())}"

    def get_session(self, request_id: str, gateway_config: Dict, random_person: Dict) -> requests.Session:
        with self._lock:
            self._cleanup_expired()
            session = _create_gateway_session(gateway_config, random_person)
            self._sessions[request_id] = session
            self._timestamps[request_id] = datetime.now()
            return session

    def cleanup_session(self, request_id: str) -> None:
        with self._lock:
            sess = self._sessions.pop(request_id, None)
            self._timestamps.pop(request_id, None)
            if sess:
                try:
                    sess.close()
                except Exception:
                    pass

    def get_active_sessions_count(self) -> int:
        with self._lock:
            return len(self._sessions)

    def _cleanup_expired(self) -> None:
        now = datetime.now()
        expired = [rid for rid, ts in self._timestamps.items() if now - ts > SESSION_MAX_AGE]
        for rid in expired:
            sess = self._sessions.pop(rid, None)
            self._timestamps.pop(rid, None)
            if sess:
                try:
                    sess.close()
                except Exception:
                    pass
            logger.debug(f"Expired session cleaned: {rid}")
