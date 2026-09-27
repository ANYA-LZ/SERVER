"""
3DS Lookup handler — checks if a card is enrolled in 3D Secure.

Creates a session, sends card data to the gateway's 3DS endpoint,
and returns the enrollment status.
"""

import json
import logging
import random
import uuid
from typing import Any, Dict, Tuple
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter

from core.session import REQUEST_TIMEOUT
from core.geo import _fake
from core.proxy import _proxy_dict, parse_proxy, is_proxy_error, categorize_proxy_error, ProxyConnectionError

logger = logging.getLogger(__name__)

APPROVED = "𝘼𝙥𝙥𝙧𝙤𝙫𝙚𝙙 ✅"
DECLINED = "𝘿𝙚𝙘𝙡𝙞𝙣𝙚𝙙 ❌"
ERROR = "𝙀𝙍𝙍𝙊𝙍 ⚠️"
PASSAD = "𝙋𝘼𝙎𝙎𝙀𝘿 ❎"
SUCCESS = "𝙎𝙐𝘾𝘾𝞢𝙎𝙎 ✅"
FAILED = "𝙁𝘼𝙄𝙇𝙀𝘿 ❌"


def handle_3ds_lookup(card_info: Dict, person: Dict, gateway_config: Dict) -> Tuple[str, str]:
    """Check if a card is enrolled in 3D Secure via the gateway's 3DS endpoint.

    Builds a session, sends card details to the gateway, and parses the 3DS
    enrollment response. Returns a status indicating whether the card is
    enrolled, requires additional authentication, or failed.

    Args:
        card_info: Dict with number, month, year, cvv
        person: Generated random person profile
        gateway_config: Gateway configuration including url, proxy, etc.

    Returns:
        (status_label, result_message)
    """
    gateway_url = gateway_config.get("url")
    if not gateway_url:
        return ERROR, "Gateway URL missing in config"

    proxy_url = parse_proxy(gateway_config.get("proxy"))
    session = requests.Session()
    adapter = HTTPAdapter(pool_maxsize=5)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    if proxy_url:
        session.proxies = {"http": proxy_url, "https": proxy_url}

    parsed = urlparse(gateway_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    session.headers.update({
        "User-Agent": person.get("user_agent", (
            "Mozilla/5.0 (Linux; Android 14; SM-G991B) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36"
        )),
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Accept-Language": "en-US,en;q=0.9",
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": origin,
        "Referer": gateway_url,
        "X-Requested-With": "XMLHttpRequest",
        "Connection": "keep-alive",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
    })

    cookies_list = gateway_config.get("cookies", [])
    for c in cookies_list:
        name, value = c.get("name"), c.get("value")
        if name and value:
            session.cookies.set(name, value)

    try:
        warmup = session.get(origin, timeout=REQUEST_TIMEOUT)
        warmup.raise_for_status()
        session.cookies.update(warmup.cookies)

        three_ds_url = gateway_config.get("three_ds_url", gateway_url)
        three_ds_method = gateway_config.get("three_ds_method", "POST")

        payload = {
            "card_number": card_info["number"],
            "card_month": card_info["month"],
            "card_year": card_info["year"],
            "card_cvc": card_info["cvv"],
            "billing_name": f"{person.get('first_name', '')} {person.get('last_name', '')}",
            "billing_address": person.get("address", ""),
            "billing_city": person.get("city", ""),
            "billing_state": person.get("state", ""),
            "billing_zip": person.get("zipcode", ""),
            "billing_country": person.get("country", "US"),
        }

        if three_ds_method.upper() == "GET":
            resp = session.get(three_ds_url, params=payload, timeout=REQUEST_TIMEOUT)
        else:
            resp = session.post(three_ds_url, data=payload, timeout=REQUEST_TIMEOUT)

        session.cookies.update(resp.cookies)

        status, message = _parse_3ds_response(resp.content, resp.text, gateway_config)

        return status, message

    except requests.RequestException as exc:
        is_pe, msg = is_proxy_error(exc)
        if is_pe:
            msg = categorize_proxy_error(exc)
            logger.error(f"Proxy error in 3DS lookup: {msg}")
            return ERROR, msg
        logger.error(f"3DS lookup request failed: {exc}")
        return ERROR, f"3DS lookup failed: {exc}"
    except Exception as exc:
        logger.error(f"Unexpected error in 3DS lookup: {exc}")
        return ERROR, f"3DS processing failed: {exc}"
    finally:
        try:
            session.close()
        except Exception:
            pass


def _parse_3ds_response(content: bytes, text: str, gateway_config: Dict) -> Tuple[str, str]:
    """Parse the 3DS enrollment response.

    Attempts to determine the 3DS status from JSON or HTML response body.

    Returns:
        (status_label, message) — e.g., (PASSAD, '3DS Enrolled') or (APPROVED, 'Not Enrolled')
    """
    try:
        data = json.loads(content)

        if "proxy_error" in data:
            return ERROR, data["proxy_error"]

        three_ds_status = data.get("threeDSecure") or data.get("three_d_secure") or data.get("status")
        if three_ds_status:
            if str(three_ds_status).lower() in ("enrolled", "challenge_required", "requires_action"):
                return PASSAD, "3DS Enrolled — Challenge Required"
            if str(three_ds_status).lower() in ("not_enrolled", "attempt", "not_supported"):
                return APPROVED, "Not Enrolled in 3DS"

        if data.get("enrolled"):
            return PASSAD, "3DS Enrolled"

        if data.get("success") is True:
            return APPROVED, "3DS Lookup Successful"

        return PASSAD, f"3DS Response: {three_ds_status or 'unknown'}"

    except (json.JSONDecodeError, ValueError):
        content_lower = text.lower()

        if "challenge" in content_lower or "3ds" in content_lower or "three_d_secure" in content_lower:
            if "enrolled" in content_lower:
                return PASSAD, "3DS Enrolled"
            return PASSAD, "3DS Challenge Required"

        if "not enrolled" in content_lower or "frictionless" in content_lower:
            return APPROVED, "Not Enrolled in 3DS"

        if "error" in content_lower:
            return ERROR, "3DS Lookup Error"

        return PASSAD, "3DS Lookup Completed"
