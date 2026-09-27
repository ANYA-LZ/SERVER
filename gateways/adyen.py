"""
Adyen Charge handler — credit card payment via Adyen CSE (Client-Side Encryption).
Implements GOG wallet top-up flow with encrypted card data submission.
"""

import re
import json
import time
import os
import base64
import logging
from typing import Any, Dict, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

from core.session import REQUEST_TIMEOUT
from core.proxy import _proxy_dict, is_proxy_error, categorize_proxy_error

logger = logging.getLogger(__name__)

CHARGE = "𝘾𝙃𝘼𝙍𝙂𝙀𝘿 ✅"
ERROR = "𝙀𝙍𝙍𝙊𝙍 ⚠️"
FAILED = "𝙁𝘼𝙄𝙇𝙀𝘿 ❌"
INSUFFICIENT_FUNDS = "𝙄𝙣𝙨𝙪𝙛𝙛𝙞𝙘𝙞𝙚𝙣𝙩 𝙁𝙪𝙣𝙙𝙨 ☑️"
PASSAD = "𝙋𝘼𝙎𝙎𝙀𝘿 ❎"


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

    topup = 500
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
        nonlocal country_code, currency, locale
        gog_lc = session.cookies.get("gog_lc", domain=".gog.com") or ""
        parts = gog_lc.split("_", 2)
        if len(parts) == 3:
            country_code, currency, locale = parts[0], parts[1], parts[2]

    try:
        resp = session.post(f"{gog_api}/user/accessToken.json", timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            return ERROR, "Failed to get GOG access token"
        _sync_locale()
        access_token = resp.json().get("accessToken")
        if not access_token:
            return ERROR, "GOG access token not found"
        auth_headers = {"Authorization": f"Bearer {access_token}"}

        checkout_country = country_code
        checkout_currency = currency
        checkout_locale = locale
        logger.debug(
            f"Adyen locale frozen: {checkout_country}_{checkout_currency}_{checkout_locale}"
        )

        def _force_locale():
            session.cookies.set(
                "gog_lc",
                f"{checkout_country}_{checkout_currency}_{checkout_locale}",
                domain=".gog.com",
            )

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

        _force_locale()
        resp = session.get(f"{gog_base}/cartToken.json", timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            return ERROR, "Failed to get cart token"
        _force_locale()
        cart_token = resp.json().get("cartToken")
        if not cart_token:
            return ERROR, "Cart token not found"

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

        adyen_public_key = _fetch_adyen_public_key(adyen_token, adyen_url, gog_base, session)
        if not adyen_public_key:
            return ERROR, "Failed to fetch Adyen public key"

        encrypted_card = _adyen_encrypt("number", card_info["number"], adyen_public_key)
        encrypted_month = _adyen_encrypt("expiryMonth", card_info["month"], adyen_public_key)
        encrypted_year = _adyen_encrypt("expiryYear", str(card_info["year"]), adyen_public_key)
        encrypted_cvv = _adyen_encrypt("cvc", card_info["cvv"], adyen_public_key)

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


def handle_adyen_charge(card_info: Dict, person: Dict, gateway_config: Dict) -> Tuple[str, str]:
    """Main entry point for Adyen Charge processing.

    Delegates to the full Adyen charge flow for GOG wallet top-up.
    """
    return _adyen_charge_flow(card_info, person, gateway_config)
