"""
Geo data and random person generation — US-based profiles for payment forms.
Includes Faker integration and remote geo data caching.
"""

import random
import logging
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import requests
from faker import Faker

logger = logging.getLogger(__name__)

_fake = Faker("en_US")

GEO_CACHE_TTL = timedelta(minutes=5)
EMAIL_DOMAINS = ("gmail.com", "yahoo.com", "hotmail.com", "outlook.com")

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
