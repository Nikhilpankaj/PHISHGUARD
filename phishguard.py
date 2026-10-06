#!/usr/bin/env python3
"""
PHISHGUARD 2.0 - Phishing URL Detector

Static (offline) analysis
-------------------------
* Registered-domain aware parsing (tldextract if installed, built-in fallback)
* Brand impersonation, typosquatting and homoglyph / mixed-script detection
* IP hosts, including obfuscated forms (decimal / octal / hex)
* Dangerous schemes (javascript:, data:, ...), defanged input (hxxp, [.])
* Hostname/path keyword scoring with word-boundary matching
* Shorteners, free hosting, risky TLDs, ports, encoding tricks, payload types
* Allowlist support to cut false positives; blocklist support for known-bad
* Per-category score caps, structured (explainable) indicators

Optional network checks (all disabled by --offline)
---------------------------------------------------
* DNS resolution with timeout
* Redirect-chain inspection with SSRF protection (every hop is resolved,
  non-public addresses are refused, and the connection is pinned to the
  address that was validated)
* TLS certificate checks (verification failure, very new certificates)
* Light page-content analysis (password forms, cross-domain form actions,
  brand names in the page title)
* Domain age via RDAP
* Google Safe Browsing and VirusTotal lookups (API key required)

Reporting
---------
* Text, JSON and CSV output (CSV is formula-injection safe)
* Batch scanning with threads, stdin support, de-duplication
* Exit codes for scripting, --evaluate mode for threshold calibration

Use only on URLs you are authorized to analyze.  Network checks contact the
target site; use --offline for purely static analysis.  Lookups with
VirusTotal / Google Safe Browsing send the URL to those third parties.
"""

from __future__ import annotations

import argparse
import base64
import csv
import http.client
import ipaddress
import json
import logging
import math
import os
import re
import socket
import ssl
import sys
import threading
import time
import unicodedata
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from html.parser import HTMLParser
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, quote, unquote, urljoin, urlparse

__version__ = "2.0.0"
USER_AGENT = f"PhishGuard/{__version__} (security scanner)"

log = logging.getLogger("phishguard")

# ---------------------------------------------------------------------------
# Default detection data (all overridable with --config)
# ---------------------------------------------------------------------------

# Strong = credential-harvesting language; weak = common but less telling.
DEFAULT_KEYWORDS_STRONG = {
    "login", "signin", "verify", "verification", "password", "credential",
    "wallet", "unlock", "suspend", "suspended", "recover", "authenticate",
    "billing",
}
DEFAULT_KEYWORDS_WEAK = {
    "account", "secure", "security", "update", "confirm", "bank", "payment",
    "support", "auth", "reset", "invoice", "webmail",
}

DEFAULT_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly",
    "rb.gy", "buff.ly", "rebrand.ly", "shorturl.at", "t.ly", "lnkd.in",
    "tiny.cc", "bl.ink", "s.id", "v.gd", "soo.gd", "trib.al", "tr.ee",
}

DEFAULT_SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "work", "link", "zip", "mov", "tk", "ml", "ga",
    "cf", "gq", "icu", "cam", "buzz", "cyou", "sbs", "cfd", "rest",
    "monster", "pw", "su",
}

DEFAULT_SUSPICIOUS_PORTS = {
    21, 22, 23, 25, 110, 143, 445, 1433, 3306, 3389, 4444, 5900, 8080, 8443,
}

# brand token -> official registered domains
DEFAULT_BRANDS: Dict[str, Set[str]] = {
    "paypal": {"paypal.com", "paypal.me", "paypalobjects.com"},
    "google": {"google.com", "google.co.in", "gmail.com", "gstatic.com",
               "googleapis.com", "googlesyndication.com", "youtube.com",
               "goo.gl", "g.co", "withgoogle.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com",
                  "microsoftonline.com", "office365.com", "msn.com",
                  "bing.com", "windows.com", "skype.com", "azure.com"},
    "office365": {"office365.com", "office.com", "microsoft.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de",
               "amazon.ca", "amzn.to", "a.co"},
    "facebook": {"facebook.com", "fb.com", "fb.me", "messenger.com",
                 "meta.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net", "wa.me"},
    "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com", "lnkd.in"},
    "twitter": {"twitter.com", "x.com", "t.co"},
    "dropbox": {"dropbox.com"},
    "github": {"github.com"},
    "adobe": {"adobe.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "usps": {"usps.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "citibank": {"citibank.com", "citi.com"},
    "hsbc": {"hsbc.com", "hsbc.co.in"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "metamask": {"metamask.io"},
    "spotify": {"spotify.com"},
    "ebay": {"ebay.com", "ebay.co.uk", "ebay.in"},
    "yahoo": {"yahoo.com"},
    # India
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "bank.sbi"},
    "hdfcbank": {"hdfcbank.com"},
    "hdfc": {"hdfcbank.com", "hdfc.com"},
    "icicibank": {"icicibank.com"},
    "icici": {"icicibank.com", "icicidirect.com"},
    "axisbank": {"axisbank.com"},
    "kotak": {"kotak.com"},
    "paytm": {"paytm.com", "paytmbank.com"},
    "phonepe": {"phonepe.com"},
    "irctc": {"irctc.co.in"},
    "uidai": {"uidai.gov.in"},
    "aadhaar": {"uidai.gov.in"},
    "incometax": {"incometax.gov.in", "incometaxindia.gov.in"},
    "flipkart": {"flipkart.com"},
    "airtel": {"airtel.in"},
    "swiggy": {"swiggy.com"},
    "zomato": {"zomato.com"},
    "npci": {"npci.org.in"},
}

# Brand names that are also ordinary words: weaker evidence on their own.
AMBIGUOUS_BRANDS = {"apple", "chase"}

# Large, well-known domains (merged with every brand's official domains).
# Replace/extend with a Tranco list via --allowlist for better coverage.
DEFAULT_EXTRA_ALLOWLIST = {
    "wikipedia.org", "reddit.com", "stackoverflow.com", "cloudflare.com",
    "mozilla.org", "anthropic.com", "claude.ai", "openai.com", "zoom.us",
    "slack.com", "atlassian.com", "salesforce.com", "oracle.com", "ibm.com",
    "bbc.co.uk", "bbc.com", "nytimes.com", "theguardian.com", "thehindu.com",
    "indiatimes.com", "hindustantimes.com", "ndtv.com", "gov.uk", "nic.in",
    "india.gov.in", "digilocker.gov.in", "python.org", "pypi.org",
    "npmjs.com", "wordpress.org", "medium.com", "quora.com", "twitch.tv",
    "tiktok.com", "pinterest.com", "walmart.com", "target.com", "bestbuy.com",
    "booking.com", "airbnb.com", "uber.com", "stripe.com", "shopify.com",
}

# Hosts where *anyone* can publish content.  These are never allowlisted even
# when the parent domain is, because they are heavily abused for phishing.
USER_CONTENT_HOSTS = {
    "sites.google.com", "docs.google.com", "drive.google.com",
    "storage.googleapis.com", "storage.cloud.google.com", "script.google.com",
    "s3.amazonaws.com", "amazonaws.com", "blob.core.windows.net",
    "web.core.windows.net", "dl.dropboxusercontent.com", "onedrive.live.com",
    "1drv.ms", "notion.site", "githubusercontent.com", "forms.office.com",
    "sharepoint.com",
}

# Free hosting / dynamic DNS suffixes: the *label before the suffix* is
# attacker-controlled, so they behave like public suffixes.
FREE_HOSTING_SUFFIXES = {
    "github.io", "gitlab.io", "netlify.app", "vercel.app", "pages.dev",
    "workers.dev", "web.app", "firebaseapp.com", "herokuapp.com",
    "blogspot.com", "blogspot.in", "wordpress.com", "weebly.com",
    "wixsite.com", "000webhostapp.com", "glitch.me", "repl.co", "r2.dev",
    "onrender.com", "fly.dev", "surge.sh", "ngrok.io", "ngrok-free.app",
    "trycloudflare.com", "duckdns.org", "no-ip.org", "ddns.net", "hopto.org",
    "myftp.org", "zapto.org", "freeddns.org", "serveo.net", "tiiny.site",
    "carrd.co", "webflow.io", "square.site", "godaddysites.com",
    "mystrikingly.com", "azurewebsites.net", "pythonanywhere.com",
}

# Multi-label public suffixes for the built-in fallback splitter.
MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    "co.in", "org.in", "net.in", "gen.in", "firm.in", "ind.in", "ac.in",
    "edu.in", "res.in", "gov.in", "nic.in", "mil.in",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "com.br", "net.br", "org.br", "gov.br",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.mx", "co.za", "com.sg", "com.hk", "co.nz", "com.tr", "com.ar",
    "co.kr", "or.kr", "com.my", "com.pk", "com.bd", "co.id", "com.ng",
    "com.eg", "com.sa", "com.ua", "com.tw", "com.vn", "com.ph", "co.th",
    "com.co", "com.pe", "com.ve", "co.il", "com.ru", "net.ru",
}
KNOWN_SUFFIXES = MULTI_LABEL_SUFFIXES | FREE_HOSTING_SUFFIXES

DANGEROUS_SCHEMES = {"javascript", "data", "vbscript", "file", "blob"}
NON_WEB_SCHEMES = {"mailto", "tel", "sms", "sip", "magnet"}

SUSPICIOUS_PARAMS = {
    "redirect", "redirect_url", "redirect_uri", "url", "next", "return",
    "returnurl", "return_url", "continue", "dest", "destination", "target",
    "goto", "link", "r", "u",
}

DANGEROUS_EXTENSIONS = {
    "exe", "scr", "bat", "cmd", "com", "js", "jse", "vbs", "vbe", "wsf",
    "ps1", "msi", "jar", "apk", "dmg", "lnk", "hta", "docm", "xlsm", "pptm",
    "pif", "cpl", "reg",
}
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "iso", "img", "gz", "tar", "cab"}
DOCUMENT_EXTENSIONS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
                       "jpg", "jpeg", "png", "gif", "txt", "mp4", "mp3"}

# Categories whose points are scaled down for allowlisted domains.  "Hard"
# categories (deception, brand, intel, content, network, ...) are never scaled.
SOFT_CATEGORIES = frozenset({"structure", "lexical", "transport", "hosting",
                             "payload"})

DEFAULT_CATEGORY_CAPS = {
    "structure": 40, "lexical": 30, "transport": 20, "hosting": 30,
    "payload": 25, "deception": 70, "brand": 70, "dns": 20, "network": 50,
    "tls": 25, "age": 30, "content": 55, "intel": 100,
}

CLASS_LOW = "LOW RISK"
CLASS_MEDIUM = "SUSPICIOUS / MEDIUM RISK"
CLASS_HIGH = "PHISHING / HIGH RISK"
CLASS_INVALID = "INVALID / HIGH RISK"
CLASS_NOT_WEB = "NOT A WEB URL"

MAX_REDIRECTS = 5
REQUEST_TIMEOUT = 7.0
BODY_LIMIT = 262_144


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def _default_allowlist() -> Set[str]:
    allow = set(DEFAULT_EXTRA_ALLOWLIST)
    for domains in DEFAULT_BRANDS.values():
        allow |= domains
    return allow


@dataclass
class Config:
    keywords_strong: Set[str] = field(default_factory=lambda: set(DEFAULT_KEYWORDS_STRONG))
    keywords_weak: Set[str] = field(default_factory=lambda: set(DEFAULT_KEYWORDS_WEAK))
    shorteners: Set[str] = field(default_factory=lambda: set(DEFAULT_SHORTENERS))
    suspicious_tlds: Set[str] = field(default_factory=lambda: set(DEFAULT_SUSPICIOUS_TLDS))
    suspicious_ports: Set[int] = field(default_factory=lambda: set(DEFAULT_SUSPICIOUS_PORTS))
    brands: Dict[str, Set[str]] = field(
        default_factory=lambda: {k: set(v) for k, v in DEFAULT_BRANDS.items()})
    allowlist: Set[str] = field(default_factory=_default_allowlist)
    category_caps: Dict[str, int] = field(default_factory=lambda: dict(DEFAULT_CATEGORY_CAPS))
    allowlist_factor: float = 0.35
    medium_threshold: int = 30
    high_threshold: int = 60

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        cfg = cls()
        for key in ("keywords_strong", "keywords_weak", "shorteners",
                    "suspicious_tlds", "allowlist"):
            if key in data:
                setattr(cfg, key, {str(x).lower() for x in data[key]})
        if "suspicious_ports" in data:
            cfg.suspicious_ports = {int(x) for x in data["suspicious_ports"]}
        if "brands" in data:
            cfg.brands = {str(k).lower(): {str(d).lower() for d in v}
                          for k, v in data["brands"].items()}
        if "category_caps" in data:
            cfg.category_caps.update({str(k): int(v) for k, v in data["category_caps"].items()})
        if "allowlist_factor" in data:
            cfg.allowlist_factor = float(data["allowlist_factor"])
        if "medium_threshold" in data:
            cfg.medium_threshold = int(data["medium_threshold"])
        if "high_threshold" in data:
            cfg.high_threshold = int(data["high_threshold"])
        cfg.validate()
        return cfg

    def validate(self) -> None:
        if not (0 <= self.medium_threshold < self.high_threshold <= 100):
            raise ValueError("thresholds must satisfy 0 <= medium < high <= 100")
        if not (0.0 <= self.allowlist_factor <= 1.0):
            raise ValueError("allowlist_factor must be between 0 and 1")

    def to_dict(self) -> dict:
        return {
            "keywords_strong": sorted(self.keywords_strong),
            "keywords_weak": sorted(self.keywords_weak),
            "shorteners": sorted(self.shorteners),
            "suspicious_tlds": sorted(self.suspicious_tlds),
            "suspicious_ports": sorted(self.suspicious_ports),
            "brands": {k: sorted(v) for k, v in sorted(self.brands.items())},
            "allowlist": sorted(self.allowlist),
            "category_caps": dict(sorted(self.category_caps.items())),
            "allowlist_factor": self.allowlist_factor,
            "medium_threshold": self.medium_threshold,
            "high_threshold": self.high_threshold,
        }


_DEFAULT_CONFIG: Optional[Config] = None


def get_default_config() -> Config:
    global _DEFAULT_CONFIG
    if _DEFAULT_CONFIG is None:
        _DEFAULT_CONFIG = Config()
    return _DEFAULT_CONFIG


def load_config(path: str) -> Config:
    with open(path, "r", encoding="utf-8") as fh:
        return Config.from_dict(json.load(fh))


def load_domain_list(path: str) -> Set[str]:
    """Read domains from a file: one per line, or Tranco-style 'rank,domain'."""
    domains: Set[str] = set()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            token = line.split(",")[-1].strip().lower()
            token = re.sub(r"^[a-z][a-z0-9+.-]*://", "", token).split("/")[0]
            token = token.rstrip(".")
            if token:
                domains.add(token)
    return domains


@dataclass
class Options:
    dns: bool = False
    redirects: bool = False
    content: bool = False
    rdap: bool = False
    gsb_key: Optional[str] = None
    vt_key: Optional[str] = None
    blocklist: Optional["Blocklist"] = None
    timeout: float = REQUEST_TIMEOUT
    max_redirects: int = MAX_REDIRECTS
    body_limit: int = BODY_LIMIT
    allow_private: bool = False  # disables SSRF protection (lab use only)

    @property
    def uses_network(self) -> bool:
        return bool(self.dns or self.redirects or self.content or self.rdap
                    or self.gsb_key or self.vt_key)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Indicator:
    category: str
    points: int
    message: str

    def to_dict(self) -> dict:
        return {"category": self.category, "points": self.points,
                "message": self.message}


@dataclass
class HostInfo:
    host: str = ""            # ASCII (punycode) form
    host_uni: str = ""        # Unicode form
    is_ip: bool = False
    ip: Optional[str] = None  # canonical IP when is_ip
    obfuscated_ip: bool = False
    subdomain: str = ""
    sld: str = ""
    suffix: str = ""
    registered_domain: str = ""
    sub_uni: str = ""
    sld_uni: str = ""
    free_hosting: bool = False


@dataclass
class Result:
    url: str
    normalized_url: str = ""
    hostname: str = ""
    hostname_unicode: str = ""
    registered_domain: str = ""
    score: int = 0
    classification: str = CLASS_LOW
    indicators: List[Indicator] = field(default_factory=list)
    ip_address: bool = False
    allowlisted: bool = False
    resolved_ips: List[str] = field(default_factory=list)
    redirect_chain: List[str] = field(default_factory=list)
    final_url: str = ""
    ctx: Optional["Ctx"] = field(default=None, repr=False, compare=False)

    @property
    def reasons(self) -> List[str]:
        return [i.message for i in self.indicators]

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "normalized_url": self.normalized_url,
            "hostname": self.hostname,
            "hostname_unicode": self.hostname_unicode,
            "registered_domain": self.registered_domain,
            "ip_address": self.ip_address,
            "allowlisted": self.allowlisted,
            "score": self.score,
            "classification": self.classification,
            "reasons": self.reasons,
            "indicators": [i.to_dict() for i in self.indicators],
            "resolved_ips": list(self.resolved_ips),
            "redirect_chain": list(self.redirect_chain),
            "final_url": self.final_url,
        }


@dataclass
class Ctx:
    """Everything the static checks need, computed once."""
    original: str
    normalized: str
    scheme_explicit: bool
    parsed: object
    scheme: str
    info: HostInfo
    config: Config
    port: Optional[int] = None
    port_invalid: bool = False
    strong_hits: Set[str] = field(default_factory=set)
    host_tokens: Set[str] = field(default_factory=set)
    path_tokens: Set[str] = field(default_factory=set)


# ---------------------------------------------------------------------------
# Generic text helpers
# ---------------------------------------------------------------------------

def safe_text(value: object) -> str:
    """Escape control / invisible / bidi characters before printing."""
    out = []
    for ch in str(value):
        if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp") or ch == "\x7f":
            code = ord(ch)
            out.append(f"\\x{code:02x}" if code <= 0xFF else f"\\u{code:04x}")
        else:
            out.append(ch)
    return "".join(out)


def csv_safe(value: object) -> str:
    """Neutralise spreadsheet formula injection in CSV cells."""
    text = safe_text(value)
    if text and text[0] in "=+-@\t\r":
        return "'" + text
    return text


def calculate_entropy(value: str) -> float:
    """Shannon entropy of a string, in bits per character."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def damerau_levenshtein(a: str, b: str) -> int:
    """Optimal-string-alignment distance (insert/delete/substitute/transpose)."""
    la, lb = len(a), len(b)
    if abs(la - lb) > 3:
        return 4
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


def tokens(text: str) -> List[str]:
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if t]


# Characters that look like ASCII letters (Cyrillic, Greek, misc. Latin).
CONFUSABLES = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0458": "j", "\u0455": "s",
    "\u0501": "d", "\u0261": "g", "\u04bb": "h", "\u051b": "q", "\u051d": "w",
    "\u043a": "k", "\u043c": "m", "\u043d": "h", "\u0442": "t", "\u0432": "b",
    "\u03bf": "o", "\u03b1": "a", "\u03bd": "v", "\u03c1": "p", "\u03b9": "i",
    "\u03ba": "k", "\u03c4": "t", "\u03c5": "u", "\u03b5": "e",
    "\u0251": "a", "\u0131": "i", "\u04cf": "l", "\u2113": "l", "\u217c": "l",
}

_SKELETON_MAP = str.maketrans({
    "0": "o", "1": "l", "i": "l", "|": "l", "!": "l",
    "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a",
})


def ascii_fold(text: str) -> str:
    """Lower-case, strip accents, and map look-alike letters to ASCII."""
    text = unicodedata.normalize("NFKD", text.lower())
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    return "".join(CONFUSABLES.get(ch, ch) for ch in text)


def skeleton(text: str) -> str:
    """Aggressive look-alike normalisation used only for equality checks."""
    folded = ascii_fold(text).replace("-", "")
    folded = folded.translate(_SKELETON_MAP)
    return folded.replace("rn", "m").replace("vv", "w")


def label_scripts(label: str) -> Set[str]:
    scripts: Set[str] = set()
    for ch in unicodedata.normalize("NFKC", label):
        if not ch.isalpha():
            continue
        if ch.isascii():
            scripts.add("LATIN")
            continue
        try:
            first = unicodedata.name(ch).split()[0]
        except ValueError:
            scripts.add("UNKNOWN")
            continue
        if first in ("HIRAGANA", "KATAKANA", "CJK", "BOPOMOFO", "HANGUL"):
            first = "CJK"
        scripts.add(first)
    return scripts


def looks_random(label: str) -> Tuple[bool, float]:
    """Heuristic for algorithmically generated / random-looking labels."""
    s = label.replace("-", "")
    if len(s) < 10 or not s.isascii():
        return False, 0.0
    entropy = calculate_entropy(s)
    letters = [c for c in s if c.isalpha()]
    vowel_ratio = (sum(c in "aeiou" for c in letters) / len(letters)) if letters else 0.0
    digit_mix = bool(re.search(r"[a-z]\d+[a-z]", s)) and sum(c.isdigit() for c in s) >= 2
    return (entropy >= 3.2 and (vowel_ratio <= 0.2 or digit_mix)), entropy


# ---------------------------------------------------------------------------
# URL / host parsing
# ---------------------------------------------------------------------------

_DEFANG_PAIRS = [
    ("[://]", "://"), ("[:]", ":"), ("[.]", "."), ("(.)", "."), ("{.}", "."),
    ("[/]", "/"), ("[@]", "@"),
]


def refang(url: str) -> Tuple[str, bool]:
    """Undo common 'defanging' (hxxp://evil[.]com) used when sharing IOCs."""
    original = url.strip()
    s = re.sub(r"^hxxp", "http", original, flags=re.IGNORECASE)
    for old, new in _DEFANG_PAIRS:
        s = s.replace(old, new)
    s = re.sub(r"\[dot\]|\(dot\)", ".", s, flags=re.IGNORECASE)
    return s, s != original


_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):")
_SCHEME_SLASHES_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*)://")


def detect_special_scheme(url: str) -> Optional[str]:
    """Return a scheme like 'javascript' if url uses one that is not host-based."""
    if _SCHEME_SLASHES_RE.match(url):
        scheme = _SCHEME_SLASHES_RE.match(url).group(1).lower()
        return scheme if scheme in DANGEROUS_SCHEMES else None
    m = _SCHEME_RE.match(url)
    if m and m.group(1).lower() in (DANGEROUS_SCHEMES | NON_WEB_SCHEMES):
        return m.group(1).lower()
    return None


def normalize_url(url: str) -> Tuple[str, bool]:
    """Return (normalized_url, scheme_was_explicit)."""
    url = url.strip()
    if _SCHEME_SLASHES_RE.match(url):
        return url, True
    if url.startswith("//"):
        url = url[2:]
    return "http://" + url, False


def to_unicode_host(host: str) -> str:
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = label[4:].encode("ascii").decode("punycode")
            except (UnicodeError, ValueError):
                pass
        labels.append(label)
    return ".".join(labels)


def to_ascii_host(host: str) -> Optional[str]:
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        labels = []
        for label in host.split("."):
            if label.isascii():
                labels.append(label)
                continue
            try:
                labels.append("xn--" + label.encode("punycode").decode("ascii"))
            except UnicodeError:
                return None
        return ".".join(labels)


_LEGACY_IP_RE = re.compile(r"(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}")


def classify_ip_host(host: str) -> Tuple[bool, Optional[str], bool]:
    """Return (is_ip, canonical_ip, obfuscated).  Handles 3232235777, 0x7f.1 ..."""
    h = host.strip("[]")
    try:
        return True, str(ipaddress.ip_address(h)), False
    except ValueError:
        pass
    if _LEGACY_IP_RE.fullmatch(h):
        try:
            return True, socket.inet_ntoa(socket.inet_aton(h)), True
        except OSError:
            pass
    return False, None, False


def is_ip_address(hostname: str) -> bool:
    return classify_ip_host(hostname)[0]


_TLDEXTRACT = None
_TLDEXTRACT_LOCK = threading.Lock()


def _get_tldextract():
    global _TLDEXTRACT
    if _TLDEXTRACT is None:
        with _TLDEXTRACT_LOCK:
            if _TLDEXTRACT is None:
                try:
                    import tldextract  # type: ignore
                    _TLDEXTRACT = tldextract.TLDExtract(
                        suffix_list_urls=(), cache_dir=None,
                        include_psl_private_domains=True)
                except Exception:  # missing package or incompatible version
                    _TLDEXTRACT = False
    return _TLDEXTRACT or None


def split_domain(host: str) -> Tuple[str, str, str]:
    """Split an ASCII hostname into (subdomain, sld, suffix)."""
    extractor = _get_tldextract()
    if extractor is not None:
        try:
            r = extractor(host)
            if r.suffix:
                return r.subdomain, r.domain, r.suffix
        except Exception:
            pass
    labels = host.split(".")
    if len(labels) < 2:
        return "", host, ""
    for n in (3, 2):
        if len(labels) > n and ".".join(labels[-n:]) in KNOWN_SUFFIXES:
            return (".".join(labels[:-n - 1]), labels[-n - 1],
                    ".".join(labels[-n:]))
    return ".".join(labels[:-2]), labels[-2], labels[-1]


def parse_host(hostname: str) -> HostInfo:
    h = (hostname or "").lower().rstrip(".")
    ascii_h = to_ascii_host(h) or h
    is_ip, ip, obf = classify_ip_host(ascii_h)
    if is_ip:
        return HostInfo(host=ascii_h, host_uni=h, is_ip=True, ip=ip,
                        obfuscated_ip=obf, registered_domain=ascii_h)
    sub, sld, suffix = split_domain(ascii_h)
    rd = f"{sld}.{suffix}" if suffix else sld
    return HostInfo(
        host=ascii_h, host_uni=to_unicode_host(ascii_h), subdomain=sub,
        sld=sld, suffix=suffix, registered_domain=rd,
        sub_uni=to_unicode_host(sub), sld_uni=to_unicode_host(sld),
        free_hosting=suffix in FREE_HOSTING_SUFFIXES)


def is_user_content_host(host: str) -> bool:
    return any(host == d or host.endswith("." + d) for d in USER_CONTENT_HOSTS)


def is_allowlisted(info: HostInfo, config: Config) -> bool:
    if info.is_ip or info.free_hosting or is_user_content_host(info.host):
        return False
    return info.registered_domain in config.allowlist


# ---------------------------------------------------------------------------
# Blocklist
# ---------------------------------------------------------------------------

def canonical_url_key(url: str) -> str:
    """Scheme-less, lower-cased key so http/https and trailing '/' still match."""
    url, _ = refang(url)
    url = re.sub(r"^[a-z][a-z0-9+.-]*://", "", url.strip(), flags=re.IGNORECASE)
    return url.lower().rstrip("/")


@dataclass
class Blocklist:
    urls: Set[str] = field(default_factory=set)
    domains: Set[str] = field(default_factory=set)

    @classmethod
    def from_file(cls, path: str) -> "Blocklist":
        bl = cls()
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                line, _ = refang(line)
                if "/" in line or "?" in line:
                    bl.urls.add(canonical_url_key(line))
                else:
                    bl.domains.add(line.lower().rstrip("."))
        return bl

    def match(self, url: str, host: str) -> Optional[str]:
        if canonical_url_key(url) in self.urls:
            return "exact URL"
        parts = host.split(".")
        for i in range(len(parts)):
            if ".".join(parts[i:]) in self.domains:
                return "domain " + ".".join(parts[i:])
        return None


# ---------------------------------------------------------------------------
# Static checks
# ---------------------------------------------------------------------------

def check_scheme(ctx: Ctx) -> List[Indicator]:
    if not ctx.scheme_explicit:
        return [Indicator("info", 0, "No scheme supplied; HTTP(S) assumed")]
    if ctx.scheme == "https":
        return []
    if ctx.scheme == "http":
        return [Indicator("transport", 10, "URL does not use HTTPS")]
    return [Indicator("transport", 15, f"Non-web URL scheme: {ctx.scheme}://")]


def check_length(ctx: Ctx) -> List[Indicator]:
    n = len(ctx.normalized)
    if n > 200:
        return [Indicator("structure", 15, "Extremely long URL")]
    if n > 150:
        return [Indicator("structure", 10, "Very long URL")]
    if n > 100:
        return [Indicator("structure", 5, "Long URL")]
    return []


def check_deception(ctx: Ctx) -> List[Indicator]:
    out: List[Indicator] = []
    p, info = ctx.parsed, ctx.info

    # Userinfo before the host: http://paypal.com@evil.com/
    if "@" in p.netloc and ctx.scheme in ("http", "https"):
        out.append(Indicator(
            "deception", 25,
            "Credentials/userinfo before the host (@ obfuscation); "
            f"the real host is {info.host}"))
        user = unquote(p.username or "").lower()
        if re.search(r"[a-z0-9-]+\.[a-z]{2,}", user) or any(
                b in tokens(user) for b in ctx.config.brands):
            out.append(Indicator(
                "deception", 25,
                "Userinfo looks like a domain/brand name, imitating a trusted site"))

    if info.is_ip:
        out.append(Indicator("deception", 25, "Hostname is an IP address"))
        if info.obfuscated_ip:
            out.append(Indicator(
                "deception", 20,
                f"IP address written in obfuscated form (really {info.ip})"))
        else:
            try:
                ip = ipaddress.ip_address(info.ip)
                if not ip.is_global:
                    out.append(Indicator("info", 0, "IP address is private/reserved"))
            except ValueError:
                pass

    # IDN / homograph
    labels = info.host.split(".")
    if any(l.startswith("xn--") for l in labels) or not info.host.isascii():
        out.append(Indicator(
            "deception", 8,
            f"Internationalized (IDN) hostname: {safe_text(info.host_uni)}"))
        for label in labels:
            if label.startswith("xn--") and to_unicode_host(label) == label:
                out.append(Indicator("deception", 12, f"Malformed punycode label: {label}"))
    for label in info.host_uni.split("."):
        scripts = label_scripts(label)
        if len(scripts) > 1 and not scripts <= {"LATIN", "CJK"}:
            out.append(Indicator(
                "deception", 30,
                f"Label '{safe_text(label)}' mixes scripts ({', '.join(sorted(scripts))})"
                " - possible homograph attack"))
            break

    # Invisible / bidi control characters
    if any(unicodedata.category(ch) in ("Cc", "Cf") for ch in ctx.original):
        out.append(Indicator(
            "deception", 20,
            "Contains invisible or bidirectional control characters"))

    # Backslashes are treated as '/' by browsers: http://good.com\@evil.com
    if "\\" in ctx.original:
        out.append(Indicator("deception", 10, "Contains backslash (browser parsing trick)"))

    if not info.is_ip and re.search(r"[^a-z0-9._\-]", info.host):
        out.append(Indicator("deception", 10, "Hostname contains unusual characters"))
    if not info.is_ip and "." not in info.host:
        out.append(Indicator("structure", 10, "Hostname has no domain suffix"))
    return out


def check_host_structure(ctx: Ctx) -> List[Indicator]:
    info = ctx.info
    if info.is_ip:
        return []
    out: List[Indicator] = []
    host = info.host_uni  # decoded, so 'xn--' prefixes/punycode digits don't count

    depth = len([l for l in info.subdomain.split(".") if l])
    if depth >= 4:
        out.append(Indicator("structure", 15, "Excessive number of subdomains"))
    elif depth == 3:
        out.append(Indicator("structure", 10, "Many subdomains"))
    elif depth == 2:
        out.append(Indicator("structure", 3, "Several subdomains"))

    hyphens = host.count("-")
    if hyphens >= 5:
        out.append(Indicator("structure", 12, "Excessive hyphens in hostname"))
    elif hyphens >= 3:
        out.append(Indicator("structure", 8, "Many hyphens in hostname"))

    if sum(c.isdigit() for c in host) >= 6:
        out.append(Indicator("structure", 10, "Many digits in hostname"))

    if re.search(r"[._-]{3,}", host):
        out.append(Indicator("structure", 8, "Repeated separators in hostname"))

    random_like, entropy = looks_random(info.sld_uni)
    if random_like:
        out.append(Indicator(
            "structure", 10,
            f"Domain label looks randomly generated ('{info.sld_uni}', entropy {entropy:.2f})"))
    return out


def check_lexical(ctx: Ctx) -> List[Indicator]:
    cfg, info, p = ctx.config, ctx.info, ctx.parsed
    out: List[Indicator] = []

    host_text = ascii_fold(info.host_uni)
    host_tokens = set(tokens(host_text))
    host_compact = re.sub(r"[^a-z0-9]", "", host_text)
    path_tokens = set(tokens(ascii_fold(unquote(p.path)))) | set(
        tokens(ascii_fold(unquote(p.query))))
    ctx.host_tokens, ctx.path_tokens = host_tokens, path_tokens

    def hits(words: Iterable[str], toks: Set[str], compact: Optional[str] = None) -> Set[str]:
        found = set()
        for w in words:
            if w in toks or (compact is not None and len(w) >= 6 and w in compact):
                found.add(w)
        return found

    if not info.is_ip:
        strong_h = hits(cfg.keywords_strong, host_tokens, host_compact)
        weak_h = hits(cfg.keywords_weak, host_tokens, host_compact) - strong_h
    else:
        strong_h = weak_h = set()
    strong_p = hits(cfg.keywords_strong, path_tokens)
    weak_p = hits(cfg.keywords_weak, path_tokens) - strong_p
    ctx.strong_hits = strong_h | strong_p

    pts = min(6 * len(strong_h) + 3 * len(weak_h), 20)
    if pts:
        out.append(Indicator("lexical", pts, "Suspicious keywords in hostname: "
                             + ", ".join(sorted(strong_h | weak_h))))
    pts = min(3 * len(strong_p) + len(weak_p), 8)
    if pts:
        out.append(Indicator("lexical", pts, "Suspicious keywords in path/query: "
                             + ", ".join(sorted(strong_p | weak_p))))

    # Another URL embedded in path/query/fragment (the scheme prefix of the
    # URL itself is excluded on purpose).
    embedded = unquote(unquote(p.path + "?" + p.query + "#" + p.fragment)).lower()
    if re.search(r"https?://", embedded):
        out.append(Indicator("lexical", 15, "Contains another URL inside the URL"))

    # Redirect-style parameters, and whether they point off-site.
    params = parse_qsl(p.query, keep_blank_values=True)
    found = sorted({k.lower() for k, _ in params if k.lower() in SUSPICIOUS_PARAMS})
    if found:
        out.append(Indicator("lexical", 10,
                             "Potential redirect parameters: " + ", ".join(found)))
        for key, value in params:
            value = unquote(value)
            if key.lower() in SUSPICIOUS_PARAMS and re.match(r"(?:https?:)?//", value):
                target = urlparse(value if "://" in value else "http:" + value).hostname
                if target and parse_host(target).registered_domain != info.registered_domain:
                    out.append(Indicator(
                        "lexical", 10,
                        f"Redirect parameter points to a different domain ({target})"))
                    break
    return out


def check_hosting(ctx: Ctx) -> List[Indicator]:
    info, cfg = ctx.info, ctx.config
    if info.is_ip:
        return []
    out: List[Indicator] = []
    if info.host in cfg.shorteners or info.registered_domain in cfg.shorteners:
        out.append(Indicator("hosting", 20, "Uses a URL shortening service"))
    if info.free_hosting:
        out.append(Indicator(
            "hosting", 8, f"Hosted on a free hosting / dynamic DNS service ({info.suffix})"))
    if is_user_content_host(info.host):
        out.append(Indicator(
            "hosting", 5, "User-content hosting service (often abused for phishing)"))
    tld = info.suffix.rsplit(".", 1)[-1] if info.suffix else ""
    if tld in cfg.suspicious_tlds:
        out.append(Indicator("hosting", 12, f"Suspicious/high-risk TLD: .{tld}"))
    return out


def check_encoding(ctx: Ctx) -> List[Indicator]:
    out: List[Indicator] = []
    p = ctx.parsed
    hostpart = p.netloc.rsplit("@", 1)[-1]
    if "%" in hostpart:
        out.append(Indicator("structure", 15, "Percent-encoding inside the hostname"))
    path = p.path
    if (re.search(r"%25", path)
            or re.search(r"%(?:3[0-9]|4[1-9a-f]|5[0-9a]|6[1-9a-f]|7[0-9a])", path, re.I)
            or re.search(r"%2e%2e|%2f%2f|%5c", path, re.I)):
        out.append(Indicator(
            "structure", 8,
            "Path hides characters with unnecessary/double encoding"))
    if "//" in path:
        out.append(Indicator("structure", 8, "Contains double slash in path"))
    return out


def check_ports(ctx: Ctx) -> List[Indicator]:
    if ctx.port_invalid:
        return [Indicator("transport", 10, "Invalid port number in URL")]
    port = ctx.port
    if not port:
        return []
    if port in ctx.config.suspicious_ports:
        return [Indicator("transport", 8, f"Uses unusual/sensitive port: {port}")]
    if port not in (80, 443):
        return [Indicator("transport", 4, f"Uses non-standard web port: {port}")]
    return []


def check_path_query(ctx: Ctx) -> List[Indicator]:
    p = ctx.parsed
    out: List[Indicator] = []
    parts = [seg for seg in p.path.split("/") if seg]
    if len(parts) >= 8:
        out.append(Indicator("structure", 10, "Very deep URL path"))
    elif len(parts) >= 5:
        out.append(Indicator("structure", 5, "Deep URL path"))
    n_params = len([x for x in re.split(r"[&;]", p.query) if x])
    if n_params >= 10:
        out.append(Indicator("structure", 10, "Large number of query parameters"))
    elif n_params >= 6:
        out.append(Indicator("structure", 5, "Many query parameters"))
    if len(p.query) > 500:
        out.append(Indicator("structure", 8, "Very long query string"))
    return out


def check_payload(ctx: Ctx) -> List[Indicator]:
    name = unquote(ctx.parsed.path).rsplit("/", 1)[-1].lower()
    if "." not in name:
        return []
    exts = name.split(".")[1:]
    ext = exts[-1]
    out: List[Indicator] = []
    if ext in DANGEROUS_EXTENSIONS:
        out.append(Indicator("payload", 15, f"Links directly to an executable/script file (.{ext})"))
    elif ext in ARCHIVE_EXTENSIONS:
        out.append(Indicator("payload", 10, f"Links directly to an archive/disk image (.{ext})"))
    if len(exts) >= 2 and exts[-2] in DOCUMENT_EXTENSIONS and (
            ext in DANGEROUS_EXTENSIONS or ext in ARCHIVE_EXTENSIONS):
        out.append(Indicator("payload", 15, f"Double extension disguises file type (.{exts[-2]}.{ext})"))
    return out


def check_brand(ctx: Ctx) -> List[Indicator]:
    """Brand impersonation, typosquatting and homoglyph detection."""
    cfg, info = ctx.config, ctx.info
    if info.is_ip:
        return []
    rd = info.registered_domain
    sub_fold = ascii_fold(info.sub_uni)
    sld_fold = ascii_fold(info.sld_uni)
    sub_tokens = set(tokens(sub_fold))
    sld_tokens = set(tokens(sld_fold))
    sub_compact = re.sub(r"[^a-z0-9]", "", sub_fold)
    sld_compact = re.sub(r"[^a-z0-9]", "", sld_fold)
    sub_dotted = "." + info.subdomain + "."

    candidates: Dict[str, Indicator] = {}

    def offer(brand: str, points: int, message: str, deliberate: bool = False) -> None:
        # Common-word brands ('apple', 'chase') are weak evidence on their own,
        # unless the spelling itself was deliberately disguised.
        if brand in AMBIGUOUS_BRANDS and not deliberate and points <= 40:
            points = max(points - 15, 8)
        cur = candidates.get(brand)
        if cur is None or points > cur.points:
            candidates[brand] = Indicator("brand", points, message)

    for brand, legit in cfg.brands.items():
        if rd in legit or any(info.host.endswith("." + d) for d in legit):
            continue

        # The official domain embedded in a subdomain: paypal.com.evil.xyz
        for d in legit:
            if f".{d}." in sub_dotted:
                offer(brand, 40,
                      f"Official domain '{d}' appears inside the subdomain of unrelated domain {rd}")

        if brand in sub_tokens:
            offer(brand, 40, f"Brand '{brand}' used as a subdomain of unrelated domain {rd}")
        elif brand in sld_tokens:
            offer(brand, 35, f"Brand '{brand}' used in domain {rd}, which is not an official domain")
        elif len(brand) >= 6 and (brand in sub_compact or brand in sld_compact):
            offer(brand, 22, f"Hostname contains brand name '{brand}' but {rd} is not official")

        # Homoglyphs and typosquats against the registered label.
        for cand in {info.sld_uni, info.sld_uni.replace("-", "")}:
            folded = ascii_fold(cand)
            if folded == brand and cand != brand:
                offer(brand, 55,
                      f"Domain label '{safe_text(cand)}' uses look-alike characters to imitate '{brand}'",
                      deliberate=True)
            elif folded != brand and len(brand) >= 4 and skeleton(folded) == skeleton(brand):
                offer(brand, 40,
                      f"Domain label '{safe_text(cand)}' is a character-substitution look-alike of '{brand}'",
                      deliberate=True)
            elif folded != brand:
                dist = damerau_levenshtein(folded, brand)
                if (len(brand) >= 9 and dist <= 2) or (len(brand) >= 6 and dist <= 1):
                    offer(brand, 30,
                          f"Possible typosquat of '{brand}': '{safe_text(cand)}' (edit distance {dist})")

        if brand in ctx.path_tokens and brand not in candidates:
            offer(brand, 12, f"Brand name '{brand}' appears in the URL path but {rd} is unrelated")

    out = sorted(candidates.values(), key=lambda i: -i.points)[:2]
    if out and out[0].points >= 20 and ctx.strong_hits:
        out.append(Indicator(
            "brand", 10,
            "Brand impersonation combined with credential keywords ("
            + ", ".join(sorted(ctx.strong_hits)) + ")"))
    return out


STATIC_CHECKS = (
    check_scheme, check_length, check_deception, check_host_structure,
    check_lexical, check_hosting, check_encoding, check_ports,
    check_path_query, check_payload, check_brand,
)


def run_static_checks(ctx: Ctx) -> List[Indicator]:
    out: List[Indicator] = []
    for fn in STATIC_CHECKS:
        try:
            out.extend(fn(ctx))
        except Exception as exc:  # one broken check must not sink a batch
            log.debug("check %s failed", fn.__name__, exc_info=True)
            out.append(Indicator("info", 0, f"Internal error in {fn.__name__}: {exc.__class__.__name__}"))
    return out


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def compute_score(indicators: Iterable[Indicator], config: Config, allowlisted: bool) -> int:
    inds = list(indicators)
    if any(i.points >= 100 for i in inds):
        return 100
    totals: Dict[str, float] = {}
    for ind in inds:
        if ind.points > 0:
            totals[ind.category] = totals.get(ind.category, 0) + ind.points
    score = 0.0
    for cat, pts in totals.items():
        cap = config.category_caps.get(cat)
        if cap is not None:
            pts = min(pts, cap)
        if allowlisted and cat in SOFT_CATEGORIES:
            pts *= config.allowlist_factor
        score += pts
    return int(min(100, round(score)))


def classify(score: int, config: Config) -> str:
    if score >= config.high_threshold:
        return CLASS_HIGH
    if score >= config.medium_threshold:
        return CLASS_MEDIUM
    return CLASS_LOW


def _finalize(result: Result, config: Config) -> Result:
    result.score = compute_score(result.indicators, config, result.allowlisted)
    result.classification = classify(result.score, config)
    if result.allowlisted:
        result.indicators.append(Indicator(
            "info", 0, "Registered domain is on the allowlist; heuristic score reduced"))
    result.indicators.sort(key=lambda i: -i.points)  # stable
    return result


def _invalid(result: Result, message: str, cls: str = CLASS_INVALID, score: int = 100) -> Result:
    result.score = score
    result.classification = cls
    result.indicators = [Indicator("deception", score, message)] if score else [Indicator("info", 0, message)]
    return result


# ---------------------------------------------------------------------------
# Network layer (stdlib only)
# ---------------------------------------------------------------------------

def _run_with_timeout(fn, timeout: float, *args):
    """Run fn(*args) in a daemon thread; raise TimeoutError if it overruns."""
    box: dict = {}

    def target():
        try:
            box["value"] = fn(*args)
        except BaseException as exc:  # propagate to caller
            box["error"] = exc

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise TimeoutError("timed out")
    if "error" in box:
        raise box["error"]
    return box["value"]


@lru_cache(maxsize=4096)
def resolve_host(host: str, timeout: float = 5.0) -> Tuple[Tuple[str, ...], Optional[str]]:
    """Resolve host -> (ips, error).  Cached and time-limited."""
    try:
        ipaddress.ip_address(host.strip("[]"))
        return (host.strip("[]"),), None
    except ValueError:
        pass
    try:
        infos = _run_with_timeout(socket.getaddrinfo, timeout, host, None, 0, socket.SOCK_STREAM)
    except socket.gaierror:
        return (), "DNS resolution failed (name does not resolve)"
    except TimeoutError:
        return (), "DNS lookup timed out"
    except (OSError, UnicodeError) as exc:
        return (), f"DNS lookup could not be completed ({exc.__class__.__name__})"
    ips = sorted({i[4][0].split("%")[0] for i in infos if i[4]})
    if not ips:
        return (), "Hostname did not resolve to an IP address"
    return tuple(ips), None


def is_public_ip(ip: str) -> bool:
    """True only for globally routable unicast addresses."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return bool(addr.is_global and not addr.is_multicast)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Connects to a pre-validated IP, defeating DNS-rebinding between
    the safety check and the connection."""

    def __init__(self, host, port, ip, timeout):
        super().__init__(host, port, timeout=timeout)
        self._pinned_ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, ip, timeout, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self._pinned_ip = ip

    def connect(self):
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


@dataclass
class HopResponse:
    status: int
    location: Optional[str]
    content_type: str
    body: bytes
    cert: Optional[dict] = None
    tls_error: Optional[str] = None


def _unverified_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch_hop(url: str, ip: str, timeout: float, body_limit: int = 0) -> HopResponse:
    """GET one URL (no redirect following) via a pinned IP.  The body is
    only read for non-redirect responses and never beyond body_limit."""
    p = urlparse(url)
    scheme = p.scheme.lower()
    host = to_ascii_host(p.hostname or "")
    if not host:
        raise ValueError("unusable hostname")
    port = p.port or (443 if scheme == "https" else 80)
    target = (p.path or "/") + ("?" + p.query if p.query else "")
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.8",
               "Connection": "close"}

    contexts = [ssl.create_default_context(), _unverified_context()] if scheme == "https" else [None]
    tls_error: Optional[str] = None
    last_exc: Optional[BaseException] = None
    for attempt, ctx in enumerate(contexts):
        conn = (_PinnedHTTPSConnection(host, port, ip, timeout, ctx) if ctx is not None
                else _PinnedHTTPConnection(host, port, ip, timeout))
        try:
            conn.request("GET", target, headers=headers)
            resp = conn.getresponse()
            cert = None
            if ctx is not None and attempt == 0 and conn.sock is not None:
                try:
                    cert = conn.sock.getpeercert()
                except (ValueError, AttributeError):
                    cert = None
            location = resp.getheader("Location")
            ctype = resp.getheader("Content-Type") or ""
            redirect = 300 <= resp.status < 400 and bool(location)
            body = resp.read(body_limit) if (body_limit and not redirect) else b""
            return HopResponse(resp.status, location, ctype, body, cert, tls_error)
        except ssl.SSLCertVerificationError as exc:
            tls_error = getattr(exc, "verify_message", None) or str(exc)
            last_exc = exc
        finally:
            conn.close()
    raise last_exc if last_exc else OSError("request failed")


def cert_age_days(cert: dict) -> Optional[int]:
    try:
        issued = ssl.cert_time_to_seconds(cert["notBefore"])
    except (KeyError, ValueError, TypeError):
        return None
    return max(0, int((time.time() - issued) / 86400))


@dataclass
class ChainOutcome:
    chain: List[str]
    final_url: str = ""
    response: Optional[HopResponse] = None
    indicators: List[Indicator] = field(default_factory=list)
    resolved: Dict[str, Tuple[str, ...]] = field(default_factory=dict)
    reached: bool = False


def follow_chain(start_url: str, options: Options, want_body: bool) -> ChainOutcome:
    """Follow redirects manually, validating every hop."""
    out = ChainOutcome(chain=[start_url])
    current, seen, redirects = start_url, {start_url}, 0
    tls_warned: Set[str] = set()

    while True:
        p = urlparse(current)
        scheme = (p.scheme or "").lower()
        host = p.hostname
        if scheme not in ("http", "https") or not host:
            if redirects:
                out.indicators.append(Indicator("network", 15, "Redirects to a non-HTTP(S) target"))
            else:
                out.indicators.append(Indicator("info", 0, "Network fetch skipped: not an HTTP(S) URL"))
            break

        lookup = to_ascii_host(host) or host
        ips, err = resolve_host(lookup, options.timeout)
        out.resolved[lookup] = ips
        if err or not ips:
            if redirects:
                out.indicators.append(Indicator("network", 8, f"Redirect target {host} did not resolve"))
            break

        usable = list(ips) if options.allow_private else [ip for ip in ips if is_public_ip(ip)]
        if not usable:
            if redirects:
                out.indicators.append(Indicator(
                    "network", 20, f"Redirects to a non-public/internal address ({host})"))
            else:
                out.indicators.append(Indicator(
                    "info", 0, "Network fetch skipped: host resolves to a non-public address"))
            break

        try:
            resp = fetch_hop(current, usable[0], options.timeout,
                             options.body_limit if want_body else 0)
        except (OSError, http.client.HTTPException, ValueError) as exc:
            out.indicators.append(Indicator(
                "info", 0, f"HTTP request to {host} failed ({exc.__class__.__name__})"))
            break
        out.reached = True

        if resp.tls_error and host not in tls_warned:
            tls_warned.add(host)
            out.indicators.append(Indicator(
                "tls", 15, f"TLS certificate verification failed for {host}: {resp.tls_error}"))
        if resp.cert:
            age = cert_age_days(resp.cert)
            if age is not None and age <= 7:
                out.indicators.append(Indicator(
                    "tls", 8, f"TLS certificate for {host} was issued {age} day(s) ago"))

        if resp.status in (301, 302, 303, 307, 308) and resp.location:
            nxt = urljoin(current, resp.location.strip())
            redirects += 1
            if redirects > options.max_redirects:
                out.indicators.append(Indicator(
                    "network", 10, f"More than {options.max_redirects} redirects; stopped following"))
                break
            if nxt in seen:
                out.indicators.append(Indicator("network", 8, "Redirect loop detected"))
                break
            seen.add(nxt)
            out.chain.append(nxt)
            current = nxt
            continue

        out.response = resp
        break

    out.final_url = out.chain[-1]
    return out


# --- page content ----------------------------------------------------------

class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self._in_title = False
        self.forms: List[dict] = []
        self._form: Optional[dict] = None
        self.password_fields = 0
        self.meta_refresh: Optional[str] = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "password": 0}
            self.forms.append(self._form)
        elif tag == "input" and a.get("type", "text").lower() == "password":
            self.password_fields += 1
            if self._form is not None:
                self._form["password"] += 1
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            m = re.search(r"url\s*=\s*(\S+)", a.get("content", ""), re.I)
            if m:
                self.meta_refresh = m.group(1).strip("'\"")

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "form":
            self._form = None

    def handle_data(self, data):
        if self._in_title and len(self.title) < 200:
            self.title += data


def content_indicators(body: bytes, content_type: str, final_url: str,
                       config: Config) -> List[Indicator]:
    ctype = (content_type or "").lower()
    if ctype and "html" not in ctype and "xml" not in ctype:
        return []
    m = re.search(r"charset=([\w-]+)", ctype)
    try:
        text = body.decode(m.group(1) if m else "utf-8", errors="replace")
    except LookupError:
        text = body.decode("utf-8", errors="replace")
    parser = _PageParser()
    try:
        parser.feed(text)
        parser.close()
    except Exception:  # HTMLParser is lenient; guard anyway
        pass

    final_info = parse_host(urlparse(final_url).hostname or "")
    if is_allowlisted(final_info, config):
        return []
    out: List[Indicator] = []

    if parser.password_fields:
        out.append(Indicator("content", 8, "Page contains a password field"))

    for form in parser.forms:
        action = form["action"].strip()
        if not action or action.startswith(("#", "javascript:")):
            continue
        target = urlparse(urljoin(final_url, action))
        if target.scheme not in ("http", "https") or not target.hostname:
            continue
        target_rd = parse_host(target.hostname).registered_domain
        if target_rd != final_info.registered_domain:
            out.append(Indicator(
                "content", 30 if form["password"] else 20,
                f"Form submits {'a password ' if form['password'] else ''}to a different domain ({target_rd})"))
            break
        if form["password"] and target.scheme == "http" and urlparse(final_url).scheme == "https":
            out.append(Indicator("content", 12, "Password form submits over insecure HTTP"))
            break

    title_tokens = set(tokens(ascii_fold(parser.title)))
    for brand, legit in config.brands.items():
        if len(brand) >= 4 and brand in title_tokens and final_info.registered_domain not in legit:
            out.append(Indicator(
                "content", 25,
                f"Page title mentions '{brand}' but {final_info.registered_domain} is not an official domain"))
            break

    if parser.meta_refresh:
        out.append(Indicator("info", 0, f"Page uses a meta-refresh redirect (not followed): {safe_text(parser.meta_refresh)[:80]}"))
    return out


# --- RDAP / threat intel ---------------------------------------------------

def _http_json(url: str, *, method: str = "GET", headers: Optional[dict] = None,
               payload: Optional[dict] = None, timeout: float = REQUEST_TIMEOUT) -> dict:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    hdrs.update(headers or {})
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec - fixed https hosts
        raw = resp.read(2_000_000)
    return json.loads(raw.decode("utf-8", "replace") or "{}")


@lru_cache(maxsize=2048)
def rdap_age_days(domain: str, timeout: float = REQUEST_TIMEOUT) -> Tuple[Optional[int], Optional[str]]:
    """Return (age_in_days, error) from RDAP registration event."""
    try:
        data = _http_json("https://rdap.org/domain/" + quote(domain), timeout=timeout,
                          headers={"Accept": "application/rdap+json"})
    except urllib.error.HTTPError as exc:
        return None, f"RDAP lookup failed (HTTP {exc.code})"
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return None, f"RDAP lookup failed ({exc.__class__.__name__})"
    for event in data.get("events", []):
        if event.get("eventAction") == "registration" and event.get("eventDate"):
            try:
                dt = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
            except ValueError:
                continue
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return max(0, (datetime.now(timezone.utc) - dt).days), None
    return None, "RDAP record has no registration date"


def check_safe_browsing(url: str, api_key: str, timeout: float) -> List[str]:
    body = {
        "client": {"clientId": "phishguard", "clientVersion": __version__},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    data = _http_json(
        "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + quote(api_key),
        method="POST", payload=body, timeout=timeout)
    return sorted({m.get("threatType", "UNKNOWN") for m in data.get("matches", [])})


def check_virustotal(url: str, api_key: str, timeout: float) -> Optional[dict]:
    """Return last_analysis_stats, or None when VirusTotal has no report."""
    url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
    try:
        data = _http_json("https://www.virustotal.com/api/v3/urls/" + url_id,
                          headers={"x-apikey": api_key}, timeout=timeout)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise
    return data["data"]["attributes"]["last_analysis_stats"]


def intel_indicators(urls: Iterable[str], options: Options) -> List[Indicator]:
    out: List[Indicator] = []
    for url in urls:
        label = safe_text(url)[:60]
        if options.gsb_key:
            try:
                threats = check_safe_browsing(url, options.gsb_key, options.timeout)
                if threats:
                    out.append(Indicator(
                        "intel", 60, f"Google Safe Browsing flags {label}: {', '.join(threats)}"))
            except (urllib.error.URLError, OSError, ValueError, KeyError) as exc:
                out.append(Indicator("info", 0, f"Safe Browsing lookup failed ({exc.__class__.__name__})"))
        if options.vt_key:
            try:
                stats = check_virustotal(url, options.vt_key, options.timeout)
                if stats is None:
                    out.append(Indicator("info", 0, "VirusTotal has no report for this URL"))
                else:
                    mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
                    if mal >= 3:
                        out.append(Indicator("intel", 55, f"VirusTotal: {mal} engines flag {label} as malicious"))
                    elif mal >= 1:
                        out.append(Indicator("intel", 30, f"VirusTotal: {mal} engine(s) flag {label} as malicious"))
                    elif sus >= 3:
                        out.append(Indicator("intel", 15, f"VirusTotal: {sus} engines flag {label} as suspicious"))
            except (urllib.error.URLError, OSError, ValueError, KeyError) as exc:
                out.append(Indicator("info", 0, f"VirusTotal lookup failed ({exc.__class__.__name__})"))
    return out


# ---------------------------------------------------------------------------
# Analysis driver
# ---------------------------------------------------------------------------

def _build_context(url: str, config: Config) -> Tuple[Result, Optional[Ctx]]:
    result = Result(url=url.strip(), final_url=url.strip())
    cleaned, defanged = refang(url)

    special = detect_special_scheme(cleaned)
    if special in DANGEROUS_SCHEMES:
        return _invalid(result, f"Dangerous URL scheme: {special}:", CLASS_HIGH), None
    if special in NON_WEB_SCHEMES:
        return _invalid(result, f"Not a web URL ({special}:)", CLASS_NOT_WEB, 0), None

    normalized, explicit = normalize_url(cleaned)
    result.normalized_url = result.final_url = normalized
    try:
        parsed = urlparse(normalized)
        hostname = (parsed.hostname or "").lower().rstrip(".")
    except ValueError as exc:
        return _invalid(result, f"URL parsing failed: {exc}"), None
    if not hostname:
        return _invalid(result, "No valid hostname found"), None

    try:
        port, port_invalid = parsed.port, False
    except ValueError:
        port, port_invalid = None, True

    info = parse_host(hostname)
    result.hostname = info.host
    result.hostname_unicode = info.host_uni
    result.registered_domain = info.registered_domain
    result.ip_address = info.is_ip
    result.allowlisted = is_allowlisted(info, config)

    ctx = Ctx(original=cleaned, normalized=normalized, scheme_explicit=explicit,
              parsed=parsed, scheme=(parsed.scheme or "").lower(), info=info,
              config=config, port=port, port_invalid=port_invalid)
    result.ctx = ctx
    if defanged:
        result.indicators.append(Indicator("info", 0, "Input was defanged (hxxp / [.]); refanged for analysis"))
    return result, ctx


def _apply_network(result: Result, ctx: Ctx, config: Config, options: Options) -> None:
    info = ctx.info
    need_fetch = options.redirects or options.content

    # DNS (also done implicitly during fetching)
    if options.dns or need_fetch:
        lookup = info.ip if info.is_ip else info.host
        ips, err = resolve_host(lookup, options.timeout)
        result.resolved_ips = list(ips)
        if err:
            result.indicators.append(Indicator("dns", 8, err))
        else:
            if any(not _is_global(ip) for ip in ips) and not info.is_ip:
                result.indicators.append(Indicator(
                    "dns", 10, "Public hostname resolves to a private/reserved address"))
            if len(ips) > 8:
                result.indicators.append(Indicator(
                    "dns", 5, f"Hostname resolves to many addresses ({len(ips)}); possible fast-flux"))

    final_url = ctx.normalized
    outcome: Optional[ChainOutcome] = None
    if need_fetch:
        starts = [ctx.normalized]
        if not ctx.scheme_explicit:
            starts = ["https://" + ctx.normalized[len("http://"):], ctx.normalized]
        for start in starts:
            outcome = follow_chain(start, options, want_body=options.content)
            if outcome.reached:
                break
        assert outcome is not None
        result.indicators.extend(outcome.indicators)
        result.redirect_chain = list(dict.fromkeys(outcome.chain))
        final_url = outcome.final_url
        result.final_url = final_url
        if len(result.resolved_ips) == 0:
            for ips in outcome.resolved.values():
                result.resolved_ips = list(ips)
                break

        hops = len(outcome.chain) - 1
        if hops >= 3:
            result.indicators.append(Indicator("network", 12, f"Long redirect chain ({hops} redirects)"))

        final_info = parse_host(urlparse(final_url).hostname or "")
        if hops and final_info.registered_domain != info.registered_domain:
            is_short = info.host in config.shorteners or info.registered_domain in config.shorteners
            if not is_short:
                result.indicators.append(Indicator(
                    "network", 10,
                    f"Final destination is on a different domain ({final_info.registered_domain})"))
            # Judge the destination on its own merits.
            dest = analyze_url(final_url, config=config, options=Options())
            if dest.score >= config.medium_threshold:
                result.indicators.append(Indicator(
                    "network", min(30, dest.score // 2),
                    f"Final destination {safe_text(final_url)[:70]} scores {dest.score}/100 on its own"))

        if options.content and outcome.response and outcome.response.status < 400 and outcome.response.body:
            result.indicators.extend(content_indicators(
                outcome.response.body, outcome.response.content_type, final_url, config))

    # Domain age
    if options.rdap:
        domains = {info.registered_domain}
        if outcome is not None:
            fi = parse_host(urlparse(final_url).hostname or "")
            domains.add(fi.registered_domain)
        for dom in sorted(domains):
            di = parse_host(dom)
            if di.is_ip or not di.suffix or is_allowlisted(di, config) or dom in config.shorteners:
                continue
            age, err = rdap_age_days(to_ascii_host(dom) or dom, options.timeout)
            if err:
                result.indicators.append(Indicator("info", 0, f"{dom}: {err}"))
            elif age is not None:
                if age < 30:
                    result.indicators.append(Indicator("age", 25, f"Domain {dom} was registered only {age} day(s) ago"))
                elif age < 90:
                    result.indicators.append(Indicator("age", 15, f"Domain {dom} is young ({age} days old)"))
                elif age < 180:
                    result.indicators.append(Indicator("age", 8, f"Domain {dom} is under 6 months old ({age} days)"))

    # Threat intelligence
    if options.gsb_key or options.vt_key:
        targets = [ctx.normalized] + ([final_url] if final_url != ctx.normalized else [])
        result.indicators.extend(intel_indicators(targets, options))


def _is_global(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def analyze_url(url: str, resolve_dns: bool = False, follow_redirects: bool = False,
                config: Optional[Config] = None, options: Optional[Options] = None) -> Result:
    """Analyze a URL and return a Result.

    resolve_dns / follow_redirects are kept for compatibility with PhishGuard 2.x;
    pass an Options object for the full feature set.
    """
    config = config or get_default_config()
    if options is None:
        options = Options(dns=resolve_dns, redirects=follow_redirects)

    result, ctx = _build_context(url, config)
    if ctx is None:
        return result

    result.indicators.extend(run_static_checks(ctx))

    if options.blocklist is not None:
        hit = options.blocklist.match(ctx.normalized, ctx.info.host)
        if hit:
            result.indicators.append(Indicator("intel", 70, f"Matches local blocklist ({hit})"))

    if options.uses_network:
        try:
            _apply_network(result, ctx, config, options)
        except Exception as exc:  # network layer must never crash a batch
            log.debug("network analysis failed", exc_info=True)
            result.indicators.append(Indicator(
                "info", 0, f"Network analysis aborted ({exc.__class__.__name__})"))
    return _finalize(result, config)


# ---------------------------------------------------------------------------
# I/O helpers and reporting
# ---------------------------------------------------------------------------

def read_urls(source: str) -> List[str]:
    """Read URLs from a file ('-' = stdin), skipping comments and duplicates."""
    if source == "-":
        lines = sys.stdin.read().splitlines()
    else:
        with open(source, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    seen: Set[str] = set()
    urls: List[str] = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#") and line not in seen:
            seen.add(line)
            urls.append(line)
    return urls


def read_urls_from_file(filename: str) -> List[str]:  # 2.x compatibility
    return read_urls(filename)


def print_result(result: Result) -> None:
    print("\n" + "=" * 72)
    print("PHISHGUARD URL ANALYSIS")
    print("=" * 72)
    print(f"URL            : {safe_text(result.url)}")
    host = safe_text(result.hostname)
    if result.hostname_unicode and result.hostname_unicode != result.hostname:
        host += f"  ({safe_text(result.hostname_unicode)})"
    print(f"Hostname       : {host}")
    if result.registered_domain and not result.ip_address:
        print(f"Registered dom.: {safe_text(result.registered_domain)}")
    print(f"Risk Score     : {result.score}/100")
    print(f"Classification : {result.classification}")
    if result.resolved_ips:
        print("Resolved IPs   : " + ", ".join(result.resolved_ips[:8]))
    if len(result.redirect_chain) > 1:
        print("\nRedirect Chain:")
        for i, item in enumerate(result.redirect_chain, 1):
            print(f"  {i}. {safe_text(item)}")
    print("\nDetection Indicators:")
    if result.indicators:
        for ind in result.indicators:
            tag = "[i]" if ind.points == 0 else "[!]"
            pts = f"(+{ind.points})" if ind.points else "     "
            print(f"  {tag} {pts:<6} {safe_text(ind.message)}")
    else:
        print("  [+] No suspicious indicators detected.")
    print("=" * 72)


def print_batch(results: List[Result], verbose: bool) -> None:
    print("\n" + "=" * 90)
    print("BATCH SCAN RESULTS")
    print("=" * 90)
    print(f"{'SCORE':<8}{'CLASSIFICATION':<28}URL")
    print("-" * 90)
    for r in results:
        print(f"{r.score:<8}{r.classification:<28}{safe_text(r.url)}")
        if verbose:
            for ind in r.indicators:
                if ind.points:
                    print(f"{'':<8}  (+{ind.points}) {safe_text(ind.message)}")
    print("=" * 90)


def write_json(results: List[Result], filename: str) -> None:
    payload = [r.to_dict() for r in results]
    if filename == "-":
        json.dump(payload, sys.stdout, indent=2)
        print()
        return
    with open(filename, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def write_csv(results: List[Result], filename: str) -> None:
    with open(filename, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["url", "hostname", "registered_domain", "score",
                         "classification", "resolved_ips", "final_url", "reasons"])
        for r in results:
            writer.writerow([
                csv_safe(r.url), csv_safe(r.hostname), csv_safe(r.registered_domain),
                r.score, csv_safe(r.classification),
                csv_safe("; ".join(r.resolved_ips)), csv_safe(r.final_url),
                csv_safe("; ".join(r.reasons)),
            ])


def evaluate(good: List[str], bad: List[str], config: Config) -> dict:
    """Score labelled URL sets offline and report precision/recall by threshold."""
    opts = Options()
    good_scores = [analyze_url(u, config=config, options=opts).score for u in good]
    bad_scores = [analyze_url(u, config=config, options=opts).score for u in bad]

    def metrics(th: int) -> dict:
        tp = sum(s >= th for s in bad_scores)
        fn = len(bad_scores) - tp
        fp = sum(s >= th for s in good_scores)
        tn = len(good_scores) - fp
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        return {"threshold": th, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
                "precision": precision, "recall": recall, "f1": f1}

    sweep = [metrics(t) for t in range(5, 100, 5)]
    # ties -> highest threshold, i.e. the one that raises the fewest false alarms
    best = max(sweep, key=lambda m: (m["f1"], m["threshold"])) if sweep else None
    return {"good": len(good_scores), "bad": len(bad_scores),
            "medium": metrics(config.medium_threshold),
            "high": metrics(config.high_threshold),
            "sweep": sweep, "best": best}


def print_evaluation(report: dict, config: Config) -> None:
    print(f"\nEvaluation: {report['good']} benign, {report['bad']} phishing URLs (offline)")
    print(f"{'threshold':<11}{'TP':>5}{'FP':>5}{'TN':>5}{'FN':>5}{'precision':>11}{'recall':>9}{'F1':>7}")
    marks = {config.medium_threshold: "  <- medium", config.high_threshold: "  <- high"}
    rows = {m["threshold"]: m for m in report["sweep"]}
    rows[config.medium_threshold] = report["medium"]
    rows[config.high_threshold] = report["high"]
    for th in sorted(rows):
        m = rows[th]
        print(f"{th:<11}{m['tp']:>5}{m['fp']:>5}{m['tn']:>5}{m['fn']:>5}"
              f"{m['precision']:>11.2f}{m['recall']:>9.2f}{m['f1']:>7.2f}{marks.get(th, '')}")
    if report["best"]:
        print(f"\nBest F1 at threshold {report['best']['threshold']} "
              f"(F1 {report['best']['f1']:.2f}).  Use --medium / --high or a --config file to apply.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_arguments(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="PHISHGUARD - Phishing URL Detection Tool",
        epilog="Exit status: 0 = ok, 1 = a URL met the --fail-on level, 2 = usage/IO error.")
    parser.add_argument("--version", action="version", version=f"PhishGuard {__version__}")

    src = parser.add_mutually_exclusive_group()
    src.add_argument("-u", "--url", action="append", help="URL to analyze (repeatable)")
    src.add_argument("-f", "--file", help="File with one URL per line ('-' reads stdin)")
    src.add_argument("--evaluate", nargs=2, metavar=("GOOD_FILE", "BAD_FILE"),
                     help="Score labelled benign/phishing URL files and report precision/recall")

    net = parser.add_argument_group("network checks (disabled by --offline)")
    net.add_argument("--offline", action="store_true", help="Disable every network check")
    net.add_argument("--dns", action="store_true", help="Resolve the hostname")
    net.add_argument("--redirects", action="store_true",
                     help="Follow redirects (SSRF-guarded) and inspect TLS certificates")
    net.add_argument("--content", action="store_true",
                     help="Fetch the landing page and inspect forms/title (implies --redirects)")
    net.add_argument("--rdap", action="store_true", help="Look up domain registration age via RDAP")
    net.add_argument("--full", action="store_true", help="Enable --dns --redirects --content --rdap")
    net.add_argument("--gsb-key", default=os.environ.get("GOOGLE_SAFE_BROWSING_KEY"),
                     help="Google Safe Browsing API key (env GOOGLE_SAFE_BROWSING_KEY); sends the URL to Google")
    net.add_argument("--vt-key", default=os.environ.get("VT_API_KEY"),
                     help="VirusTotal API key (env VT_API_KEY); sends the URL to VirusTotal")
    net.add_argument("--timeout", type=float, default=REQUEST_TIMEOUT, help="Network timeout in seconds")
    net.add_argument("--max-redirects", type=int, default=MAX_REDIRECTS)
    net.add_argument("--allow-private-targets", action="store_true",
                     help="Disable SSRF protection (only for authorized lab/internal scanning)")

    tune = parser.add_argument_group("tuning")
    tune.add_argument("--config", metavar="FILE", help="JSON config (see --dump-config)")
    tune.add_argument("--dump-config", action="store_true", help="Print the default config as JSON and exit")
    tune.add_argument("--allowlist", metavar="FILE", help="Trusted domains (one per line or Tranco CSV)")
    tune.add_argument("--blocklist", metavar="FILE", help="Known-bad URLs/domains (one per line)")
    tune.add_argument("--medium", type=int, help="Medium-risk score threshold")
    tune.add_argument("--high", type=int, help="High-risk score threshold")

    out = parser.add_argument_group("output")
    out.add_argument("--json", metavar="FILE", help="Write JSON results ('-' = stdout only)")
    out.add_argument("--csv", metavar="FILE", help="Write CSV results")
    out.add_argument("--verbose", action="store_true", help="Show indicators for every URL in batch mode")
    out.add_argument("--quiet", action="store_true", help="No banner or console report")
    out.add_argument("--workers", type=int, default=0, help="Parallel workers for batch scans (default: auto)")
    out.add_argument("--fail-on", choices=("none", "medium", "high"), default="high",
                     help="Exit with status 1 if any URL reaches this level (default: high)")
    out.add_argument("--debug", action="store_true", help="Debug logging")
    return parser.parse_args(argv)


def _die(message: str, code: int = 2) -> int:
    print(f"[ERROR] {message}", file=sys.stderr)
    return code


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_arguments(argv)
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.WARNING,
                        format="%(levelname)s: %(message)s")

    try:
        config = load_config(args.config) if args.config else Config()
        if args.medium is not None:
            config.medium_threshold = args.medium
        if args.high is not None:
            config.high_threshold = args.high
        config.validate()
        if args.allowlist:
            config.allowlist |= load_domain_list(args.allowlist)
        blocklist = Blocklist.from_file(args.blocklist) if args.blocklist else None
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return _die(f"Configuration problem: {exc}")

    if args.dump_config:
        print(json.dumps(config.to_dict(), indent=2))
        return 0

    json_stdout = args.json == "-"
    quiet = args.quiet or json_stdout

    def say(*a, **k):
        if not quiet:
            print(*a, **k)

    if args.evaluate:
        try:
            good, bad = read_urls(args.evaluate[0]), read_urls(args.evaluate[1])
        except OSError as exc:
            return _die(f"Could not read file: {exc}")
        print_evaluation(evaluate(good, bad, config), config)
        return 0

    say("=" * 72)
    say("             PHISHGUARD - PHISHING URL DETECTOR")
    say(f"                       Version {__version__}")
    say("=" * 72)

    # ---- collect URLs
    try:
        if args.url:
            urls = list(dict.fromkeys(u.strip() for u in args.url if u.strip()))
        elif args.file:
            urls = read_urls(args.file)
        elif sys.stdin.isatty():
            entered = input("\nEnter URL: ").strip()
            urls = [entered] if entered else []
        else:
            urls = read_urls("-")
    except OSError as exc:
        return _die(f"Could not read file: {exc}")
    except (KeyboardInterrupt, EOFError):
        print("\nExiting.")
        return 0
    if not urls:
        print("No URLs to analyze.", file=sys.stderr)
        return 2

    # ---- options
    options = Options(
        dns=args.dns or args.full, redirects=args.redirects or args.content or args.full,
        content=args.content or args.full, rdap=args.rdap or args.full,
        gsb_key=args.gsb_key, vt_key=args.vt_key, blocklist=blocklist,
        timeout=args.timeout, max_redirects=args.max_redirects,
        allow_private=args.allow_private_targets)
    if args.offline:
        if options.uses_network:
            print("[!] --offline set: network checks disabled.", file=sys.stderr)
        options.dns = options.redirects = options.content = options.rdap = False
        options.gsb_key = options.vt_key = None
    if options.allow_private:
        print("[!] SSRF protection is disabled (--allow-private-targets).", file=sys.stderr)

    workers = args.workers or (8 if options.uses_network and len(urls) > 1 else 1)

    def work(u: str) -> Result:
        try:
            return analyze_url(u, config=config, options=options)
        except Exception as exc:  # last-resort guard so one URL can't kill a batch
            log.debug("analysis crashed", exc_info=True)
            r = Result(url=u)
            return _invalid(r, f"Analysis error: {exc.__class__.__name__}")

    if workers > 1:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(work, urls))
    else:
        results = [work(u) for u in urls]

    # ---- report
    if not quiet:
        if len(results) == 1:
            print_result(results[0])
        else:
            print_batch(results, args.verbose)

    if args.json:
        try:
            write_json(results, args.json)
            say(f"[+] JSON report saved to: {args.json}")
        except OSError as exc:
            print(f"[ERROR] Could not write JSON report: {exc}", file=sys.stderr)
    if args.csv:
        try:
            write_csv(results, args.csv)
            say(f"[+] CSV report saved to: {args.csv}")
        except OSError as exc:
            print(f"[ERROR] Could not write CSV report: {exc}", file=sys.stderr)

    say("\nNote: PHISHGUARD is a heuristic detector.")
    say("A high score does not by itself prove that a URL is malicious.")

    levels = {
        "high": {CLASS_HIGH, CLASS_INVALID},
        "medium": {CLASS_HIGH, CLASS_INVALID, CLASS_MEDIUM},
        "none": set(),
    }[args.fail_on]
    return 1 if any(r.classification in levels for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
