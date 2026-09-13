from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

URL_REGEX = re.compile(
    r"https?://(?:www\.)?[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z]{2,})+(?::\d{1,5})?(?:/[^\s\"'<>,;]*)?"
)

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "work",
    "buzz", "icu", "vip", "loan", "download", "racing", "win",
    "bid", "stream", "accountant", "faith", "date", "review",
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd",
    "ow.ly", "buff.ly", "cutt.ly", "shorturl.at", "rb.gy",
    "dwz.cn", "v.gd", "t.me", "adf.ly", "bl.ink",
}

PHISHING_KEYWORDS = {
    "login", "verify", "account", "update", "secure", "banking",
    "confirm", "password", "signin", "credential", "auth",
    "suspend", "restrict", "unusual", "activity", "alert",
}


def is_valid_url(value: str) -> bool:
    try:
        result = urlparse(value)
        return result.scheme in ("http", "https") and bool(result.netloc)
    except Exception:
        return False


def parse_url(value: str) -> Optional[dict]:
    try:
        parsed = urlparse(value)
        return {
            "scheme": parsed.scheme,
            "netloc": parsed.netloc,
            "hostname": parsed.hostname,
            "port": parsed.port,
            "path": parsed.path,
            "query": parsed.query,
            "fragment": parsed.fragment,
            "username": parsed.username,
            "password": parsed.password,
        }
    except Exception:
        return None


def extract_domain(url: str) -> Optional[str]:
    try:
        parsed = urlparse(url)
        return parsed.hostname
    except Exception:
        return None


def extract_ips_from_url(url: str) -> list[str]:
    from utils.ip_utils import is_valid_ip
    parsed = urlparse(url)
    parts = parsed.netloc.split(":")[0]
    if is_valid_ip(parts):
        return [parts]
    return []


def is_shortened_url(url: str) -> bool:
    domain = extract_domain(url)
    return domain is not None and domain.lower() in SHORTENER_DOMAINS


def is_ip_based_url(url: str) -> bool:
    domain = extract_domain(url)
    if domain is None:
        return False
    from utils.ip_utils import is_valid_ip
    return is_valid_ip(domain)


def has_suspicious_tld(url: str) -> bool:
    domain = extract_domain(url)
    if domain is None:
        return False
    parts = domain.split(".")
    if len(parts) < 2:
        return False
    return parts[-1].lower() in SUSPICIOUS_TLDS


def has_phishing_keywords(url: str) -> bool:
    lower = url.lower()
    return any(kw in lower for kw in PHISHING_KEYWORDS)


def get_url_path_depth(url: str) -> int:
    parsed = urlparse(url)
    path = parsed.path.strip("/")
    if not path:
        return 0
    return len(path.split("/"))


def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path.rstrip("/") or "/"
    query = parsed.query
    return urlunparse((
        parsed.scheme or "https",
        hostname + (f":{parsed.port}" if parsed.port else ""),
        path,
        parsed.params,
        query,
        "",
    ))


def extract_urls_from_text(text: str) -> list[str]:
    return list(dict.fromkeys(m.group() for m in URL_REGEX.finditer(text)))


def redact_url_credentials(url: str) -> str:
    parsed = urlparse(url)
    if parsed.username or parsed.password:
        netloc = parsed.hostname or ""
        if parsed.port:
            netloc += f":{parsed.port}"
        return urlunparse((
            parsed.scheme, netloc, parsed.path,
            parsed.params, parsed.query, parsed.fragment,
        ))
    return url


def url_fingerprint(url: str) -> str:
    parsed = urlparse(normalize_url(url))
    parts = [
        (parsed.hostname or "").lower(),
        parsed.path.rstrip("/"),
        urlencode(sorted(parse_qs(parsed.query).items())),
    ]
    return "|".join(parts)


def encode_url_component(value: str) -> str:
    from urllib.parse import quote
    return quote(value, safe="")


def decode_url_component(value: str) -> str:
    from urllib.parse import unquote
    return unquote(value)


def get_tld(url: str) -> Optional[str]:
    domain = extract_domain(url)
    if domain is None:
        return None
    parts = domain.split(".")
    if len(parts) >= 2:
        return parts[-1].lower()
    return None


def is_data_url(url: str) -> bool:
    return url.lower().startswith("data:")


def url_to_ioc_value(url: str) -> str:
    normalized = normalize_url(url)
    return redact_url_credentials(normalized)
