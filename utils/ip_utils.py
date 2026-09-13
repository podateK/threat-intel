from __future__ import annotations

import ipaddress
import re
from typing import Optional

IPV4_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
IPV6_REGEX = re.compile(
    r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
    r"|^(?:[0-9a-fA-F]{1,4}:){1,7}:$"
    r"|^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$"
    r"|^(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}$"
    r"|^(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}$"
    r"|^(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}$"
    r"|^(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}$"
    r"|^[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}$"
    r"|^:(?::[0-9a-fA-F]{1,4}){1,7}$"
    r"|^::$"
)

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

RESERVED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
]


def is_valid_ip(value: str) -> bool:
    return bool(IPV4_REGEX.match(value)) or bool(IPV6_REGEX.match(value))


def is_ipv4(value: str) -> bool:
    return bool(IPV4_REGEX.match(value))


def is_ipv6(value: str) -> bool:
    return bool(IPV6_REGEX.match(value))


def parse_ip(value: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def is_private_ip(value: str) -> bool:
    addr = parse_ip(value)
    if addr is None:
        return False
    return any(addr in network for network in PRIVATE_RANGES)


def is_reserved_ip(value: str) -> bool:
    addr = parse_ip(value)
    if addr is None:
        return False
    return any(addr in network for network in RESERVED_NETWORKS)


def get_ip_version(value: str) -> Optional[int]:
    addr = parse_ip(value)
    if addr is None:
        return None
    return addr.version


def ip_to_int(value: str) -> Optional[int]:
    addr = parse_ip(value)
    if addr is None:
        return None
    return int(addr)


def int_to_ip(value: int) -> str:
    return str(ipaddress.ip_address(value))


def expand_ipv6(value: str) -> Optional[str]:
    addr = parse_ip(value)
    if addr is None or not isinstance(addr, ipaddress.IPv6Address):
        return None
    return addr.exploded


def collapse_ipv6(value: str) -> Optional[str]:
    addr = parse_ip(value)
    if addr is None or not isinstance(addr, ipaddress.IPv6Address):
        return None
    return addr.compressed


def get_asn_info(value: str) -> dict:
    try:
        from ipwhois import IPWhois
        obj = IPWhois(value)
        result = obj.lookup_rdap()
        return {
            "asn": result.get("asn"),
            "asn_description": result.get("asn_description"),
            "asn_country": result.get("asn_country_code"),
            "asn_registry": result.get("asn_registry"),
            "network_name": result.get("network", {}).get("name"),
        }
    except Exception:
        return {"asn": None, "asn_description": None, "asn_country": None}


def categorize_ip(value: str) -> str:
    addr = parse_ip(value)
    if addr is None:
        return "unknown"
    if addr.is_loopback:
        return "loopback"
    if addr.is_multicast:
        return "multicast"
    if is_private_ip(value):
        return "private"
    if is_reserved_ip(value):
        return "reserved"
    return "public"


def extract_ips_from_text(text: str) -> list[str]:
    return [m.group() for m in re.finditer(
        rf"(?:{IPV4_REGEX.pattern}|{IPV6_REGEX.pattern})", text
    )]
