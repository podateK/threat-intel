from __future__ import annotations

import logging
from typing import Optional

import aiohttp

from config import settings

logger = logging.getLogger(__name__)

SHODAN_API_URL = "https://api.shodan.io"


async def _shodan_request(path: str) -> Optional[dict]:
    if not settings.SHODAN_API_KEY:
        return None
    url = f"{SHODAN_API_URL}{path}"
    params = {"key": settings.SHODAN_API_KEY}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    return await resp.json()
                if resp.status == 404:
                    return None
                logger.warning("Shodan API error %d for %s", resp.status, path)
                return None
    except Exception as e:
        logger.warning("Shodan request failed: %s", e)
        return None


async def lookup_ip(ip: str) -> Optional[dict]:
    data = await _shodan_request(f"/shodan/host/{ip}?key={settings.SHODAN_API_KEY}")
    if data is None:
        return None
    return {
        "type": "ip",
        "value": ip,
        "ip_str": data.get("ip_str"),
        "org": data.get("org"),
        "isp": data.get("isp"),
        "asn": data.get("asn"),
        "os": data.get("os"),
        "country_code": data.get("country_code"),
        "country_name": data.get("country_name"),
        "city": data.get("city"),
        "region_code": data.get("region_code"),
        "latitude": data.get("latitude"),
        "longitude": data.get("longitude"),
        "ports": data.get("ports", []),
        "vulns": data.get("vulns", []),
        "hostnames": data.get("hostnames", []),
        "domains": data.get("domains", []),
        "last_update": data.get("last_update"),
        "services": [
            {
                "port": s.get("port"),
                "protocol": s.get("transport"),
                "product": s.get("product"),
                "version": s.get("version"),
                "banner": (s.get("data", "")[:200] if s.get("data") else None),
            }
            for s in data.get("data", [])[:20]
        ],
        "open_ports_count": len(data.get("ports", [])),
    }


async def lookup_domain(domain: str) -> Optional[dict]:
    data = await _shodan_request(f"/dns/resolve?hostnames={domain}&key={settings.SHODAN_API_KEY}")
    if data is None:
        return None
    resolved = data.get(domain)
    if resolved:
        return {
            "type": "domain",
            "value": domain,
            "resolved_ip": resolved,
        }
    return None


async def get_dns_info(domain: str) -> Optional[dict]:
    data = await _shodan_request(f"/dns/domain/{domain}?key={settings.SHODAN_API_KEY}")
    if data is None:
        return None
    return {
        "type": "dns",
        "value": domain,
        "domain": data.get("domain"),
        "data": data.get("data", []),
        "subdomains": data.get("subdomains", []),
    }


async def search_query(query: str, page: int = 1) -> Optional[dict]:
    data = await _shodan_request(
        f"/shodan/host/search?key={settings.SHODAN_API_KEY}&q={query}&page={page}"
    )
    if data is None:
        return None
    return {
        "matches": data.get("matches", []),
        "total": data.get("total", 0),
    }
