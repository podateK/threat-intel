from __future__ import annotations

import logging
from typing import Optional

import aiohttp

from config import settings

logger = logging.getLogger(__name__)

VT_BASE_URL = "https://www.virustotal.com/api/v3"


async def _vt_request(path: str, api_key: str) -> Optional[dict]:
    url = f"{VT_BASE_URL}{path}"
    headers = {"x-apikey": api_key}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    return await resp.json()
                if resp.status == 404:
                    return None
                logger.warning("VirusTotal API error %d for %s", resp.status, path)
                return None
    except Exception as e:
        logger.warning("VirusTotal request failed: %s", e)
        return None


async def lookup_ip(ip: str) -> Optional[dict]:
    if not settings.VIRUSTOTAL_API_KEY:
        return None
    data = await _vt_request(f"/ip_addresses/{ip}", settings.VIRUSTOTAL_API_KEY)
    if data is None:
        return None
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "type": "ip",
        "value": ip,
        "country": attrs.get("country"),
        "as_owner": attrs.get("as_owner"),
        "asn": attrs.get("asn"),
        "network": attrs.get("network"),
        "whois": attrs.get("whois"),
        "last_analysis_stats": stats,
        "malicious_count": stats.get("malicious", 0),
        "suspicious_count": stats.get("suspicious", 0),
        "harmless_count": stats.get("harmless", 0),
        "total_votes": attrs.get("total_votes", {}),
        "reputation": attrs.get("reputation"),
        "last_analysis_date": attrs.get("last_analysis_date"),
    }


async def lookup_domain(domain: str) -> Optional[dict]:
    if not settings.VIRUSTOTAL_API_KEY:
        return None
    data = await _vt_request(f"/domains/{domain}", settings.VIRUSTOTAL_API_KEY)
    if data is None:
        return None
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "type": "domain",
        "value": domain,
        "registrar": attrs.get("registrar"),
        "creation_date": attrs.get("creation_date"),
        "popularity_ranks": attrs.get("popularity_ranks"),
        "last_dns_records": attrs.get("last_dns_records", [])[:10],
        "last_analysis_stats": stats,
        "malicious_count": stats.get("malicious", 0),
        "suspicious_count": stats.get("suspicious", 0),
        "harmless_count": stats.get("harmless", 0),
        "total_votes": attrs.get("total_votes", {}),
        "reputation": attrs.get("reputation"),
        "last_https_certificate": attrs.get("last_https_certificate"),
    }


async def lookup_file_hash(hash_value: str) -> Optional[dict]:
    if not settings.VIRUSTOTAL_API_KEY:
        return None
    data = await _vt_request(f"/files/{hash_value}", settings.VIRUSTOTAL_API_KEY)
    if data is None:
        return None
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "type": "file",
        "value": hash_value,
        "meaningful_name": attrs.get("meaningful_name"),
        "type_description": attrs.get("type_description"),
        "size": attrs.get("size"),
        "md5": attrs.get("md5"),
        "sha1": attrs.get("sha1"),
        "sha256": attrs.get("sha256"),
        "last_analysis_stats": stats,
        "malicious_count": stats.get("malicious", 0),
        "suspicious_count": stats.get("suspicious", 0),
        "harmless_count": stats.get("harmless", 0),
        "undetected_count": stats.get("undetected", 0),
        "total_votes": attrs.get("total_votes", {}),
        "reputation": attrs.get("reputation"),
        "first_submission_date": attrs.get("first_submission_date"),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "tags": attrs.get("tags", []),
        "names": attrs.get("names", [])[:5],
    }


async def lookup_url(url: str) -> Optional[dict]:
    if not settings.VIRUSTOTAL_API_KEY:
        return None
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    data = await _vt_request(f"/urls/{url_id}", settings.VIRUSTOTAL_API_KEY)
    if data is None:
        return None
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "type": "url",
        "value": url,
        "url": attrs.get("url"),
        "final_url": attrs.get("last_final_url"),
        "title": attrs.get("title"),
        "categories": attrs.get("categories", {}),
        "last_analysis_stats": stats,
        "malicious_count": stats.get("malicious", 0),
        "suspicious_count": stats.get("suspicious", 0),
        "harmless_count": stats.get("harmless", 0),
        "total_votes": attrs.get("total_votes", {}),
        "reputation": attrs.get("reputation"),
        "last_http_response_code": attrs.get("last_http_response_code"),
    }


async def search(query: str, limit: int = 10) -> list[dict]:
    if not settings.VIRUSTOTAL_API_KEY:
        return []
    data = await _vt_request(
        f"/search?query={query}&limit={limit}",
        settings.VIRUSTOTAL_API_KEY,
    )
    if data is None:
        return []
    results = data.get("data", [])
    return [
        {
            "id": r.get("id"),
            "type": r.get("type"),
            "attributes": r.get("attributes", {}),
        }
        for r in results[:limit]
    ]
