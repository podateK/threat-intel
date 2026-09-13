from __future__ import annotations

import asyncio
import logging
from typing import Optional

from services import virustotal, shodan_lookup, whois_lookup, dns_lookup

logger = logging.getLogger(__name__)


async def enrich_ip(ip: str) -> dict:
    tasks = {
        "whois": whois_lookup.whois_lookup(ip),
        "dns": dns_lookup.reverse_dns(ip),
        "shodan": shodan_lookup.lookup_ip(ip),
        "virustotal": virustotal.lookup_ip(ip),
    }
    results = await asyncio.gather(
        *tasks.values(), return_exceptions=True
    )
    enriched: dict = {"value": ip, "type": "ip", "sources": {}}
    for key, result in zip(tasks.keys(), results):
        if isinstance(result, Exception):
            logger.warning("Enrichment %s failed for %s: %s", key, ip, result)
            enriched["sources"][key] = {"error": str(result)}
        else:
            enriched["sources"][key] = result
    enriched["source_count"] = sum(
        1 for v in enriched["sources"].values() if "error" not in v and v is not None
    )
    return enriched


async def enrich_domain(domain: str) -> dict:
    tasks = {
        "whois": whois_lookup.whois_lookup(domain),
        "dns": dns_lookup.dns_resolve(domain),
        "shodan": shodan_lookup.lookup_domain(domain),
        "virustotal": virustotal.lookup_domain(domain),
    }
    results = await asyncio.gather(
        *tasks.values(), return_exceptions=True
    )
    enriched: dict = {"value": domain, "type": "domain", "sources": {}}
    for key, result in zip(tasks.keys(), results):
        if isinstance(result, Exception):
            logger.warning("Enrichment %s failed for %s: %s", key, domain, result)
            enriched["sources"][key] = {"error": str(result)}
        else:
            enriched["sources"][key] = result
    enriched["source_count"] = sum(
        1 for v in enriched["sources"].values() if "error" not in v and v is not None
    )
    return enriched


async def enrich_hash(hash_value: str) -> dict:
    tasks = {
        "virustotal": virustotal.lookup_file_hash(hash_value),
    }
    results = await asyncio.gather(
        *tasks.values(), return_exceptions=True
    )
    enriched: dict = {"value": hash_value, "type": "hash", "sources": {}}
    for key, result in zip(tasks.keys(), results):
        if isinstance(result, Exception):
            logger.warning("Enrichment %s failed for %s: %s", key, hash_value, result)
            enriched["sources"][key] = {"error": str(result)}
        else:
            enriched["sources"][key] = result
    enriched["source_count"] = sum(
        1 for v in enriched["sources"].values() if "error" not in v and v is not None
    )
    return enriched


async def enrich_url(url: str) -> dict:
    tasks = {
        "virustotal": virustotal.lookup_url(url),
    }
    results = await asyncio.gather(
        *tasks.values(), return_exceptions=True
    )
    enriched: dict = {"value": url, "type": "url", "sources": {}}
    for key, result in zip(tasks.keys(), results):
        if isinstance(result, Exception):
            logger.warning("Enrichment %s failed for %s: %s", key, url, result)
            enriched["sources"][key] = {"error": str(result)}
        else:
            enriched["sources"][key] = result
    enriched["source_count"] = sum(
        1 for v in enriched["sources"].values() if "error" not in v and v is not None
    )
    return enriched


async def enrich_email(email: str) -> dict:
    domain = email.split("@")[-1] if "@" in email else None
    domain_info = None
    if domain:
        domain_info = await dns_lookup.dns_resolve(domain)
    return {
        "value": email,
        "type": "email",
        "sources": {
            "dns_domain": domain_info,
        },
        "source_count": 1 if domain_info else 0,
    }


async def enrich_ioc(value: str, ioc_type: str) -> dict:
    enrichers = {
        "ip": enrich_ip,
        "domain": enrich_domain,
        "hash_md5": enrich_hash,
        "hash_sha1": enrich_hash,
        "hash_sha256": enrich_hash,
        "url": enrich_url,
        "email": enrich_email,
    }
    enricher = enrichers.get(ioc_type)
    if enricher is None:
        return {"value": value, "type": ioc_type, "sources": {}, "error": f"Unknown IOC type: {ioc_type}"}
    return await enricher(value)
