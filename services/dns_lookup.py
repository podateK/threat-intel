from __future__ import annotations

import asyncio
import logging
import socket
from typing import Optional

logger = logging.getLogger(__name__)


async def dns_resolve(domain: str) -> dict:
    result: dict = {
        "domain": domain,
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
        "cname": None,
        "soa": None,
        "ptr_records": [],
    }

    loop = asyncio.get_event_loop()

    def _resolve():
        try:
            info = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            seen = set()
            for family, _, _, _, sockaddr in info:
                ip = sockaddr[0]
                if ip not in seen:
                    seen.add(ip)
                    if family == socket.AF_INET:
                        result["a_records"].append(ip)
                    elif family == socket.AF_INET6:
                        result["aaaa_records"].append(ip)
        except socket.gaierror:
            pass

    await loop.run_in_executor(None, _resolve)

    try:
        import dns.resolver
        for rtype in ("MX", "NS", "TXT", "CNAME", "SOA", "PTR"):
            try:
                answers = dns.resolver.resolve(domain, rtype)
                for rdata in answers:
                    if rtype == "MX":
                        result["mx_records"].append({
                            "host": str(rdata.exchange),
                            "priority": rdata.preference,
                        })
                    elif rtype == "NS":
                        result["ns_records"].append(str(rdata))
                    elif rtype == "TXT":
                        result["txt_records"].append(str(rdata))
                    elif rtype == "CNAME":
                        result["cname"] = str(rdata)
                    elif rtype == "SOA":
                        result["soa"] = {
                            "mname": str(rdata.mname),
                            "rname": str(rdata.rname),
                            "serial": rdata.serial,
                        }
            except Exception:
                continue
    except ImportError:
        logger.debug("dnspython not installed, skipping DNS record lookups")

    result["total_ips"] = len(result["a_records"]) + len(result["aaaa_records"])
    result["has_mx"] = len(result["mx_records"]) > 0
    result["has_ipv6"] = len(result["aaaa_records"]) > 0

    return result


async def reverse_dns(ip: str) -> Optional[str]:
    loop = asyncio.get_event_loop()

    def _reverse():
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror):
            return None

    return await loop.run_in_executor(None, _reverse)


async def dns_bulk_resolve(domains: list[str], concurrency: int = 50) -> dict[str, dict]:
    semaphore = asyncio.Semaphore(concurrency)

    async def _limited(domain: str) -> tuple[str, dict]:
        async with semaphore:
            return domain, await dns_resolve(domain)

    tasks = [_limited(d) for d in domains]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    output: dict[str, dict] = {}
    for item in results:
        if isinstance(item, tuple):
            domain, data = item
            output[domain] = data
    return output
