from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models.ioc import IOC, IOCType
from models.threat import ThreatActor, ThreatActorIOC, Campaign, CampaignIOC

logger = logging.getLogger(__name__)


def _extract_ip_from_enrichment(ioc: IOC) -> list[str]:
    ips: list[str] = []
    dns_data = ioc.enrichment_data.get("sources", {}).get("dns", {})
    if isinstance(dns_data, dict):
        ips.extend(dns_data.get("a_records", []))
        ips.extend(dns_data.get("aaaa_records", []))
    shodan_data = ioc.enrichment_data.get("sources", {}).get("shodan", {})
    if isinstance(shodan_data, dict):
        hostnames = shodan_data.get("hostnames", [])
        if isinstance(hostnames, list):
            pass
    return ips


def _extract_domain_from_enrichment(ioc: IOC) -> list[str]:
    domains: list[str] = []
    dns_data = ioc.enrichment_data.get("sources", {}).get("dns", {})
    if isinstance(dns_data, dict):
        cname = dns_data.get("cname")
        if cname:
            domains.append(cname)
    return domains


def find_ip_domain_correlations(iocs: list[IOC]) -> list[dict]:
    correlations = []
    ip_map: dict[str, list[IOC]] = {}
    domain_map: dict[str, list[IOC]] = {}

    for ioc in iocs:
        if ioc.ioc_type == IOCType.IP:
            ip_map.setdefault(ioc.value, []).append(ioc)
        elif ioc.ioc_type == IOCType.DOMAIN:
            domain_map.setdefault(ioc.value, []).append(ioc)

    for ioc in iocs:
        related_ips = _extract_ip_from_enrichment(ioc)
        for ip in related_ips:
            if ip in ip_map:
                for linked_ioc in ip_map[ip]:
                    if linked_ioc.id != ioc.id:
                        correlations.append({
                            "type": "domain_ip",
                            "source_ioc_id": ioc.id,
                            "source_ioc_value": ioc.value,
                            "target_ioc_id": linked_ioc.id,
                            "target_ioc_value": linked_ioc.value,
                            "description": f"Domain {ioc.value} resolves to IP {linked_ioc.value}",
                        })

        related_domains = _extract_domain_from_enrichment(ioc)
        for domain in related_domains:
            if domain in domain_map:
                for linked_ioc in domain_map[domain]:
                    if linked_ioc.id != ioc.id:
                        correlations.append({
                            "type": "ip_domain",
                            "source_ioc_id": ioc.id,
                            "source_ioc_value": ioc.value,
                            "target_ioc_id": linked_ioc.id,
                            "target_ioc_value": linked_ioc.value,
                            "description": f"IP {ioc.value} resolves to domain {linked_ioc.value}",
                        })

    return correlations


def find_shared_infrastructure_correlations(iocs: list[IOC]) -> list[dict]:
    correlations = []
    org_map: dict[str, list[IOC]] = {}

    for ioc in iocs:
        shodan_data = ioc.enrichment_data.get("sources", {}).get("shodan", {})
        if isinstance(shodan_data, dict):
            org = shodan_data.get("org")
            if org:
                org_map.setdefault(org, []).append(ioc)

    for org, org_iocs in org_map.items():
        if len(org_iocs) > 1:
            for i, ioc_a in enumerate(org_iocs):
                for ioc_b in org_iocs[i + 1:]:
                    correlations.append({
                        "type": "shared_infrastructure",
                        "source_ioc_id": ioc_a.id,
                        "source_ioc_value": ioc_a.value,
                        "target_ioc_id": ioc_b.id,
                        "target_ioc_value": ioc_b.value,
                        "description": f"Shared infrastructure: {org}",
                    })

    return correlations


def find_temporal_correlations(iocs: list[IOC], window_hours: int = 24) -> list[dict]:
    correlations = []
    sorted_iocs = sorted(iocs, key=lambda x: x.first_seen or datetime.min)

    for i, ioc_a in enumerate(sorted_iocs):
        for ioc_b in sorted_iocs[i + 1:]:
            if ioc_a.id == ioc_b.id:
                continue
            if ioc_a.first_seen and ioc_b.first_seen:
                delta = abs((ioc_b.first_seen - ioc_a.first_seen).total_seconds())
                if delta <= window_hours * 3600:
                    correlations.append({
                        "type": "temporal",
                        "source_ioc_id": ioc_a.id,
                        "source_ioc_value": ioc_a.value,
                        "target_ioc_id": ioc_b.id,
                        "target_ioc_value": ioc_b.value,
                        "description": f"Observed within {window_hours}h window",
                    })

    return correlations


def find_tag_correlations(iocs: list[IOC]) -> list[dict]:
    correlations = []
    tag_map: dict[str, list[IOC]] = {}

    for ioc in iocs:
        for tag in (ioc.tags or []):
            tag_map.setdefault(tag, []).append(ioc)

    seen = set()
    for tag, tagged_iocs in tag_map.items():
        if len(tagged_iocs) > 1:
            for i, ioc_a in enumerate(tagged_iocs):
                for ioc_b in tagged_iocs[i + 1:]:
                    pair = tuple(sorted([ioc_a.id, ioc_b.id]))
                    if pair not in seen:
                        seen.add(pair)
                        correlations.append({
                            "type": "shared_tag",
                            "source_ioc_id": ioc_a.id,
                            "source_ioc_value": ioc_a.value,
                            "target_ioc_id": ioc_b.id,
                            "target_ioc_value": ioc_b.value,
                            "description": f"Shared tag: {tag}",
                        })

    return correlations


def run_correlation(iocs: list[IOC]) -> list[dict]:
    all_correlations = []
    all_correlations.extend(find_ip_domain_correlations(iocs))
    all_correlations.extend(find_shared_infrastructure_correlations(iocs))
    all_correlations.extend(find_temporal_correlations(iocs))
    all_correlations.extend(find_tag_correlations(iocs))

    seen = set()
    unique = []
    for c in all_correlations:
        key = (c["type"], c["source_ioc_id"], c["target_ioc_id"])
        if key not in seen:
            seen.add(key)
            unique.append(c)

    return unique


def get_correlation_graph(iocs: list[IOC]) -> dict:
    nodes = []
    edges = []

    for ioc in iocs:
        nodes.append({
            "id": ioc.id,
            "label": ioc.value,
            "type": ioc.ioc_type.value if hasattr(ioc.ioc_type, "value") else ioc.ioc_type,
            "severity": ioc.severity.value if hasattr(ioc.severity, "value") else ioc.severity,
            "score": ioc.threat_score,
        })

    correlations = run_correlation(iocs)
    for c in correlations:
        edges.append({
            "source": c["source_ioc_id"],
            "target": c["target_ioc_id"],
            "type": c["type"],
            "description": c["description"],
        })

    return {"nodes": nodes, "edges": edges}
