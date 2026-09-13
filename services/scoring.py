from __future__ import annotations

import logging
from typing import Optional

from models.ioc import IOC, IOCType, IOCSeverity

logger = logging.getLogger(__name__)


def compute_threat_score(confidence: float, severity: IOCSeverity, enrichment_data: dict) -> float:
    from models.ioc import IOC_SEVERITY_WEIGHTS
    base_score = confidence * IOC_SEVERITY_WEIGHTS.get(severity, 0.5)

    vt_data = enrichment_data.get("sources", {}).get("virustotal", {})
    if vt_data and not isinstance(vt_data, dict) or (isinstance(vt_data, dict) and "error" not in vt_data):
        malicious = vt_data.get("malicious_count", 0)
        if malicious > 10:
            base_score = min(1.0, base_score + 0.3)
        elif malicious > 5:
            base_score = min(1.0, base_score + 0.2)
        elif malicious > 0:
            base_score = min(1.0, base_score + 0.1)

    shodan_data = enrichment_data.get("sources", {}).get("shodan", {})
    if shodan_data and isinstance(shodan_data, dict) and "error" not in shodan_data:
        vulns = shodan_data.get("vulns", [])
        if len(vulns) > 5:
            base_score = min(1.0, base_score + 0.2)
        elif len(vulns) > 0:
            base_score = min(1.0, base_score + 0.1)

    return round(min(1.0, max(0.0, base_score)), 4)


def score_bulk(iocs: list[dict]) -> list[dict]:
    scored = []
    for ioc_data in iocs:
        score = compute_threat_score(
            confidence=ioc_data.get("confidence", 0.5),
            severity=IOCSeverity(ioc_data.get("severity", "medium")),
            enrichment_data=ioc_data.get("enrichment_data", {}),
        )
        ioc_data["threat_score"] = score
        scored.append(ioc_data)
    return scored


def score_from_virustotal(vt_stats: dict) -> float:
    malicious = vt_stats.get("malicious", 0)
    total = sum(vt_stats.values()) if vt_stats else 0
    if total == 0:
        return 0.0
    ratio = malicious / total
    return round(min(1.0, ratio * 2), 4)


def recalculate_score(ioc: IOC) -> float:
    return compute_threat_score(
        confidence=ioc.confidence,
        severity=ioc.severity,
        enrichment_data=ioc.enrichment_data or {},
    )


def get_severity_from_score(score: float) -> IOCSeverity:
    if score >= 0.8:
        return IOCSeverity.CRITICAL
    if score >= 0.6:
        return IOCSeverity.HIGH
    if score >= 0.4:
        return IOCSeverity.MEDIUM
    if score >= 0.2:
        return IOCSeverity.LOW
    return IOCSeverity.INFO


def get_score_breakdown(confidence: float, severity: IOCSeverity, enrichment_data: dict) -> dict:
    from models.ioc import IOC_SEVERITY_WEIGHTS
    base = confidence * IOC_SEVERITY_WEIGHTS.get(severity, 0.5)

    vt_bonus = 0.0
    shodan_bonus = 0.0

    vt_data = enrichment_data.get("sources", {}).get("virustotal", {})
    if isinstance(vt_data, dict) and "error" not in vt_data:
        malicious = vt_data.get("malicious_count", 0)
        if malicious > 10:
            vt_bonus = 0.3
        elif malicious > 5:
            vt_bonus = 0.2
        elif malicious > 0:
            vt_bonus = 0.1

    shodan_data = enrichment_data.get("sources", {}).get("shodan", {})
    if isinstance(shodan_data, dict) and "error" not in shodan_data:
        vulns = shodan_data.get("vulns", [])
        if len(vulns) > 5:
            shodan_bonus = 0.2
        elif len(vulns) > 0:
            shodan_bonus = 0.1

    total = min(1.0, base + vt_bonus + shodan_bonus)
    return {
        "base_score": round(base, 4),
        "virustotal_bonus": vt_bonus,
        "shodan_bonus": shodan_bonus,
        "total_score": round(total, 4),
    }
