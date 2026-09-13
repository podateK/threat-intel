from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Optional

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from models.alert import Alert, AlertSeverity, AlertStatus, AlertType
from models.ioc import IOC, IOCSeverity

logger = logging.getLogger(__name__)


class AlertRule:
    def __init__(
        self,
        rule_id: str,
        title_template: str,
        severity: AlertSeverity,
        alert_type: AlertType,
        description_template: str = "",
        threshold: float = 0.7,
    ):
        self.rule_id = rule_id
        self.title_template = title_template
        self.severity = severity
        self.alert_type = alert_type
        self.description_template = description_template
        self.threshold = threshold

    def evaluate(self, ioc: IOC) -> Optional[dict]:
        return None


class ScoreThresholdRule(AlertRule):
    def __init__(self, threshold: float = 0.7):
        super().__init__(
            rule_id="score_threshold",
            title_template="High Threat Score: {value}",
            severity=AlertSeverity.HIGH,
            alert_type=AlertType.SCORE_CHANGE,
            description_template="IOC {value} has threat score {score:.2f}",
            threshold=threshold,
        )

    def evaluate(self, ioc: IOC) -> Optional[dict]:
        if ioc.threat_score >= self.threshold:
            return {
                "title": self.title_template.format(value=ioc.value),
                "description": self.description_template.format(value=ioc.value, score=ioc.threat_score),
                "severity": self.severity,
                "alert_type": self.alert_type,
                "rule_id": self.rule_id,
                "ioc_id": ioc.id,
                "metadata": {"threat_score": ioc.threat_score, "threshold": self.threshold},
            }
        return None


class CriticalSeverityRule(AlertRule):
    def __init__(self):
        super().__init__(
            rule_id="critical_severity",
            title_template="Critical IOC Detected: {value}",
            severity=AlertSeverity.CRITICAL,
            alert_type=AlertType.ENRICHMENT,
            description_template="Critical severity IOC {value} detected from source {source}",
        )

    def evaluate(self, ioc: IOC) -> Optional[dict]:
        if ioc.severity == IOCSeverity.CRITICAL:
            return {
                "title": self.title_template.format(value=ioc.value),
                "description": self.description_template.format(value=ioc.value, source=ioc.source),
                "severity": self.severity,
                "alert_type": self.alert_type,
                "rule_id": self.rule_id,
                "ioc_id": ioc.id,
                "metadata": {"source": ioc.source, "severity": ioc.severity.value},
            }
        return None


class MultiSourceRule(AlertRule):
    def __init__(self, min_sources: int = 3):
        super().__init__(
            rule_id="multi_source",
            title_template="Multi-Source Corroboration: {value}",
            severity=AlertSeverity.MEDIUM,
            alert_type=AlertType.CORRELATION,
            description_template="IOC {value} confirmed by {source_count} sources",
        )
        self.min_sources = min_sources

    def evaluate(self, ioc: IOC) -> Optional[dict]:
        source_count = ioc.enrichment_data.get("source_count", 0) if ioc.enrichment_data else 0
        if source_count >= self.min_sources:
            return {
                "title": self.title_template.format(value=ioc.value),
                "description": self.description_template.format(value=ioc.value, source_count=source_count),
                "severity": self.severity,
                "alert_type": self.alert_type,
                "rule_id": self.rule_id,
                "ioc_id": ioc.id,
                "metadata": {"source_count": source_count},
            }
        return None


class MalwareHashRule(AlertRule):
    def __init__(self, min_detections: int = 5):
        super().__init__(
            rule_id="malware_hash",
            title_template="Malware Hash Detected: {value}",
            severity=AlertSeverity.HIGH,
            alert_type=AlertType.ENRICHMENT,
            description_template="Hash {value} detected by {detections} engines",
        )
        self.min_detections = min_detections

    def evaluate(self, ioc: IOC) -> Optional[dict]:
        if ioc.ioc_type.value.startswith("hash"):
            vt_data = (ioc.enrichment_data or {}).get("sources", {}).get("virustotal", {})
            if isinstance(vt_data, dict):
                detections = vt_data.get("malicious_count", 0)
                if detections >= self.min_detections:
                    return {
                        "title": self.title_template.format(value=ioc.value),
                        "description": self.description_template.format(value=ioc.value, detections=detections),
                        "severity": self.severity,
                        "alert_type": self.alert_type,
                        "rule_id": self.rule_id,
                        "ioc_id": ioc.id,
                        "metadata": {"detections": detections},
                    }
        return None


DEFAULT_RULES: list[AlertRule] = [
    ScoreThresholdRule(threshold=0.7),
    CriticalSeverityRule(),
    MultiSourceRule(min_sources=3),
    MalwareHashRule(min_detections=5),
]


class AlertEngine:
    def __init__(self, rules: Optional[list[AlertRule]] = None):
        self.rules = rules or DEFAULT_RULES

    def evaluate_ioc(self, ioc: IOC) -> list[dict]:
        alerts = []
        for rule in self.rules:
            result = rule.evaluate(ioc)
            if result:
                alerts.append(result)
        return alerts

    async def process_ioc(self, session: AsyncSession, ioc: IOC) -> list[Alert]:
        generated = self.evaluate_ioc(ioc)
        created_alerts = []

        for alert_data in generated:
            existing = await session.execute(
                select(Alert).where(
                    and_(
                        Alert.ioc_id == alert_data.get("ioc_id"),
                        Alert.rule_id == alert_data.get("rule_id"),
                        Alert.status.in_([AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED, AlertStatus.INVESTIGATING]),
                    )
                )
            )
            if existing.scalars().first():
                continue

            alert = Alert(
                title=alert_data["title"],
                description=alert_data.get("description"),
                severity=alert_data["severity"],
                alert_type=alert_data["alert_type"],
                ioc_id=alert_data.get("ioc_id"),
                rule_id=alert_data.get("rule_id"),
                metadata=alert_data.get("metadata", {}),
            )
            session.add(alert)
            created_alerts.append(alert)
            logger.info("Created alert: %s", alert.title)

        await session.commit()
        return created_alerts

    async def process_batch(self, session: AsyncSession, iocs: list[IOC]) -> list[Alert]:
        all_alerts = []
        for ioc in iocs:
            alerts = await self.process_ioc(session, ioc)
            all_alerts.extend(alerts)
        return all_alerts


alert_engine = AlertEngine()
