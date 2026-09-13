from __future__ import annotations

import enum
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field
from sqlalchemy import (
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import relationship

from models.ioc import Base, IOC


class AlertSeverity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, enum.Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class AlertType(str, enum.Enum):
    THRESHOLD = "threshold"
    CORRELATION = "correlation"
    ENRICHMENT = "enrichment"
    FEED = "feed"
    MANUAL = "manual"
    SCORE_CHANGE = "score_change"


class Alert(Base):
    __tablename__ = "alerts"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    title: str = Column(String(512), nullable=False)
    description: Optional[str] = Column(Text, nullable=True)
    severity: AlertSeverity = Column(Enum(AlertSeverity), nullable=False, index=True)
    status: AlertStatus = Column(Enum(AlertStatus), default=AlertStatus.OPEN, index=True)
    alert_type: AlertType = Column(Enum(AlertType), nullable=False)
    ioc_id: Optional[int] = Column(Integer, ForeignKey("iocs.id"), nullable=True)
    rule_id: Optional[str] = Column(String(128), nullable=True)
    metadata: dict = Column(default=dict)
    acknowledged_by: Optional[str] = Column(String(128), nullable=True)
    acknowledged_at: Optional[datetime] = Column(DateTime, nullable=True)
    resolved_at: Optional[datetime] = Column(DateTime, nullable=True)
    created_at: datetime = Column(DateTime, server_default=func.now())
    updated_at: datetime = Column(DateTime, server_default=func.now(), onupdate=func.now())

    ioc = relationship("IOC", back_populates="alerts")


class AlertBase(BaseModel):
    title: str = Field(..., min_length=1, max_length=512)
    description: Optional[str] = None
    severity: AlertSeverity
    alert_type: AlertType
    ioc_id: Optional[int] = None
    rule_id: Optional[str] = None
    metadata: dict = Field(default_factory=dict)


class AlertCreate(AlertBase):
    pass


class AlertUpdate(BaseModel):
    status: Optional[AlertStatus] = None
    severity: Optional[AlertSeverity] = None
    description: Optional[str] = None
    acknowledged_by: Optional[str] = None


class AlertRead(BaseModel):
    id: int
    title: str
    description: Optional[str]
    severity: AlertSeverity
    status: AlertStatus
    alert_type: AlertType
    ioc_id: Optional[int]
    rule_id: Optional[str]
    metadata: dict
    acknowledged_by: Optional[str]
    acknowledged_at: Optional[datetime]
    resolved_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
