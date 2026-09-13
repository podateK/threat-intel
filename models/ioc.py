from __future__ import annotations

import enum
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator
from sqlalchemy import (
    Column,
    DateTime,
    Enum,
    Float,
    Integer,
    JSON,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class IOCType(str, enum.Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    URL = "url"
    EMAIL = "email"


class IOCSeverity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


IOC_SEVERITY_WEIGHTS: dict[IOCSeverity, float] = {
    IOCSeverity.INFO: 0.1,
    IOCSeverity.LOW: 0.25,
    IOCSeverity.MEDIUM: 0.5,
    IOCSeverity.HIGH: 0.75,
    IOCSeverity.CRITICAL: 1.0,
}


class IOCStatus(str, enum.Enum):
    NEW = "new"
    ENRICHED = "enriched"
    ANALYZED = "analyzed"
    EXPIRED = "expired"
    FALSE_POSITIVE = "false_positive"


class IOC(Base):
    __tablename__ = "iocs"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    value: str = Column(String(2048), nullable=False, index=True)
    ioc_type: IOCType = Column(Enum(IOCType), nullable=False, index=True)
    severity: IOCSeverity = Column(Enum(IOCSeverity), default=IOCSeverity.MEDIUM)
    confidence: float = Column(Float, default=0.5, nullable=False)
    threat_score: float = Column(Float, default=0.0, nullable=False)
    status: IOCStatus = Column(Enum(IOCStatus), default=IOCStatus.NEW)
    source: str = Column(String(512), default="manual")
    tags: list[str] = Column(JSON, default=list)
    enrichment_data: dict = Column(JSON, default=dict)
    first_seen: datetime = Column(DateTime, server_default=func.now())
    last_seen: datetime = Column(DateTime, server_default=func.now(), onupdate=func.now())
    expiry: Optional[datetime] = Column(DateTime, nullable=True)
    created_at: datetime = Column(DateTime, server_default=func.now())
    updated_at: datetime = Column(DateTime, server_default=func.now(), onupdate=func.now())

    threat_actors = relationship("ThreatActorIOC", back_populates="ioc", lazy="selectin")
    campaigns = relationship("CampaignIOC", back_populates="ioc", lazy="selectin")
    alerts = relationship("Alert", back_populates="ioc", lazy="selectin")


class IOCBase(BaseModel):
    value: str = Field(..., min_length=1, max_length=2048)
    ioc_type: IOCType
    severity: IOCSeverity = IOCSeverity.MEDIUM
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    source: str = "manual"
    tags: list[str] = Field(default_factory=list)
    expiry: Optional[datetime] = None


class IOCCreate(IOCBase):
    @field_validator("value")
    @classmethod
    def strip_value(cls, v: str) -> str:
        return v.strip()


class IOCUpdate(BaseModel):
    severity: Optional[IOCSeverity] = None
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    status: Optional[IOCStatus] = None
    source: Optional[str] = None
    tags: Optional[list[str]] = None
    expiry: Optional[datetime] = None


class IOCSearch(BaseModel):
    value: Optional[str] = None
    ioc_type: Optional[IOCType] = None
    severity: Optional[IOCSeverity] = None
    status: Optional[IOCStatus] = None
    source: Optional[str] = None
    tags: Optional[list[str]] = None
    min_score: Optional[float] = None
    max_score: Optional[float] = None
    since: Optional[datetime] = None
    until: Optional[datetime] = None
    page: int = Field(default=1, ge=1)
    per_page: int = Field(default=50, ge=1, le=200)


class IOCBulkCreate(BaseModel):
    iocs: list[IOCCreate] = Field(..., min_length=1, max_length=1000)


class IOCRead(BaseModel):
    id: int
    value: str
    ioc_type: IOCType
    severity: IOCSeverity
    confidence: float
    threat_score: float
    status: IOCStatus
    source: str
    tags: list[str]
    enrichment_data: dict
    first_seen: datetime
    last_seen: datetime
    expiry: Optional[datetime]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
