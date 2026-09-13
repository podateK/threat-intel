from __future__ import annotations

import enum
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field
from sqlalchemy import (
    Column,
    DateTime,
    Enum,
    Float,
    Integer,
    JSON,
    String,
    Text,
    ForeignKey,
    func,
)
from sqlalchemy.orm import relationship

from models.ioc import Base, IOC


class ThreatActorType(str, enum.Enum):
    INDIVIDUAL = "individual"
    GROUP = "group"
    ORGANIZATION = "organization"
    STATE = "state"
    UNKNOWN = "unknown"


class ThreatActor(Base):
    __tablename__ = "threat_actors"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    name: str = Column(String(256), unique=True, nullable=False, index=True)
    aliases: list[str] = Column(JSON, default=list)
    actor_type: ThreatActorType = Column(Enum(ThreatActorType), default=ThreatActorType.UNKNOWN)
    description: Optional[str] = Column(Text, nullable=True)
    motivation: Optional[str] = Column(String(512), nullable=True)
    sophistication: Optional[str] = Column(String(128), nullable=True)
    country: Optional[str] = Column(String(64), nullable=True)
    external_references: list[dict] = Column(JSON, default=list)
    tags: list[str] = Column(JSON, default=list)
    created_at: datetime = Column(DateTime, server_default=func.now())
    updated_at: datetime = Column(DateTime, server_default=func.now(), onupdate=func.now())

    ioc_links = relationship("ThreatActorIOC", back_populates="threat_actor", lazy="selectin")
    campaigns = relationship("ThreatActorCampaign", back_populates="threat_actor", lazy="selectin")


class Campaign(Base):
    __tablename__ = "campaigns"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    name: str = Column(String(256), unique=True, nullable=False, index=True)
    description: Optional[str] = Column(Text, nullable=True)
    objective: Optional[str] = Column(String(512), nullable=True)
    first_seen: datetime = Column(DateTime, server_default=func.now())
    last_seen: datetime = Column(DateTime, server_default=func.now(), onupdate=func.now())
    tags: list[str] = Column(JSON, default=list)
    external_references: list[dict] = Column(JSON, default=list)
    created_at: datetime = Column(DateTime, server_default=func.now())
    updated_at: datetime = Column(DateTime, server_default=func.now(), onupdate=func.now())

    ioc_links = relationship("CampaignIOC", back_populates="campaign", lazy="selectin")
    actor_links = relationship("ThreatActorCampaign", back_populates="campaign", lazy="selectin")


class ThreatActorIOC(Base):
    __tablename__ = "threat_actor_iocs"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    threat_actor_id: int = Column(Integer, ForeignKey("threat_actors.id"), nullable=False)
    ioc_id: int = Column(Integer, ForeignKey("iocs.id"), nullable=False)
    confidence: float = Column(Float, default=0.5)
    created_at: datetime = Column(DateTime, server_default=func.now())

    threat_actor = relationship("ThreatActor", back_populates="ioc_links")
    ioc = relationship("IOC", back_populates="threat_actors")


class CampaignIOC(Base):
    __tablename__ = "campaign_iocs"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    campaign_id: int = Column(Integer, ForeignKey("campaigns.id"), nullable=False)
    ioc_id: int = Column(Integer, ForeignKey("iocs.id"), nullable=False)
    confidence: float = Column(Float, default=0.5)
    created_at: datetime = Column(DateTime, server_default=func.now())

    campaign = relationship("Campaign", back_populates="ioc_links")
    ioc = relationship("IOC", back_populates="campaigns")


class ThreatActorCampaign(Base):
    __tablename__ = "threat_actor_campaigns"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    threat_actor_id: int = Column(Integer, ForeignKey("threat_actors.id"), nullable=False)
    campaign_id: int = Column(Integer, ForeignKey("campaigns.id"), nullable=False)
    confidence: float = Column(Float, default=0.5)
    created_at: datetime = Column(DateTime, server_default=func.now())

    threat_actor = relationship("ThreatActor", back_populates="campaigns")
    campaign = relationship("Campaign", back_populates="actor_links")


class ThreatActorBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    aliases: list[str] = Field(default_factory=list)
    actor_type: ThreatActorType = ThreatActorType.UNKNOWN
    description: Optional[str] = None
    motivation: Optional[str] = None
    sophistication: Optional[str] = None
    country: Optional[str] = None
    external_references: list[dict] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class ThreatActorCreate(ThreatActorBase):
    pass


class ThreatActorRead(ThreatActorBase):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class CampaignBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    description: Optional[str] = None
    objective: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    tags: list[str] = Field(default_factory=list)
    external_references: list[dict] = Field(default_factory=list)


class CampaignCreate(CampaignBase):
    pass


class CampaignRead(CampaignBase):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
