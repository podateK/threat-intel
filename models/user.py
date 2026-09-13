from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import Boolean, Column, DateTime, Integer, String, func

from models.ioc import Base


class User(Base):
    __tablename__ = "users"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    username: str = Column(String(128), unique=True, nullable=False, index=True)
    email: str = Column(String(256), unique=True, nullable=False, index=True)
    hashed_password: str = Column(String(512), nullable=False)
    full_name: Optional[str] = Column(String(256), nullable=True)
    role: str = Column(String(32), default="analyst")
    is_active: bool = Column(Boolean, default=True)
    created_at: datetime = Column(DateTime, server_default=func.now())
    last_login: Optional[datetime] = Column(DateTime, nullable=True)


class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=128)
    email: str = Field(..., max_length=256)
    full_name: Optional[str] = None
    role: str = "analyst"


class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=128)


class UserRead(UserBase):
    id: int
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]

    model_config = {"from_attributes": True}


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    username: Optional[str] = None
    user_id: Optional[int] = None
    role: Optional[str] = None
