from datetime import datetime
from typing import Optional
from uuid import UUID
from pydantic import BaseModel, ConfigDict

#schema for api key creation
class APIKeyCreate(BaseModel):
    name: str

#schema for listing API keys
class APIKeyResponse(BaseModel):
    id: UUID
    name: str
    created_at: datetime
    last_used_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

#schema returned ONLY ONCE when a key is first created
class APIKeyCreatedResponse(BaseModel):
    id: UUID
    name: str
    key: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)