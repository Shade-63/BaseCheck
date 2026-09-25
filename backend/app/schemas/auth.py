from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, EmailStr, ConfigDict

#signup schema
class UserCreate(BaseModel):
    email: EmailStr
    password: str

#login schema
class UserLogin(BaseModel):
    email: EmailStr
    password: str

#schema for returning user data
class UserResponse(BaseModel):
    id: UUID
    email: EmailStr
    tier: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

#schema for returning JWt access+ refresh tokens
class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

#schema for refreshing an access token
class TokenRefreshRequest(BaseModel):
    refresh_token: str

