import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
import jwt
from passlib.context import CryptContext

from backend.app.config import settings

#bcrypting the pass
pwd_context = CryptContext(schemes=["bcrypt"], deprecated= "auto")

def hash_password(password: str)-> str:
    """HAshes a plain text into password using bycrypt"""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies the plain text pass against the stored bycrypt hash"""
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Generates a short-lived JWT acess token"""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc)+(
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_TIME)
    )
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

def create_refresh_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Generates a longer-lived JWT refresh token"""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

def decode_token(token: str)->Dict[str, Any]:
    """Decodes and validates the JWT token signature and expiration"""
    return jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])

def hash_api_key(raw_key: str) -> str:
    """hashes an API key using SHA-256 for fast O(1) indexed lookups. We don't use bycrypt for API keys because keys are checked on every single request"""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()