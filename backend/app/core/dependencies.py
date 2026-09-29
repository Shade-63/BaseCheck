from datetime import datetime, timezone
from uuid import UUID
from fastapi import Depends, HTTPException, status, Security
from fastapi.security import OAuth2PasswordBearer, HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from sqlalchemy.orm import Session
import jwt

from backend.app.database import get_db
from backend.app.models.user import User
from backend.app.models.api_key import APIKey
from backend.app.core.security import decode_token, hash_api_key

#Poitns swagger and fastapi to our login endpoint for token generation
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
http_bearer = HTTPBearer(auto_error= False)

#API key header scheme (X-API-Key)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def get_current_user(
        credentials:HTTPAuthorizationCredentials = Depends(http_bearer),
        db: Session = Depends(get_db),
)-> User:
    """Authenticates a user via JWT bearer token in the Authorization header."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not credentials:
        raise credentials_exception
    
    token = credentials.credentials #extracts the raw token string
    try:
        payload = decode_token(token)
        user_id_str: str = payload.get("sub")
        token_type: str= payload.get("type")

        if not user_id_str or token_type != "access":
            raise credentials_exception

        user_id = UUID(user_id_str)
    except (jwt.PyJWTError, ValueError):
        raise credentials_exception

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise credentials_exception

    return user

def get_api_key_user(
        raw_key: str = Security(api_key_header),
        db: Session = Depends(get_db),
)-> User:
    """Authenticates a request using an API key passed in X-API-Key header"""
    if not raw_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header."
        )

    #1. compute SHA-256 hash
    key_hash = hash_api_key(raw_key)

    #2. query active matching key
    api_key_record = (
        db.query(APIKey)
        .filter(APIKey.key_hash == key_hash, APIKey.revoked_at.is_(None))
        .first()
    )
    if not api_key_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API key"
        )

    #3. update last_used_at timestamp
    api_key_record.last_used_at = datetime.now(timezone.utc)
    db.commit()
    return api_key_record.user