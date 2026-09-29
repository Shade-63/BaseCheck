import secrets
from datetime import datetime, timezone
from typing import List, Tuple
from uuid import UUID
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from backend.app.models.api_key import APIKey
from backend.app.schemas.api_key import APIKeyCreate
from backend.app.core.security import hash_api_key

def create_api_key(
        db: Session, user_id: UUID, key_data: APIKeyCreate
)-> Tuple[APIKey, str]:
    """
    Generates a secure random API key, stores its SHA-256 hash in DB, and returns both ORM record and plaintext key.
    """

    #1. generates a 32-byte secure random string with 'bc_' (basecheck) prefix
    raw_key = f"bc_{secrets.token_urlsafe(32)}"
    key_hash = hash_api_key(raw_key)

    #2. store only the hash in DB
    api_key_record = APIKey(
        user_id= user_id,
        key_hash = key_hash,
        name = key_data.name,
    )
    db.add(api_key_record)
    db.commit()
    db.refresh(api_key_record)

    #3. Return record + raw key (to display once)
    return api_key_record, raw_key

def list_api_keys(db: Session, user_id: UUID)-> List[APIKey]:
    """Lists all API keys created by user"""
    return(
        db.query(APIKey)
        .filter(APIKey.user_id == user_id)
        .order_by(APIKey.created_at.desc())
        .all()
    )

def revoke_api_key(db: Session, key_id: UUID, user_id: UUID) -> APIKey:
    """Revokes an API key belonging to user"""
    api_key = (
        db.query(APIKey)
        .filter(APIKey.id == key_id, APIKey.user_id == user_id)
        .first()
    )
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )
    if api_key.revoked_at is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail= "API key is already revoked",
        )
    api_key.revoked_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(api_key)
    return api_key