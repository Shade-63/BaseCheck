from uuid import UUID
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
import jwt

from backend.app.models.user import User
from backend.app.schemas.auth import UserCreate, TokenResponse
from backend.app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
) 

def create_user(db: Session, user_data: UserCreate) -> User:
    #1. check for existing user
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email already exists",
        )

    #2. hash password and create user
    user = User(
        email = user_data.email,
        password_hash = hash_password(user_data.password),
        tier = "free",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

def authenticate_user(db: Session, email: str, password: str) -> User:
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail= "Invalid Email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

def generate_tokens(user_id: UUID) -> TokenResponse:
    token_data = {"sub": str(user_id)}
    access_token = create_access_token(data= token_data)
    refresh_token = create_refresh_token(data= token_data)
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
    )

def refresh_user_tokens(db: Session, refresh_token_str: str) -> TokenResponse:
    try:
        payload = decode_token(refresh_token_str)
        user_id_str = payload.get("sub")
        token_type = payload.get("type")

        if not user_id_str or token_type != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail= "Invalid refresh token",
            )

        user_id = UUID(user_id_str)
    except(jwt.PyJWTError, ValueError):
        raise HTTPException(
            status_code= status.HTTP_401_UNAUTHORIZED,
            detail= "Invalid or expired refresh token",
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code= status.HTTP_401_UNAUTHORIZED,
            detail= "User not found",
        )

    #issue new pair of tokens
    return generate_tokens(user.id)