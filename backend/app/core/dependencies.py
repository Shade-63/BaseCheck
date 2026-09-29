from uuid import UUID
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
import jwt

from backend.app.database import get_db
from backend.app.models.user import User
from backend.app.core.security import decode_token

#Poitns swagger and fastapi to our login endpoint for token generation
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
http_bearer = HTTPBearer()

def get_current_user(
        credentials:HTTPAuthorizationCredentials = Depends(http_bearer),
        db: Session = Depends(get_db),
)-> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
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