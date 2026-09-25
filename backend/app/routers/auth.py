from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.schemas.auth import (
    UserCreate,
    UserLogin,
    UserResponse,
    TokenResponse,
    TokenRefreshRequest,
)
from backend.app.services import auth_service

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post(
    "/signup",
    response_model=UserResponse,
    status_code= status.HTTP_201_CREATED,
    summary="Register a new user account",
)
def signup(user_data: UserCreate, db: Session = Depends(get_db)):
    user = auth_service.create_user(db = db, user_data=user_data)
    return user

@router.post(
    "/login",
    response_model= TokenResponse,
    status_code=status.HTTP_200_OK,
    summary= "Authenticate and receive access+ refresh JWT tokens",
)
def login(credentials: UserLogin, db: Session = Depends(get_db)):
    user = auth_service.authenticate_user(
        db = db, email=credentials.email, password=credentials.password
    )
    return auth_service.generate_tokens(user.id)

@router.post(
    "/refresh",
    response_model=TokenResponse,
    status_code= status.HTTP_200_OK,
    summary="Exchange a valid refresh token for a new token pair",
)
def refresh_token(request: TokenRefreshRequest, db: Session = Depends(get_db)):
    return auth_service.refresh_user_tokens(
        db=db, refresh_token_str=request.refresh_token
    )

