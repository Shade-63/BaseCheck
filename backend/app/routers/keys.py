from typing import List
from uuid import UUID
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.user import User
from backend.app.core.dependencies import get_current_user, get_api_key_user
from backend.app.schemas.api_key import (
    APIKeyCreate,
    APIKeyCreatedResponse,
    APIKeyResponse
)
from backend.app.services import api_key_service

router = APIRouter(prefix="/keys", tags=["API Keys"])

@router.post(
    "",
    response_model= APIKeyCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generates a new API key for loggedin user",
)
def create_key(
    key_data: APIKeyCreate,
    current_user: User = Depends(get_current_user),
    db: Session= Depends(get_db),
):
    record, raw_key = api_key_service.create_api_key(
        db=db, user_id= current_user.id, key_data=key_data
    )
    return APIKeyCreatedResponse(
        id = record.id,
        name= record.name,
        key= raw_key,
        created_at=record.created_at,
    )

@router.get(
    "",
    response_model=List[APIKeyResponse],
    summary="List all the API keys belonging to the logged in user",
)
def get_keys(
    current_user: User =Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return api_key_service.list_api_keys(db=db, user_id=current_user.id)

@router.delete(
    "/{key_id}",
    response_model=APIKeyResponse,
    summary="Revoke an API key",
)
def revoke_key(
    key_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session= Depends(get_db),
):
    return api_key_service.revoke_api_key(
        db=db, key_id=key_id, user_id=current_user.id
    )

@router.get(                                                                                                                                             
        "/test-key",                                                                                                                                         
        response_model=dict,                                                                                                                                 
        summary="Test an API Key (reads X-API-Key header)",                                                                                                  
    )                                                                                                                                                        
def test_api_key(current_user: User = Depends(get_api_key_user)):                                                                                        
        return {                                                                                                                                             
            "status": "authenticated",                                                                                                                       
            "email": current_user.email,                                                                                                                     
            "tier": current_user.tier,                                                                                                                       
        }