from fastapi import APIRouter, Depends, HTTPException, Header, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Annotated
from sqlalchemy.orm import Session
import jwt
from app.database.database import get_db   
from app.api.schemas.schemas import TokenResponse
from app.crud import crud
from common_utils.auth.utils import create_access_token, hash_password , verify_password
from common_utils.auth.permission_checker import PermissionChecker

router = APIRouter()

def authenticate_user(db: Session, email: str, password: str):
    user = crud.get_user_by_email(db, email)
    if not user:
        print(f"User with email {email} not found")
        return None
    if not verify_password(hash_password(password), user.hashed_password):
        print(f"Password for email {email} is incorrect")
        return None
    return user


@router.get("/me")
async def get_me(       
    user: dict = Depends(PermissionChecker(["user_management.read"]))
):
    return {"user": user}

@router.post("/login", response_model=TokenResponse)
def login_user(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Get user's roles and permissions
    roles = crud.get_user_roles(db, user.user_id)
    permissions = crud.get_user_permissions(db, user.user_id)
    # Example if you only want permission names as strings
    # permission_strings = [perm["module"] for perm in permissions]  # Or however you want to extract string

    
    # Create token with roles and permissions
    access_token = create_access_token(
        user_id=user.user_id,
        tenant_id=user.tenant_id,
        roles=roles,
        permissions=permissions
    )

    return TokenResponse(access_token=access_token, token_type="bearer", permissions=permissions)
