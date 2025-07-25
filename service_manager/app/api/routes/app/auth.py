from fastapi import APIRouter, Depends, HTTPException, Request, Body
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import Optional, List, Annotated, Dict
import hashlib
import jwt
import traceback
from app.database.database import get_db
from app.crud import crud
from app.api.schemas.schemas import EmployeeLoginResponse
from common_utils.auth.utils import hash_password , verify_password

router = APIRouter(prefix="/employees/auth", tags=["employee Authentication"])

# Config
SECRET_KEY = "your-secret-key"  # Replace with secure env-based secret
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440
REFRESH_TOKEN_EXPIRE_DAYS = 7

def authenticate_user(db: Session, email: str, password: str):
    user = crud.get_user_by_email(db, email)
    if not user:
        print(f"User with email {email} not found")
        return None
    if not verify_password(hash_password(password), user.hashed_password):
        print(f"Incorrect password for email {email}")
        return None
    return user

def create_access_token(
    user_id: str,
    tenant_id: str,
    expires_delta: Optional[timedelta] = None
) -> str:
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = {
        "user_id": user_id,
        "tenant_id": tenant_id,
        "token_type": "access",
        "exp": expire,
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

# ----------------------- Login Endpoint -----------------------
from app.database.models import Device  # or wherever your Device model is
from sqlalchemy.exc import SQLAlchemyError

@router.post("/employee/login", response_model=EmployeeLoginResponse)
def employee_login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    request: Request,
    db: Session = Depends(get_db),
    device_uuid: str = Body(...),
    device_name: Optional[str] = Body(None),
    fcm_token: Optional[str] = Body(None),
    force_logout: Optional[bool] = Body(False),
):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.employee:
        raise HTTPException(status_code=403, detail="Only employees can login")

    try:
        # 🔍 Check existing device for this user
        existing_device = db.query(Device).filter(Device.user_id == user.user_id).first()

        # Generate access token
        access_token = create_access_token(
            user_id=user.user_id,
            tenant_id=user.tenant_id,
        )

        if existing_device:
            if existing_device.device_uuid != device_uuid:
                if not force_logout:
                    raise HTTPException(
                        status_code=403,
                        detail="You are already logged in on another device. To continue, set force_logout=True."
                    )
            # Update existing device (either same device or after force logout)
            existing_device.device_uuid = device_uuid
            existing_device.device_name = device_name
            existing_device.fcm_token = fcm_token
            existing_device.access_token = access_token
            db.commit()
        else:
            # No device exists for user — insert new
            new_device = Device(
                user_id=user.user_id,
                device_uuid=device_uuid,
                device_name=device_name,
                fcm_token=fcm_token,
                access_token=access_token,
            )
            db.add(new_device)
            db.commit()

        employee = user.employee
        department = employee.department if employee else None

        return EmployeeLoginResponse(
            access_token=access_token,
            token_type="bearer",
            user_id=user.user_id,
            employee_code=employee.employee_code if employee else None,
            username=user.username if user else None,
            department_id=department.department_id if department else None,
            department_name=department.department_name if department else None
        )

    except HTTPException as e:
        db.rollback()
        print("HTTPException:", str(e.detail))
        raise e
    except SQLAlchemyError as e:
        db.rollback()
        print("SQLAlchemyError:", str(e))
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Device login failed")
    except Exception as e:
        db.rollback()
        print("General Exception:", str(e))
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Unexpected error during login")
