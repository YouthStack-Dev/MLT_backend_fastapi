import logging
from fastapi import APIRouter, Depends, HTTPException, Request, Body
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import Optional, List, Annotated, Dict
import hashlib
import jwt
import traceback
from app.database.database import get_db
from app.crud import crud
from app.api.schemas.schemas import EmployeeLoginResponse, EmployeeResponse
from common_utils.auth.utils import hash_password , verify_password
logger = logging.getLogger(__name__)
router = APIRouter(prefix="/employees/auth", tags=["employee Authentication"])

# Config
SECRET_KEY = "your-secret-key"  # Replace with secure env-based secret
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440
REFRESH_TOKEN_EXPIRE_DAYS = 7

def authenticate_user(db: Session, email: str, password: str):
    employee = get_employee_by_email(db, email)
    if not employee:
        print(f"Employee with email {email} not found")
        return None
    if not verify_password(hash_password(password), employee.hashed_password):
        print(f"Incorrect password for email {email}")
        return None
    return employee
def get_employee_by_email(db: Session, email: str) -> Optional[EmployeeResponse]:
    return db.query(Employee).filter(Employee.email == email).first()
    
def create_access_token(
    employee_id: str,
    tenant_id: str,
    department_id: Optional[str] = None,
    department_name: Optional[str] = None,
    employee_code: Optional[str] = None,
    username: Optional[str] = None,
    expires_delta: Optional[timedelta] = None
) -> str:
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = {
        "employee_id": employee_id,
        "tenant_id": tenant_id,
        "department_id": department_id,
        "department_name": department_name,
        "employee_code": employee_code,
        "username": username,
        "token_type": "access",
        "exp": expire,
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

from fastapi.security import OAuth2PasswordBearer
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/employees/auth/token")
class PermissionChecker:
    def __init__(self, required_permissions: List[str]):
        self.required_permissions = required_permissions

    def __call__(self, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> Dict:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            employee_id = payload.get("employee_id")
            tenant_id = payload.get("tenant_id")
            
            if employee_id is None or tenant_id is None:
                raise HTTPException(status_code=401, detail="Invalid token payload")

            # Optional: Add permission validation logic here
            if self.required_permissions:
                # Validate user permissions from DB (if applicable)
                pass

            return {"employee_id": employee_id, "tenant_id": tenant_id}

        except JWTError as e:
            logging.error(f"JWT decode failed: {str(e)}")
            raise HTTPException(status_code=401, detail="Invalid token")

# ----------------------- Login Endpoint -----------------------
from app.database.models import Device, Employee  # or wherever your Device model is
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
    employee = authenticate_user(db, form_data.username, form_data.password)
    if not employee:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not employee:
        raise HTTPException(status_code=403, detail="Only employees can login")

    try:
        # 🔍 Check existing device for this user
        existing_device = db.query(Device).filter(Device.employee_id == employee.employee_id).first()

        # Generate access token
        access_token = create_access_token(
            employee_id=employee.employee_id,
            tenant_id=employee.tenant_id,
            department_id=employee.department_id,
            department_name=employee.department.department_name,
            employee_code=employee.employee_code,
            username=employee.name

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
                employee_id=employee.employee_id,
                device_uuid=device_uuid,
                device_name=device_name,
                fcm_token=fcm_token,
                access_token=access_token,
            )
            db.add(new_device)
            db.commit()

        employee = db.query(Employee).filter(Employee.employee_id == employee.employee_id).first()  # Fetch employee
        department = employee.department if employee else None

        return EmployeeLoginResponse(
            access_token=access_token,
            token_type="bearer",
            employee_id=employee.employee_id,
            employee_code=employee.employee_code if employee else None,
            username=employee.name if employee else None,
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
