from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict
from datetime import date, datetime ,time
from typing_extensions import Literal

class TenantCreate(BaseModel):
    tenant_name: str
    tenant_metadata: Optional[Dict] = None
    is_active: Optional[Literal[0, 1]] = 1

class TenantUpdate(BaseModel):
    tenant_name: Optional[str] = None
    tenant_metadata: Optional[Dict] = None
    is_active: Optional[Literal[0, 1]] = None




class TenantRead(TenantCreate):
    tenant_id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class CompanyCreate(BaseModel):
    name: str
    tenant_id: int

class CompanyRead(CompanyCreate):
    id: int
    class Config:
        from_attributes = True

class ServiceCreate(BaseModel):
    name: str
    description: Optional[str] = None

class ServiceRead(ServiceCreate):
    id: int
    class Config:
        from_attributes = True

class GroupCreate(BaseModel):
    group_name: str
    tenant_id: int
    description: Optional[str] = None

class GroupRead(GroupCreate):
    group_id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class DepartmentBase(BaseModel):
    # tenant_id: int
    department_name: str
    description: Optional[str]


class DepartmentCreate(DepartmentBase):
    pass
class DepartmentWithCountResponse(BaseModel):
    department_id: int
    department_name: str
    description: str
    employee_count: int

class DepartmentRead(DepartmentBase):
    department_id: int
class DepartmentDeleteResponse(BaseModel):
    message: str

class DepartmentUpdate(BaseModel):
    department_name: Optional[str]
    description: Optional[str]


class DepartmentOut(DepartmentBase):
    department_id: int

    class Config:
        from_attributes = True

class EmployeeBase(BaseModel):
    employee_code: str  # Added to Base as it's required for both create & update
    gender: str
    mobile_number: str
    alternate_mobile_number: Optional[str]
    office: str
    special_need: Optional[str]
    subscribe_via_email: bool
    subscribe_via_sms: bool
    address: str
    latitude: str
    longitude: str
    landmark: str
    department_id: int  # Added to Base as it's required for both create & update

class EmployeeCreate(EmployeeBase):
    username: str
    email: str
    hashed_password: str

class EmployeeUpdate(BaseModel):
    # employee_code: Optional[str]  # Optional for update
    gender: Optional[str] = None
    mobile_number: Optional[str] = None
    alternate_mobile_number: Optional[str] = None
    office: Optional[str] = None
    special_need: Optional[str] = None
    subscribe_via_email: Optional[bool] = None
    subscribe_via_sms: Optional[bool] = None
    address: Optional[str] = None
    latitude: Optional[str] = None
    longitude: Optional[str] = None
    landmark: Optional[str] = None
    department_id: Optional[int] = None

class EmployeeRead(EmployeeBase):
    employee_code: str
    user_id: int
    username: str
    email: str

    class Config:
        from_attributes = True

class EmployeeResponse(BaseModel):
    employee_code: str
    username: str
    user_id: int
    email: str
    gender: Optional[str] = None
    mobile_number: Optional[str] = None
    alternate_mobile_number: Optional[str] = None
    office: Optional[str] = None
    special_need: Optional[str] = None
    subscribe_via_email: Optional[bool] = None
    subscribe_via_sms: Optional[bool] = None
    address: Optional[str] = None
    latitude: Optional[str] = None
    longitude: Optional[str] = None
    landmark: Optional[str] = None
class EmployeesByDepartmentResponse(BaseModel):
    department_id: int
    tenant_id: int
    total_employees: int
    employees: List[EmployeeResponse]

class EmployeeDeleteRead(BaseModel):
    message: str

class RoleCreate(BaseModel):
    role_name: str
    description: Optional[str] = None
    tenant_id: int

class RoleRead(RoleCreate):
    role_id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class ModuleCreate(BaseModel):
    service_id: int
    name: str
    description: Optional[str] = None

class ModuleRead(ModuleCreate):
    id: int

    class Config:
        from_attributes = True

class PolicyEndpointCreate(BaseModel):
    endpoint: str

class PolicyEndpointRead(PolicyEndpointCreate):
    id: int
    class Config:
        from_attributes = True

class PolicyCreate(BaseModel):
    tenant_id: int
    service_id: int
    module_id: Optional[int] = None
    can_view: bool = False
    can_create: bool = False
    can_edit: bool = False
    can_delete: bool = False
    group_id: Optional[int] = None
    role_id: Optional[int] = None
    user_id: Optional[int] = None
    condition: Optional[Dict] = None

class PolicyRead(PolicyCreate):
    policy_id: int

    class Config:
        from_attributes = True

class AssignPolicyRequest(BaseModel):
    group_id: int
    policy_id: int

class UserCreate(BaseModel):
    username: str
    email: str
    hashed_password: str
    tenant_id: int
    is_active: Optional[int] = 1

class UserRead(BaseModel):
    user_id: int
    username: str
    email: str
    tenant_id: int
    is_active: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class LoginRequest(BaseModel):
    username: str
    password: str

class Constraints(BaseModel):
    ip_range: str


class PermissionItem(BaseModel):
    module: str
    service: str
    module_id: int
    service_id: int
    action: List[str]
    resource: str
    constraints: Constraints


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    permissions: List[PermissionItem] = []

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str

class CutoffBase(BaseModel):
    booking_cutoff: int = Field(..., gt=0, description="Booking must happen this many hours before shift")
    cancellation_cutoff: int = Field(..., gt=0, description="Cancellation must happen this many hours before shift")

class CutoffCreate(CutoffBase):
    pass

class CutoffUpdate(CutoffBase):
    pass

class CutoffRead(CutoffBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

# app/api/schemas/shift.py
from enum import Enum
class LogType(str, Enum):
    IN = "in"
    OUT = "out"

class DayOfWeek(str, Enum):
    MONDAY = "monday"
    TUESDAY = "tuesday"
    WEDNESDAY = "wednesday"
    THURSDAY = "thursday"
    FRIDAY = "friday"
    SATURDAY = "saturday"
    SUNDAY = "sunday"

class PickupType(str, Enum):
    PICKUP = "pickup"
    NODAL = "nodal"

class GenderType(str, Enum):
    MALE = "male"
    FEMALE = "female"
    ANY = "any"

class ShiftBase(BaseModel):
    shift_code: str = Field(..., description="Unique shift code per tenant")
    log_type: LogType
    shift_time: time
    day: List[DayOfWeek] 
    waiting_time_minutes: int
    pickup_type: PickupType
    gender: GenderType
    is_active: Optional[bool] = True
    @validator("day", pre=True)
    def parse_day_list(cls, value):
        if isinstance(value, str):
            # Remove braces and split, strip extra spaces
            return [v.strip().lower().replace("{", "").replace("}", "") for v in value.split(",")]
        return value

    class Config:
        from_attributes = True
class ShiftCreate(ShiftBase):
    pass

class ShiftRead(ShiftBase):
    id: int
    tenant_id: int

    class Config:
        from_attributes = True

class ShiftUpdate(BaseModel):
    shift_code: Optional[str]
    log_type: Optional[LogType]
    shift_time: Optional[time]
    day: Optional[List[DayOfWeek]]
    waiting_time_minutes: Optional[int]
    pickup_type: Optional[PickupType]
    gender: Optional[GenderType]
    is_active: Optional[bool]
    @validator("day", pre=True)
    def parse_day_list(cls, value):
        if isinstance(value, str):
            # Remove braces and split, strip extra spaces
            return [v.strip().lower().replace("{", "").replace("}", "") for v in value.split(",")]
        return value
    class Config:
        from_attributes = True

class VendorBase(BaseModel):
    vendor_name: str
    contact_person: Optional[str]
    phone_number: Optional[str]
    email: Optional[str]
    address: Optional[str]

class VendorCreate(VendorBase):
    pass

class VendorUpdate(BaseModel):
    vendor_name: Optional[str]
    contact_person: Optional[str]
    phone_number: Optional[str]
    email: Optional[str]
    address: Optional[str]
    is_active: Optional[bool]

class VendorOut(VendorBase):
    vendor_id: int
    tenant_id: int
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class FuelType(str, Enum):
    PETROL = "petrol"
    DIESEL = "diesel"
    ELECTRIC = "electric"
    CNG = "cng"
    HYBRID = "hybrid"

class VehicleTypeBase(BaseModel):
    name: str = Field(..., description="Name of the vehicle type")
    description: Optional[str] = Field(None, description="Optional description")
    capacity: int = Field(..., ge=1, description="Seating capacity")
    fuel_type: FuelType = Field(..., description="Type of fuel")
    vendor_id: int = Field(..., gt=0, description="Linked vendor ID")

class VehicleTypeCreate(VehicleTypeBase):
    pass

class VehicleTypeUpdate(BaseModel):
    name: Optional[str]
    description: Optional[str]
    capacity: Optional[int]
    fuel_type: Optional[FuelType]
    vendor_id: Optional[int]

class VehicleTypeOut(VehicleTypeBase):
    vehicle_type_id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class VehicleTypeUpdate(BaseModel):
    name: Optional[str]
    description: Optional[str]
    capacity: Optional[int]
    fuel_type: Optional[FuelType]
    vendor_id: Optional[int]
class DriverBase(BaseModel):
    username: str
    email: str
    hashed_password: str  # hashed on frontend or before insert

    city: Optional[str] = None
    date_of_birth: Optional[date] = None
    gender: Optional[str] = None  # male, female, other

    alternate_mobile_number: Optional[str] = None
    permanent_address: Optional[str] = None
    current_address: Optional[str] = None
    bgv_status: Optional[str] = "Pending"  # default = Pending
    bgv_date: Optional[date] = None

    police_doc_url: Optional[str] = None
    license_doc_url: Optional[str] = None
    photo_url: Optional[str] = None

class DriverCreate(DriverBase):
    pass
class DriverRead(DriverBase):
    driver_id: int
    user_id: int
    vendor_id: int
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class DriverOut(DriverBase):
    driver_id: int
    user_id: int
    vendor_id: int
    is_active: bool

    class Config:
        from_attributes = True