from fastapi import HTTPException
from app.crud.crud import create_employee , get_employee as get_employee_service, update_employee, delete_employee , get_employee_by_department

import traceback
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)
class EmployeeController:


    def create_employee(self, employee, db, tenant_id):
        try:
            return create_employee(db, employee, tenant_id)
        except HTTPException as e:
            raise e
        except Exception :
            raise HTTPException(status_code=500, detail="Unexpected error occurred while creating employee.")


    def get_employee(self, employee_code, db, tenant_id):
        try:
            return get_employee_service(db, employee_code, tenant_id)
        except HTTPException as e:
            logger.warning(f"HTTPException: {str(e.detail)}")
            raise e  # ✅ Re-raise the same HTTPException (404 or 409 etc.)
        except Exception as e:
            traceback.print_exc()
            logger.error(f"Unhandled exception in controller: {str(e)}")
            raise HTTPException(status_code=500, detail="Unexpected error occurred while fetching employee.")

    def get_employee_by_department(self, department_id, db, tenant_id):
        try:
            return get_employee_by_department(db, department_id, tenant_id)
        except HTTPException as e:
            raise e
        except Exception:
            raise HTTPException(status_code=500, detail="Unexpected error occurred while fetching employee.")

    def update_employee(self, employee_code, employee, db, tenant_id):
        try:
            return update_employee(db, employee_code, employee, tenant_id)
        except HTTPException as e:
            raise e
        except Exception:
            raise HTTPException(status_code=500, detail="Unexpected error occurred while updating employee.")

    def delete_employee(self, employee_code, db, tenant_id):
        try:
            return delete_employee(db, employee_code, tenant_id)
        except HTTPException as e:
            raise e
        except Exception:
            raise HTTPException(status_code=500, detail="Unexpected error occurred while deleting employee.")
