from fastapi import Depends, Request, HTTPException, status
from typing import List
import logging

from .middleware import JWTAuthMiddleware

from fastapi import Depends, Request, HTTPException, status
from sqlalchemy.orm import Session
from service_manager.app.database.database import get_db
from service_manager.app.database.models import User, Role, RolePolicy, Policy
import logging

logger = logging.getLogger(__name__)

class PermissionChecker:
    def __init__(self, required_permissions: list, check_tenant: bool = True):
        self.required_permissions = required_permissions
        self.check_tenant = check_tenant

    async def __call__(
        self,
        request: Request,
        data=Depends(JWTAuthMiddleware()),
        db: Session = Depends(get_db)
    ):
        user_data = data[0]   # from JWT
        token = data[1]

        logger.info(f"PermissionChecker triggered for: {self.required_permissions}")

        # Get current permissions from DB
        user_id = user_data["user_id"]
        tenant_id = user_data["tenant_id"]

        logger.info(f"Fetching permissions from DB for user_id={user_id}, tenant_id={tenant_id}")

        # Example query — adjust based on your schema
        permissions = (
            db.query(Policy.module, Policy.action)
            .join(RolePolicy, RolePolicy.policy_id == Policy.policy_id)
            .join(Role, Role.role_id == RolePolicy.role_id)
            .join(User, User.role_id == Role.role_id)
            .filter(User.user_id == user_id, User.tenant_id == tenant_id)
            .all()
        )

        user_permissions = [f"{p.module}.{p.action}" for p in permissions]
        logger.info(f"User permissions from DB: {user_permissions}")

        # Check permission
        if not any(p in user_permissions for p in self.required_permissions):
            logger.warning(f"Permission denied. Required: {self.required_permissions}, User has: {user_permissions}")
            raise HTTPException(status_code=403, detail="Insufficient permissions")

        # Tenant check
        if self.check_tenant:
            path_tenant_id = request.path_params.get("tenant_id")
            if path_tenant_id and int(path_tenant_id) != int(tenant_id):
                logger.warning(f"Tenant access forbidden: path={path_tenant_id}, token={tenant_id}")
                raise HTTPException(status_code=403, detail="Access to this tenant is forbidden")

        logger.info("Permission check passed")
        return user_data
