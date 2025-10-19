# backend/authentication/rbac.py

from enum import Enum
from functools import wraps
from flask import session, abort

# SR-02: Role-Based Access Control (RBAC)

class UserRole(Enum):
    VOTER = "voter"
    AEC_EMPLOYEE = "aec_employee"
    ADMINISTRATOR = "administrator"
    COMMISSIONER = "commissioner"

class Permission(Enum):
    VOTE = "vote"
    VIEW_OWN_STATUS = "view_own_status"
    UPDATE_ADDRESS = "update_address"
    REGISTER_VOTERS = "register_voters"
    VIEW_VOTER_LIST = "view_voter_list"
    MANAGE_USERS = "manage_users"
    VIEW_AUDIT_LOGS = "view_audit_logs"
    CONFIGURE_SYSTEM = "configure_system"
    MANAGE_CANDIDATES = "manage_candidates"
    MANAGE_ELECTIONS = "manage_elections"
    VIEW_RESULTS = "view_results"

# Role -> Permissions mapping
ROLE_PERMISSIONS = {
    UserRole.VOTER: [
        Permission.VOTE,
        Permission.VIEW_OWN_STATUS,
        Permission.UPDATE_ADDRESS,
    ],
    UserRole.AEC_EMPLOYEE: [
        Permission.REGISTER_VOTERS,
        Permission.VIEW_VOTER_LIST,
        Permission.VIEW_OWN_STATUS,
    ],
    UserRole.ADMINISTRATOR: [
        Permission.MANAGE_USERS,
        Permission.VIEW_AUDIT_LOGS,
        Permission.CONFIGURE_SYSTEM,
        Permission.REGISTER_VOTERS,
        Permission.VIEW_VOTER_LIST,
    ],
    UserRole.COMMISSIONER: [
        Permission.MANAGE_CANDIDATES,
        Permission.MANAGE_ELECTIONS,
        Permission.VIEW_RESULTS,
        Permission.VIEW_AUDIT_LOGS,
    ],
}

class RBACService:
    def has_permission(self, user_role, permission):
        if isinstance(user_role, str):
            user_role = UserRole(user_role)
        if isinstance(permission, str):
            permission = Permission(permission)
        return permission in ROLE_PERMISSIONS.get(user_role, [])

    def get_permissions(self, user_role):
        if isinstance(user_role, str):
            user_role = UserRole(user_role)
        return ROLE_PERMISSIONS.get(user_role, [])

# Decorator for required permission
def require_permission(permission):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if 'user_role' not in session:
                abort(401)
            rbac_service = RBACService()
            role = session['user_role']
            if not rbac_service.has_permission(role, permission):
                abort(403)
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Decorator for required role (optional)
def require_role(role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if 'user_role' not in session:
                abort(401)
            if session['user_role'] != role:
                abort(403)
            return func(*args, **kwargs)
        return wrapper
    return decorator
