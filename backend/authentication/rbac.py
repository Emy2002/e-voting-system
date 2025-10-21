# backend/authentication/rbac.py

from enum import Enum
from functools import wraps
from flask import session, abort
import requests
import logging

# SR-02: Role-Based Access Control (RBAC)

OPA_URL = "http://opa:8181/v1/data/rbac/allow"  # Use Docker Compose service name for inter-container communication

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

def opa_check_permission(user_role, permission):
    # Always convert to string and lowercase
    role_str = str(user_role).lower().strip()
    perm_str = str(permission).lower().strip()
    data = {
        "input": {
            "role": role_str,
            "permission": perm_str
        }
    }
    logging.warning(f"OPA check payload: {data}")
    try:
        response = requests.post(OPA_URL, json=data)
        logging.warning(f"OPA response status: {response.status_code}")
        logging.warning(f"OPA response body: {response.text}")
        if response.status_code == 200:
            result = response.json()
            return result.get("result", False)
    except Exception as e:
        logging.warning(f"OPA request error: {e}")
    return False

# Decorator for required permission (now uses OPA)
def require_permission(permission):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if 'user_role' not in session:
                abort(401)
            role = session['user_role']
            # Always use .value for Enum permissions
            perm_str = permission.value if isinstance(permission, Enum) else str(permission)
            if not opa_check_permission(role, perm_str):
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
