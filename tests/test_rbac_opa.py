import pytest
from unittest.mock import patch
from backend.authentication import rbac

@pytest.mark.parametrize("role,permission,opa_result", [
    ("voter", "vote", True),
    ("voter", "manage_users", False),
    ("administrator", "manage_users", True),
    ("commissioner", "view_results", True),
    ("aec_employee", "vote", False),
])
def test_opa_check_permission(role, permission, opa_result):
    with patch("backend.authentication.rbac.requests.post") as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"result": opa_result}
        assert rbac.opa_check_permission(role, permission) == opa_result

def test_require_permission_allows(monkeypatch):
    # Simulate OPA allowing the permission
    monkeypatch.setattr(rbac, "opa_check_permission", lambda r, p: True)
    from flask import Flask, session
    app = Flask(__name__)
    app.secret_key = "test"
    @app.route("/test")
    @rbac.require_permission(rbac.Permission.VOTE)
    def test_view():
        return "ok"
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user_role"] = "voter"
        resp = client.get("/test")
        assert resp.status_code == 200
        assert resp.data == b"ok"

def test_require_permission_denies(monkeypatch):
    # Simulate OPA denying the permission
    monkeypatch.setattr(rbac, "opa_check_permission", lambda r, p: False)
    from flask import Flask, session
    app = Flask(__name__)
    app.secret_key = "test"
    @app.route("/test")
    @rbac.require_permission(rbac.Permission.MANAGE_USERS)
    def test_view():
        return "fail"
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user_role"] = "voter"
        resp = client.get("/test")
        assert resp.status_code == 403
