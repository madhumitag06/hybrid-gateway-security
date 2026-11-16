"""
Pytest global test configuration and fixtures for hybrid-gateway-security.
"""
from datetime import datetime, timezone
import pytest
from backend.app.main import app
from backend.app.api.deps import get_current_user, get_current_active_user
from backend.app.core.rate_limit import reset_rate_limits
from backend.app.models.user import UserModel

STRICT_AUTH_TEST_MODULES = {
    "test_phase21_authorization_rbac",
    "test_phase22_service_key_hardening",
    "test_phase22_remediation",
    "test_phase22_3_network_authorization",
    "test_phase22_3_db_migration",
    "test_phase22_8_3_simulation_rendering",
    "test_auth",
    "test_auth_api",
}


@pytest.fixture(autouse=True)
def setup_test_auth_context(request):
    """
    For strict authentication and RBAC test suites, ensure zero overrides so real
    authentication, missing token 401s, and role 403 checks execute against real handlers.
    For legacy regression test suites written prior to endpoint authorization hardening,
    provide an authenticated ADMIN user context so functional endpoints can be verified.
    """
    reset_rate_limits()
    module_name = request.module.__name__.split(".")[-1]
    if module_name in STRICT_AUTH_TEST_MODULES:
        # Clear any overrides to ensure strict RBAC testing
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_current_active_user, None)
        yield
        reset_rate_limits()
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_current_active_user, None)
        return

    admin_mock_user = UserModel(
        id="test-admin-uuid-0001",
        email="admin@secops.local",
        full_name="SecOps Root Administrator",
        role="ADMIN",
        is_active=True,
        is_verified=True,
        auth_provider="LOCAL",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    def override_get_current_user():
        return admin_mock_user

    def override_get_current_active_user():
        return admin_mock_user

    app.dependency_overrides[get_current_user] = override_get_current_user
    app.dependency_overrides[get_current_active_user] = override_get_current_active_user

    yield

    app.dependency_overrides.pop(get_current_user, None)
    app.dependency_overrides.pop(get_current_active_user, None)
