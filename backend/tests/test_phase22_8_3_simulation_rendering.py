"""
Phase 22.8.3 Test Suite: Attack Simulation UI Rendering & Scenario API Loading
==============================================================================
Validates:
1. All six scenario definitions exist with exact required fields and metadata.
2. HybridTrafficService type annotations (including Tuple) evaluate cleanly without NameError.
3. GET /api/v1/hybrid/scenarios requires authentication and enforces RBAC:
   - 401 Unauthorized for unauthenticated requests.
   - 403 Forbidden for ordinary USER accounts.
   - 200 OK for ANALYST, OPERATOR, and ADMIN roles.
4. Response schema precisely matches frontend HybridScenarioInfo structure.
5. is_daemon_online() executes cleanly without NameError and returns a valid tuple.
6. Scenario dispatch validates IDs and blocks invalid keys.
"""

from typing import get_type_hints
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.core.security import create_access_token, hash_password
from backend.app.db.base import Base
from backend.app.db.session import SessionLocal, engine
from backend.app.main import app
from backend.app.models.user import UserModel
from backend.app.repositories.user_repo import UserRepository
from backend.app.services.hybrid_traffic_service import (
    HybridTrafficService,
    SCENARIO_METADATA,
)


@pytest.fixture(scope="module", autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        user_repo = UserRepository(db)
        # Ensure test accounts for different RBAC roles
        roles = [
            ("user@sim.test", "Test User", "USER"),
            ("analyst@sim.test", "Test Analyst", "ANALYST"),
            ("operator@sim.test", "Test Operator", "OPERATOR"),
            ("admin@sim.test", "Test Admin", "ADMIN"),
        ]
        for email, full_name, role in roles:
            existing = user_repo.get_by_email(email)
            if not existing:
                u = UserModel(
                    email=email,
                    full_name=full_name,
                    password_hash=hash_password("TestPassword123!"),
                    role=role,
                    is_active=True,
                )
                db.add(u)
        db.commit()
    finally:
        db.close()
    yield


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def _get_token_for_user(email: str) -> str:
    db = SessionLocal()
    try:
        user = UserRepository(db).get_by_email(email)
        assert user is not None
        return create_access_token(
            subject=user.id,
            claims={"role": user.role, "email": user.email},
        )
    finally:
        db.close()


def test_scenario_metadata_integrity():
    """Verify all six scenarios exist with all expected properties."""
    scenarios = HybridTrafficService.list_scenarios()
    assert len(scenarios) == 6

    expected_ids = {
        "benign",
        "port_scan",
        "traffic_spike",
        "suspicious_transfer",
        "containment",
        "brute_force",
    }
    actual_ids = {s["id"] for s in scenarios}
    assert actual_ids == expected_ids

    required_fields = {
        "id",
        "name",
        "category",
        "source_ip",
        "source_name",
        "destination_ip",
        "destination_name",
        "port",
        "protocol",
        "packets",
        "expected_action",
        "description",
    }
    for sc in scenarios:
        missing = required_fields - set(sc.keys())
        assert not missing, f"Scenario '{sc.get('id')}' missing fields: {missing}"
        assert sc["source_ip"].startswith("10.10.10.")
        assert sc["destination_ip"].startswith("10.20.10.")
        assert sc["packets"] > 0
        assert len(sc["description"]) > 10


def test_type_hints_evaluation_no_name_error():
    """Ensure type annotations evaluate without NameError in Python 3.12+ runtime."""
    hints = get_type_hints(HybridTrafficService.is_daemon_online)
    assert "return" in hints
    # Calling the method directly must not raise NameError
    online, data = HybridTrafficService.is_daemon_online()
    assert isinstance(online, bool)
    assert data is None or isinstance(data, dict)


def test_get_scenarios_requires_auth(client: TestClient):
    """GET /api/v1/hybrid/scenarios must reject unauthenticated requests."""
    resp = client.get("/api/v1/hybrid/scenarios")
    assert resp.status_code == 401
    assert "Authentication required" in resp.json().get("detail", "")


def test_get_scenarios_rbac_ordinary_user_forbidden(client: TestClient):
    """GET /api/v1/hybrid/scenarios must reject ordinary USER role with 403."""
    token = _get_token_for_user("user@sim.test")
    resp = client.get(
        "/api/v1/hybrid/scenarios",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403
    assert "Security Analyst" in resp.json().get("detail", "")


def test_get_scenarios_rbac_analyst_permitted(client: TestClient):
    """GET /api/v1/hybrid/scenarios succeeds for ANALYST role."""
    token = _get_token_for_user("analyst@sim.test")
    resp = client.get(
        "/api/v1/hybrid/scenarios",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == 6
    assert data[0]["id"] == "benign"


def test_get_scenarios_rbac_operator_and_admin_permitted(client: TestClient):
    """GET /api/v1/hybrid/scenarios succeeds for OPERATOR and ADMIN roles."""
    for email in ["operator@sim.test", "admin@sim.test"]:
        token = _get_token_for_user(email)
        resp = client.get(
            "/api/v1/hybrid/scenarios",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert len(resp.json()) == 6


def test_run_scenario_unknown_id_rejected():
    """Attempting to dispatch an unknown scenario ID must raise ValueError immediately."""
    with pytest.raises(ValueError, match="Unknown scenario 'nonexistent_attack'"):
        HybridTrafficService.run_scenario("nonexistent_attack")


def test_default_scenario_timeouts_configuration():
    """Phase 22.8.4: Verify scenario-specific timeouts are configured with safe operational headroom."""
    from backend.app.services.hybrid_traffic_service import DEFAULT_SCENARIO_TIMEOUTS

    # Brute force requires >= 20.0s due to 12 sequential urllib connection attempts + Scapy PCAP write
    assert DEFAULT_SCENARIO_TIMEOUTS["brute_force"] >= 20.0
    assert DEFAULT_SCENARIO_TIMEOUTS["all"] >= 45.0
    assert DEFAULT_SCENARIO_TIMEOUTS["containment"] <= 10.0
    assert DEFAULT_SCENARIO_TIMEOUTS["benign"] >= 15.0


def test_management_network_trust_10_30_10_0():
    """Phase 22.8.4: Verify management network 10.30.10.0/24 is recognized as a trusted management IP."""
    from backend.app.api.deps import is_trusted_management_ip

    assert is_trusted_management_ip("10.30.10.20") is True
    assert is_trusted_management_ip("10.30.10.10") is True
    assert is_trusted_management_ip("127.0.0.1") is True
    # Untrusted public or workload IPs must fail
    assert is_trusted_management_ip("198.51.100.1") is False
    assert is_trusted_management_ip("10.10.10.50") is False


def test_orphan_res_reconciliation(tmp_path, monkeypatch):
    """Phase 22.8.4: Verify orphaned .res files are safely parsed, reconciled, and unlinked."""
    import json
    from backend.app.services import hybrid_traffic_service

    monkeypatch.setattr(hybrid_traffic_service, "TRIGGERS_DIR", tmp_path)

    orphan_file = tmp_path / "run_brute_force_orphan123.res"
    orphan_file.write_text(
        json.dumps({
            "success": True,
            "status": "COMPLETED",
            "scenario": "brute_force",
            "completed_at": "2026-11-16T19:28:22Z",
        }),
        encoding="utf-8",
    )
    assert orphan_file.exists()

    reconciled = HybridTrafficService.reconcile_orphaned_responses("brute_force")
    assert len(reconciled) == 1
    assert reconciled[0]["scenario"] == "brute_force"
    assert reconciled[0]["status"] == "COMPLETED"
    assert not orphan_file.exists()
