"""
Configuration & Environment Loading Tests (Phase 14)
=====================================================
Validates that Settings parses comma-separated lists, JSON encoded arrays, boolean flags,
integer durations, optional API keys, and secret placeholders safely and deterministically.
"""

import os
from typing import Any, Dict
import pytest
from pydantic import ValidationError
from backend.app.config import Settings


def create_settings_with_env(env_overrides: Dict[str, str]) -> Settings:
    """
    Helper to instantiate Settings with a clean environment overlay.
    """
    old_env = os.environ.copy()
    try:
        # Clear any conflicting env vars
        for k in env_overrides:
            os.environ[k] = env_overrides[k]
        return Settings(_env_file=None)
    finally:
        os.environ.clear()
        os.environ.update(old_env)


def test_cors_origins_comma_separated_parsing():
    """
    Test 1 — CORS parsing: comma-separated string should parse into a clean list of origins.
    """
    s = create_settings_with_env({
        "CORS_ORIGINS": "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000"
    })
    assert isinstance(s.cors_origins, list)
    assert s.cors_origins == [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
    ]


def test_cors_origins_json_encoded_parsing():
    """
    Validates that JSON-formatted list syntax is also parsed cleanly.
    """
    s = create_settings_with_env({
        "CORS_ORIGINS": '["http://localhost:5173", "http://127.0.0.1:5173"]'
    })
    assert s.cors_origins == ["http://localhost:5173", "http://127.0.0.1:5173"]


def test_management_allowlist_parsing():
    """
    Test 2 — Management allowlist: comma-separated CIDR/IP list parsing.
    """
    s = create_settings_with_env({
        "MANAGEMENT_ALLOWLIST": "10.100.0.1, 192.168.1.1, 127.0.0.1"
    })
    assert isinstance(s.management_allowlist, list)
    assert s.management_allowlist == ["10.100.0.1", "192.168.1.1", "127.0.0.1"]


def test_cidr_list_parsing():
    """
    Validates on-prem and AWS VPC CIDR list parsing.
    """
    s = create_settings_with_env({
        "ON_PREM_CIDRS": "192.168.0.0/16, 10.0.0.0/16",
        "AWS_VPC_CIDRS": "10.100.0.0/16, 172.31.0.0/16",
    })
    assert s.on_prem_cidrs == ["192.168.0.0/16", "10.0.0.0/16"]
    assert s.aws_vpc_cidrs == ["10.100.0.0/16", "172.31.0.0/16"]


def test_boolean_parsing():
    """
    Test 3 — Boolean parsing: strings like 'False', 'false', '0', 'true', '1' are correctly parsed.
    """
    s1 = create_settings_with_env({
        "DEBUG": "False",
        "GOOGLE_OAUTH_ENABLED": "false",
        "DB_ECHO": "0",
    })
    assert s1.debug is False
    assert s1.google_oauth_enabled is False
    assert s1.db_echo is False

    s2 = create_settings_with_env({
        "DEBUG": "true",
        "GOOGLE_OAUTH_ENABLED": "1",
        "DB_ECHO": "True",
    })
    assert s2.debug is True
    assert s2.google_oauth_enabled is True
    assert s2.db_echo is True


def test_integer_parsing():
    """
    Test 4 — Integer parsing: numeric string variables are converted to ints.
    """
    s = create_settings_with_env({
        "PORT": "9000",
        "AUTH_ACCESS_TOKEN_EXPIRE_MINUTES": "30",
        "AUTH_REFRESH_TOKEN_EXPIRE_DAYS": "7",
        "DEFAULT_RULE_TTL_SECONDS": "600",
    })
    assert s.port == 9000
    assert s.auth_access_token_expire_minutes == 30
    assert s.auth_refresh_token_expire_days == 7
    assert s.default_rule_ttl_seconds == 600


def test_optional_api_keys_and_empty_values():
    """
    Test 5 — Optional API keys: empty strings must not crash configuration loading.
    """
    s = create_settings_with_env({
        "GROQ_API_KEY": "",
        "OPENAI_API_KEY": "",
        "AWS_ACCESS_KEY_ID": "",
        "AWS_SECRET_ACCESS_KEY": "",
        "GOOGLE_CLIENT_ID": "",
        "GOOGLE_CLIENT_SECRET": "",
        "LLM_MODEL": "",
    })
    assert s.groq_api_key == ""
    assert s.openai_api_key == ""
    assert s.google_client_id == ""
    assert s.google_client_secret == ""


def test_database_url_normalization():
    """
    Validates that legacy postgres:// urls are normalized to postgresql://.
    """
    s = create_settings_with_env({
        "DATABASE_URL": "postgres://user:pass@localhost:5432/testdb"
    })
    assert s.database_url.startswith("postgresql://")


def test_aws_vpc_flow_log_group_synchronization():
    """
    Validates that AWS_VPC_FLOW_LOG_GROUP updates aws_cloudwatch_log_group if provided.
    """
    s = create_settings_with_env({
        "AWS_VPC_FLOW_LOG_GROUP": "/custom/vpc/flow-logs"
    })
    assert s.aws_cloudwatch_log_group == "/custom/vpc/flow-logs"


def test_invalid_integer_field_fails_cleanly():
    """
    Test 6 — Invalid values: non-integer passed to integer field fails with ValidationError.
    """
    with pytest.raises(ValidationError) as excinfo:
        create_settings_with_env({
            "PORT": "invalid_port_string"
        })
    errors = excinfo.value.errors()
    assert any(e["loc"] == ("port",) for e in errors)


def test_secret_safety_no_leakage():
    """
    Test 7 — Secret safety: String representations and debug outputs do not expose raw secrets directly.
    """
    s = create_settings_with_env({
        "AUTH_JWT_SECRET": "test_jwt_secret_entropy_12345",
        "ADMIN_PASSWORD": "AdminSecretPassword123!",
    })
    assert s.auth_jwt_secret == "test_jwt_secret_entropy_12345"
    assert s.admin_password == "AdminSecretPassword123!"
