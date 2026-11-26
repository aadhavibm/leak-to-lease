"""Unit tests for lease-mcp server and security core."""

from __future__ import annotations

import hashlib
import inspect
import os
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
import mysql.connector

from lease_mcp.models import (
    ConfigureMysqlResult,
    CreateRoleResult,
    EnableDbEngineResult,
    LookupLeaseResult,
    ProveDeadResult,
    QuarantineResult,
    RotateRootResult,
)
from lease_mcp.security import (
    compute_fingerprint,
    extract_and_sanitize_line,
    mask_secret,
    parse_and_sanitize_text_line,
)
from lease_mcp.server import (
    configure_mysql_connection,
    create_dynamic_role,
    enable_db_engine,
    get_vault_client,
    lookup_lease,
    mcp,
    prove_dead,
    quarantine_secret,
    rotate_root,
)


def test_fingerprint_generation():
    """Verify SHA-256 fingerprinting produces deterministic, standard format."""
    synthetic_secret = "synthetic_test_secret_123"
    fp = compute_fingerprint(synthetic_secret)
    expected_digest = hashlib.sha256(synthetic_secret.encode("utf-8")).hexdigest()
    assert fp == f"sha256:{expected_digest}"
    assert len(fp) == 7 + 64
    assert compute_fingerprint(synthetic_secret) == fp
    assert compute_fingerprint("other_synthetic_val") != fp


def test_mask_secret():
    """Verify secret masking."""
    assert mask_secret("synthetic_val") == "********"
    assert mask_secret("") == "********"
    assert mask_secret("12345678", visible_suffix_len=4) == "****5678"


def test_yaml_and_shell_extraction_same_fingerprint(tmp_path: Path):
    """Verify both YAML and Shell formats extract the bare synthetic value and produce identical fingerprints."""
    synthetic_secret = "leaked-demo-password-NOT-REAL"  # Intentional fake for the demo.

    yaml_file = tmp_path / "application.yml"
    yaml_file.write_text(
        f"spring:\n"
        f"  datasource:\n"
        f"    username: root\n"
        f"    password: {synthetic_secret}\n"
        f"    url: jdbc:mysql://localhost:3306/petclinic\n",
        encoding="utf-8",
    )

    readme_file = tmp_path / "README.md"
    readme_file.write_text(
        f"# Setup\n"
        f"Run database with:\n"
        f"```\n"
        f"docker run -e MYSQL_ROOT_PASSWORD={synthetic_secret} -e MYSQL_DATABASE=petclinic -p 3306:3306 mysql:8.4.5\n"
        f"```\n",
        encoding="utf-8",
    )

    extracted_yaml = extract_and_sanitize_line(yaml_file, line_number=4)
    extracted_shell = extract_and_sanitize_line(readme_file, line_number=4)

    # 1. Bare value assertions
    assert extracted_yaml == synthetic_secret
    assert extracted_shell == synthetic_secret
    assert extracted_yaml == extracted_shell

    # 2. Fingerprint assertions
    fp_yaml = compute_fingerprint(extracted_yaml)
    fp_shell = compute_fingerprint(extracted_shell)
    expected_fp = f"sha256:{hashlib.sha256(synthetic_secret.encode('utf-8')).hexdigest()}"

    assert fp_yaml == expected_fp
    assert fp_shell == expected_fp
    assert fp_yaml == fp_shell

    # 3. File sanitization assertions
    yaml_content = yaml_file.read_text(encoding="utf-8")
    readme_content = readme_file.read_text(encoding="utf-8")

    assert synthetic_secret not in yaml_content
    assert synthetic_secret not in readme_content
    assert "password: ${DB_PASSWORD_QUARANTINED}" in yaml_content
    assert "docker run -e MYSQL_ROOT_PASSWORD=${DB_PASSWORD_QUARANTINED} -e MYSQL_DATABASE=petclinic" in readme_content


def test_parse_and_sanitize_text_line_formats():
    """Verify various line formats extract the bare synthetic value."""
    synthetic_val = "synthetic_key_456"

    test_lines = [
        (f"password: {synthetic_val}\n", "password: ${DB_PASSWORD_QUARANTINED}\n"),
        (f"    password: '{synthetic_val}'\n", "    password: ${DB_PASSWORD_QUARANTINED}\n"),
        (f'  password: "{synthetic_val}"\n', '  password: ${DB_PASSWORD_QUARANTINED}\n'),
        (f"password: {synthetic_val} # mysql pass\n", "password: ${DB_PASSWORD_QUARANTINED} # mysql pass\n"),
        (f"spring.datasource.password={synthetic_val}\n", "spring.datasource.password= ${DB_PASSWORD_QUARANTINED}\n"),
        (f"export MYSQL_ROOT_PASSWORD={synthetic_val}\n", "export MYSQL_ROOT_PASSWORD=${DB_PASSWORD_QUARANTINED}\n"),
        (
            f"docker run -e MYSQL_ROOT_PASSWORD={synthetic_val} -e MYSQL_DATABASE=petclinic mysql\n",
            "docker run -e MYSQL_ROOT_PASSWORD=${DB_PASSWORD_QUARANTINED} -e MYSQL_DATABASE=petclinic mysql\n",
        ),
        (
            f'docker run -e MYSQL_ROOT_PASSWORD="{synthetic_val}" -p 3306:3306 mysql\n',
            'docker run -e MYSQL_ROOT_PASSWORD="${DB_PASSWORD_QUARANTINED}" -p 3306:3306 mysql\n',
        ),
    ]

    for raw_line, expected_sanitized in test_lines:
        sec, san = parse_and_sanitize_text_line(raw_line)
        assert sec == synthetic_val, f"Failed extracting bare value from: {raw_line!r}"
        assert compute_fingerprint(sec) == f"sha256:{hashlib.sha256(synthetic_val.encode('utf-8')).hexdigest()}"
        assert san == expected_sanitized


def test_quarantine_secret_tool(tmp_path: Path):
    """Verify quarantine_secret tool executes and returns reference & fingerprint without leaking secret."""
    sample_file = tmp_path / "test-config.yml"
    synthetic_val = "synthetic_hardcoded_123"
    sample_file.write_text(f"password: {synthetic_val}\n", encoding="utf-8")

    mock_client = MagicMock()
    with patch("lease_mcp.server.get_vault_client", return_value=mock_client):
        result = quarantine_secret(
            source_path=str(sample_file),
            line_number=1,
        )

    assert isinstance(result, QuarantineResult)
    assert result.quarantine_id.startswith("quar-")
    assert result.fingerprint == f"sha256:{hashlib.sha256(synthetic_val.encode('utf-8')).hexdigest()}"
    assert result.status == "QUARANTINED_AND_SANITIZED"
    assert synthetic_val not in result.model_dump_json()

    sanitized_content = sample_file.read_text(encoding="utf-8")
    assert synthetic_val not in sanitized_content


def test_enable_db_engine_mock():
    """Verify enable_db_engine tool logic with mocked Vault client."""
    mock_client = MagicMock()
    with patch("lease_mcp.server.get_vault_client", return_value=mock_client):
        res = enable_db_engine(mount_path="database")
        assert res.mount_path == "database"
        assert res.status == "MOUNTED"
        mock_client.sys.enable_secrets_engine.assert_called_once_with(
            backend_type="database",
            path="database",
            description="Vault database secrets engine for dynamic credentials",
        )


def test_configure_mysql_connection_mock():
    """Verify configure_mysql_connection tool logic with mocked Vault client resolving secret by quarantine_id."""
    mock_client = MagicMock()
    mock_client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {"data": {
            "credential": "mock_retrieved_password",
            "fingerprint": compute_fingerprint("mock_retrieved_password"),
        }}
    }

    with patch("lease_mcp.server.get_vault_client", return_value=mock_client):
        res = configure_mysql_connection(
            quarantine_id="quar-abc12345",
            name="mysql-petclinic",
            allowed_roles=["customers", "vets", "visits"],
        )
        assert res.connection_name == "mysql-petclinic"
        assert res.admin_user == "root"
        assert res.status == "CONFIGURED"

        mock_client.secrets.database.configure.assert_called_once_with(
            name="mysql-petclinic",
            plugin_name="mysql-database-plugin",
            connection_url="{{username}}:{{password}}@tcp(127.0.0.1:3306)/petclinic",
            allowed_roles=["customers", "vets", "visits"],
            username="root",
            password="mock_retrieved_password",
            root_rotation_statements=[
                "ALTER USER '{{username}}'@'%' IDENTIFIED BY '{{password}}';",
                "ALTER USER '{{username}}'@'localhost' IDENTIFIED BY '{{password}}';",
            ],
            mount_point="database",
        )


def test_create_dynamic_role_mock():
    """Verify create_dynamic_role tool logic with default DML privileges on petclinic.*."""
    mock_client = MagicMock()
    with patch("lease_mcp.server.get_vault_client", return_value=mock_client):
        res = create_dynamic_role(role_name="customers", db_name="mysql-petclinic")
        assert res.role_name == "customers"
        assert res.db_name == "mysql-petclinic"
        assert res.default_ttl == "1h"
        assert res.max_ttl == "24h"
        assert res.status == "ROLE_ACTIVE"

        mock_client.secrets.database.create_role.assert_called_once_with(
            name="customers",
            db_name="mysql-petclinic",
            creation_statements=[
                "CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}';",
                "GRANT SELECT, INSERT, UPDATE, DELETE ON petclinic.* TO '{{name}}'@'%';",
            ],
            revocation_statements=[
                "DROP USER '{{name}}'@'%';",
            ],
            default_ttl="1h",
            max_ttl="24h",
            mount_point="database",
        )


def test_rotate_root_mock():
    """Verify rotate_root tool calls Vault root rotation endpoint."""
    mock_client = MagicMock()
    with patch("lease_mcp.server.get_vault_client", return_value=mock_client):
        res = rotate_root(db_name="mysql-petclinic")
        assert res.db_name == "mysql-petclinic"
        assert res.rotated is True
        assert res.status == "ROOT_ROTATED"
        mock_client.secrets.database.rotate_root_credentials.assert_called_once_with(
            name="mysql-petclinic",
            mount_point="database",
        )


def test_lookup_lease_mock():
    """Verify lookup_lease tool parses lease metadata."""
    mock_client = MagicMock()
    mock_client.sys.read_lease.return_value = {
        "issue_time": "2026-10-29T16:00:00Z",
        "data": {"ttl": 1800, "renewable": True},
    }
    with patch("lease_mcp.server.get_vault_client", return_value=mock_client):
        res = lookup_lease(lease_id="database/creds/customers/abc-123")
        assert res.lease_id == "database/creds/customers/abc-123"
        assert res.ttl_remaining_seconds == 1800
        assert res.renewable is True
        assert res.status == "ACTIVE"


def test_prove_dead_before_rotation_active():
    """Verify prove_dead returns ACCEPTED / ERROR_CREDENTIAL_STILL_ACTIVE when credential is still valid."""
    mock_client = MagicMock()
    mock_client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {"data": {
            "credential": "synthetic_active_password",
            "fingerprint": compute_fingerprint("synthetic_active_password"),
        }}
    }
    mock_conn = MagicMock()
    mock_conn.is_connected.return_value = True

    with patch("lease_mcp.server.get_vault_client", return_value=mock_client):
        with patch("mysql.connector.connect", return_value=mock_conn):
            res = prove_dead(quarantine_id="quar-12345", host="127.0.0.1", port=3306)
            assert res.tested_user == "root"
            assert res.connection_rejected is False
            assert res.result == "ACCEPTED"
            assert res.proof_status == "ERROR_CREDENTIAL_STILL_ACTIVE"
            assert res.error_code is None


def test_prove_dead_after_rotation_rejected():
    """Verify prove_dead catches MySQL authentication rejection and returns REJECTED / CREDENTIAL_PROVEN_DEAD."""
    mock_client = MagicMock()
    mock_client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {"data": {
            "credential": "synthetic_dead_password",
            "fingerprint": compute_fingerprint("synthetic_dead_password"),
        }}
    }
    err = mysql.connector.Error("Access denied", errno=1045)
    with patch("lease_mcp.server.get_vault_client", return_value=mock_client):
        with patch("mysql.connector.connect", side_effect=err):
            res = prove_dead(quarantine_id="quar-12345", host="127.0.0.1", port=3306)
            assert res.tested_user == "root"
            assert res.connection_rejected is True
            assert res.result == "REJECTED"
            assert res.proof_status == "CREDENTIAL_PROVEN_DEAD"
            assert "synthetic_dead_password" not in res.model_dump_json()


def test_all_tools_zero_secret_parameters():
    """Verify that NO tool accepts raw secrets or passwords in its parameter signature."""
    forbidden_param_names = {"password", "secret", "raw_secret", "admin_password", "credential"}

    tools = [
        quarantine_secret,
        enable_db_engine,
        configure_mysql_connection,
        create_dynamic_role,
        rotate_root,
        lookup_lease,
        prove_dead,
    ]

    for tool in tools:
        sig = inspect.signature(tool)
        param_names = set(sig.parameters.keys())
        overlap = param_names.intersection(forbidden_param_names)
        assert not overlap, f"Tool {tool.__name__} has forbidden secret parameter(s): {overlap}"


def test_all_models_zero_secret_fields():
    """Verify that all Pydantic output models contain no plaintext secret or password fields."""
    forbidden_field_substrings = ["password", "raw_secret", "plaintext"]

    model_classes = [
        QuarantineResult,
        EnableDbEngineResult,
        ConfigureMysqlResult,
        CreateRoleResult,
        RotateRootResult,
        LookupLeaseResult,
        ProveDeadResult,
    ]

    for model_cls in model_classes:
        for field_name in model_cls.model_fields.keys():
            for forbidden in forbidden_field_substrings:
                assert (
                    forbidden not in field_name.lower()
                ), f"Model {model_cls.__name__} has field {field_name} matching forbidden '{forbidden}'"


def test_models_instantiation():
    """Verify instantiation of all result models."""
    r1 = EnableDbEngineResult(mount_path="database", status="MOUNTED")
    assert r1.status == "MOUNTED"

    r2 = ConfigureMysqlResult(connection_name="mysql-petclinic", admin_user="root")
    assert r2.status == "CONFIGURED"

    r3 = CreateRoleResult(role_name="customers", db_name="mysql-petclinic", default_ttl="1h", max_ttl="24h")
    assert r3.role_name == "customers"

    r4 = RotateRootResult(db_name="mysql-petclinic", rotated=True)
    assert r4.rotated is True

    r5 = LookupLeaseResult(
        lease_id="database/creds/customers/123",
        issue_time="2026-10-29T15:00:00Z",
        ttl_remaining_seconds=3600,
        renewable=True,
        status="ACTIVE",
    )
    assert r5.ttl_remaining_seconds == 3600

    r6 = ProveDeadResult(
        tested_user="root",
        connection_rejected=True,
        result="REJECTED",
        error_code="1045",
        proof_status="CREDENTIAL_PROVEN_DEAD",
    )
    assert r6.connection_rejected is True
    assert r6.result == "REJECTED"
    assert r6.proof_status == "CREDENTIAL_PROVEN_DEAD"


def test_prove_dead_unreachable_db():
    """Verify prove_dead returns INCONCLUSIVE when the database is down or unreachable."""
    mock_client = MagicMock()
    mock_client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {"data": {
            "credential": "synthetic_password",
            "fingerprint": compute_fingerprint("synthetic_password"),
        }}
    }
    err = mysql.connector.Error("Can't connect to MySQL server", errno=2003)
    with patch("lease_mcp.server.get_vault_client", return_value=mock_client):
        with patch("mysql.connector.connect", side_effect=err):
            res = prove_dead(quarantine_id="quar-12345", host="127.0.0.1", port=1)
            assert res.connection_rejected is False
            assert res.result == "INCONCLUSIVE"
            assert res.proof_status == "INCONCLUSIVE_DB_UNREACHABLE"
            assert res.error_code == "2003"


def test_vault_down_raises_error():
    """Verify that when Vault is down/unreachable, tools raise a clear error rather than reporting a fake success."""
    with patch.dict(os.environ, {"VAULT_ADDR": "http://127.0.0.1:1", "VAULT_TOKEN": "some_token"}):
        with pytest.raises(Exception) as exc_info:
            enable_db_engine(mount_path="database")
        assert "Failed to connect" in str(exc_info.value) or "authenticated" in str(exc_info.value) or "Missing" in str(exc_info.value)


def test_quarantine_secret_vault_failure_no_sanitize(tmp_path: Path):
    """Verify quarantine_secret doesn't sanitize the file if the Vault write fails."""
    sample_file = tmp_path / "test-config.yml"
    synthetic_val = "synthetic_hardcoded_123"
    sample_file.write_text(f"password: {synthetic_val}\n", encoding="utf-8")

    mock_client = MagicMock()
    mock_client.secrets.kv.v2.create_or_update_secret.side_effect = Exception("Vault write error")
    mock_client.secrets.kv.v1.create_or_update_secret.side_effect = Exception("Vault write error")

    with patch("lease_mcp.server.get_vault_client", return_value=mock_client):
        with pytest.raises(Exception) as exc_info:
            quarantine_secret(source_path=str(sample_file), line_number=1)
        
        # Verify the exception was raised
        assert "Failed to store secret in Vault KV" in str(exc_info.value)
        
        # Verify that the file content was NOT sanitized (i.e. remains unchanged)
        assert sample_file.read_text(encoding="utf-8") == f"password: {synthetic_val}\n"


def test_lookup_lease_not_found():
    """Verify lookup_lease returns status NOT_FOUND and ttl 0 when lease is missing or invalid."""
    mock_client = MagicMock()
    import hvac.exceptions
    mock_client.sys.read_lease.side_effect = hvac.exceptions.InvalidPath("lease not found")
    
    with patch("lease_mcp.server.get_vault_client", return_value=mock_client):
        res = lookup_lease(lease_id="missing-lease-id")
        assert res.status == "NOT_FOUND"
        assert res.ttl_remaining_seconds == 0
        assert res.renewable is False


def test_get_vault_client_missing_token():
    """Verify get_vault_client raises RuntimeError when token is missing."""
    with patch.dict(os.environ, {}, clear=True):
        with patch("pathlib.Path.is_file", return_value=False):
            with pytest.raises(RuntimeError) as exc_info:
                get_vault_client()
            assert "Vault authentication token is missing" in str(exc_info.value)
