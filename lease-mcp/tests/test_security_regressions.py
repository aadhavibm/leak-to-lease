"""Regression coverage for parsing, source safety, and secret-free MCP failures."""

import json
import os
from pathlib import Path
import stat
import subprocess
from unittest.mock import MagicMock, patch

import hvac
import mysql.connector
from pydantic import ValidationError
import pytest

from lease_mcp.models import ProveDeadResult
from lease_mcp.security import (
    compute_fingerprint, parse_and_sanitize_text_line, prepare_secret_line,
    source_file_lock, SourceBusyError,
)
from lease_mcp.server import (
    configure_mysql_connection, create_dynamic_role, enable_db_engine,
    LeaseMcpError, lookup_lease, prove_dead, quarantine_secret,
)


def record(value="synthetic-audit-only"):
    return {"data": {"data": {"credential": value, "fingerprint": compute_fingerprint(value)}}}


@pytest.mark.parametrize(("line", "expected", "hint"), [
    ("password: audit#hash\n", "audit#hash", None),
    ("password: audit#hash # comment\n", "audit#hash", None),
    ("password: 'audit''quote'\n", "audit'quote", None),
    ('password: "audit\\\"quote"\n', 'audit"quote', None),
    ('password: "audit with spaces"\r\n', "audit with spaces", None),
    ("password: '1234'\n", "1234", None),
    ("password: 'true'\n", "true", None),
    (r"spring.datasource.password=audit\ with\ spaces" + "\n", "audit with spaces", "properties"),
    (r"password: audit\u0023hash" + "\n", "audit#hash", "properties"),
    (r"password: audit\uD83D\uDE00" + "\n", "audit\U0001f600", "properties"),
    ("password=audit#literal\n", "audit#literal", "properties"),
    ('export MYSQL_ROOT_PASSWORD="audit with spaces"\n', "audit with spaces", None),
    ("export MYSQL_ROOT_PASSWORD='audit$HOME'\n", "audit$HOME", None),
    (r"export MYSQL_ROOT_PASSWORD=audit\$literal" + "\n", "audit$literal", None),
    ('docker run -e MYSQL_ROOT_PASSWORD="audit\\\"quote" -e MYSQL_DATABASE=petclinic\n', 'audit"quote', None),
])
def test_supported_formats_extract_exact_value(line, expected, hint):
    value, sanitized = parse_and_sanitize_text_line(line, format_hint=hint)
    assert value == expected
    assert "${DB_PASSWORD_QUARANTINED}" in sanitized
    assert expected not in sanitized
    assert sanitized.endswith("\r\n" if line.endswith("\r\n") else "\n")


@pytest.mark.parametrize("encoded", [
    r'"audit\$literal"', r'"audit\`literal"', r'"audit\\\$literal"',
    r"'audit\$literal'", r"'audit\`literal'", r'audit\$literal',
    r"""'audit'"\$literal"suffix""", r'"audit\\literal"', r'"audit\qliteral"',
    r"""'audit'"\\\$"'literal'""",
])
def test_shell_literal_matches_bash_without_evaluating_source_files(encoded):
    expected = subprocess.check_output(
        ["bash", "--noprofile", "--norc", "-c", f"printf '%s' {encoded}"], text=True,
    )
    value, _ = parse_and_sanitize_text_line(
        f"export MYSQL_ROOT_PASSWORD={encoded}\n", format_hint="shell",
    )
    assert value == expected


def test_escaped_shell_quarantine_has_an_accepted_baseline_before_rotation(tmp_path):
    source = tmp_path / "demo.env"
    source.write_text(r'export MYSQL_ROOT_PASSWORD="audit\$literal"' + "\n")
    client = MagicMock()
    with patch("lease_mcp.server.get_vault_client", return_value=client):
        quarantined = quarantine_secret(str(source), 1)
        stored = client.secrets.kv.v2.create_or_update_secret.call_args.kwargs["secret"]
        assert stored["credential"] == "audit$literal"
        client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": stored}}

        def authenticate(**kwargs):
            if kwargs["password"] != "audit$literal":
                raise mysql.connector.Error(errno=1045)
            return MagicMock()

        with patch("lease_mcp.server.mysql.connector.connect", side_effect=authenticate):
            baseline = prove_dead(quarantined.quarantine_id)
    assert baseline.result == "ACCEPTED"
    assert baseline.proof_status == "ERROR_CREDENTIAL_STILL_ACTIVE"
    client.secrets.database.rotate_root_credentials.assert_not_called()


@pytest.mark.parametrize("line", [
    "username: root\n", "# password removed\n", "password:\n",
    "password: ${DB_PASSWORD_QUARANTINED}\n", "password: {{reference}}\n",
    "password: |\n", "password: >\n", "password: true\n", "password: 1234\n",
    'password: "unterminated\n', "password: *alias\n",
    "password: &shared audit-only\n",
    "export MYSQL_ROOT_PASSWORD=$HOME\n", 'export MYSQL_ROOT_PASSWORD="audit$HOME"\n',
    "export MYSQL_ROOT_PASSWORD=$(not-executed)\n",
    "export MYSQL_ROOT_PASSWORD='unterminated\n",
    "export MYSQL_ROOT_PASSWORD=first MYSQL_PASSWORD=second\n",
])
def test_unsupported_or_noncredential_lines_are_rejected(line):
    with pytest.raises(ValueError):
        parse_and_sanitize_text_line(line)


def test_quarantine_preserves_unaffected_bytes_and_file_mode(tmp_path):
    path = tmp_path / "application.yml"
    path.write_bytes(b"header: same\r\npassword: audit#hash\r\nfooter: same\r\n")
    path.chmod(0o640)
    with patch("lease_mcp.server.get_vault_client", return_value=MagicMock()):
        result = quarantine_secret(str(path), 2)
    assert result.fingerprint == compute_fingerprint("audit#hash")
    assert path.read_bytes() == b"header: same\r\npassword: ${DB_PASSWORD_QUARANTINED}\r\nfooter: same\r\n"
    assert stat.S_IMODE(path.stat().st_mode) == 0o640


def test_quarantine_rejects_repeat_and_wrong_line_before_vault(tmp_path):
    path = tmp_path / "application.yml"
    path.write_text("username: root\npassword: audit-only\n")
    with patch("lease_mcp.server.get_vault_client", return_value=MagicMock()) as vault:
        with pytest.raises(ValueError):
            quarantine_secret(str(path), 1)
        vault.assert_not_called()
        quarantine_secret(str(path), 2)
        with pytest.raises(ValueError):
            quarantine_secret(str(path), 2)
        assert vault.call_count == 1
    assert path.read_text().startswith("username: root\n")


def test_quarantine_rejects_stale_fingerprint_before_vault(tmp_path):
    path = tmp_path / "application.yml"
    path.write_text("password: current-only\n")
    with patch("lease_mcp.server.get_vault_client") as vault:
        with pytest.raises(LeaseMcpError, match="SOURCE_FINGERPRINT_MISMATCH"):
            quarantine_secret(str(path), 1, expected_fingerprint=compute_fingerprint("old-only"))
    vault.assert_not_called()
    assert path.read_text() == "password: current-only\n"


def test_quarantine_detects_concurrent_edit_and_returns_recovery_reference(tmp_path):
    path = tmp_path / "application.yml"
    path.write_text("password: audit-only\n")
    client = MagicMock()
    client.secrets.kv.v2.create_or_update_secret.side_effect = lambda **kwargs: path.write_text("username: edited\n")
    with patch("lease_mcp.server.get_vault_client", return_value=client):
        with pytest.raises(LeaseMcpError, match="QUARANTINED_NOT_SANITIZED") as error:
            quarantine_secret(str(path), 1)
    metadata = json.loads(str(error.value).split(": ", 1)[1])
    assert metadata["error_code"] == "SOURCE_CHANGED"
    assert metadata["quarantine_id"].startswith("quar-")
    assert metadata["fingerprint"] == compute_fingerprint("audit-only")
    assert path.read_text() == "username: edited\n"


def test_quarantine_replacement_failure_preserves_recovery_metadata(tmp_path, caplog):
    value = "synthetic-sensitive-exception"
    path = tmp_path / "application.yml"
    path.write_text(f"password: {value}\n")
    with patch("lease_mcp.server.get_vault_client", return_value=MagicMock()), patch(
        "lease_mcp.server.replace_secret_line", side_effect=PermissionError(value),
    ):
        with pytest.raises(LeaseMcpError) as error:
            quarantine_secret(str(path), 1)
    metadata = json.loads(str(error.value).split(": ", 1)[1])
    assert metadata["error_code"] == "SOURCE_REPLACE_FAILED"
    assert value not in str(error.value) + caplog.text
    assert path.read_text() == f"password: {value}\n"


def test_quarantine_refuses_concurrent_tool_operation(tmp_path):
    path = tmp_path / "application.yml"
    path.write_text("password: audit-only\n")
    with source_file_lock(path), patch("lease_mcp.server.get_vault_client") as vault:
        with pytest.raises(SourceBusyError):
            quarantine_secret(str(path), 1)
    vault.assert_not_called()


def test_quarantine_permission_failure_does_not_try_kv_v1(tmp_path, caplog):
    value = "synthetic-sensitive-exception"
    path = tmp_path / "application.yml"
    path.write_text("password: audit-only\n")
    client = MagicMock()
    client.secrets.kv.v2.create_or_update_secret.side_effect = hvac.exceptions.Forbidden(value)
    with patch("lease_mcp.server.get_vault_client", return_value=client):
        with pytest.raises(LeaseMcpError, match="VAULT_ACCESS_DENIED") as error:
            quarantine_secret(str(path), 1)
    assert value not in str(error.value) + caplog.text
    client.secrets.kv.v1.create_or_update_secret.assert_not_called()
    assert path.read_text() == "password: audit-only\n"


def test_quarantine_supports_kv_v1_only_on_invalid_path(tmp_path):
    path = tmp_path / "application.yml"
    path.write_text("password: audit-only\n")
    client = MagicMock()
    client.secrets.kv.v2.create_or_update_secret.side_effect = hvac.exceptions.InvalidPath("unsupported path")
    with patch("lease_mcp.server.get_vault_client", return_value=client):
        result = quarantine_secret(str(path), 1)
    client.secrets.kv.v1.create_or_update_secret.assert_called_once()
    assert result.status == "QUARANTINED_AND_SANITIZED"


@pytest.mark.parametrize("data", [
    {"credential": ""},
    {"credential": "${DB_PASSWORD_QUARANTINED}"},
    {"credential": "audit-only"},
    {"credential": "audit-only", "fingerprint": compute_fingerprint("different-only")},
])
def test_invalid_quarantine_cannot_configure_or_prove(data):
    client = MagicMock()
    client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": data}}
    with patch("lease_mcp.server.get_vault_client", return_value=client), patch("mysql.connector.connect") as connect:
        with pytest.raises(LeaseMcpError):
            configure_mysql_connection("quar-test")
        with pytest.raises(LeaseMcpError):
            prove_dead("quar-test")
    client.secrets.database.configure.assert_not_called()
    connect.assert_not_called()


def test_proof_does_not_accept_a_disconnected_connector():
    client = MagicMock()
    client.secrets.kv.v2.read_secret_version.return_value = record()
    connection = MagicMock()
    connection.is_connected.return_value = False
    with patch("lease_mcp.server.get_vault_client", return_value=client), patch(
        "mysql.connector.connect", return_value=connection,
    ):
        result = prove_dead("quar-test")
    assert result.result == "INCONCLUSIVE"
    assert result.connection_rejected is False
    connection.close.assert_called_once()


def test_hash_credential_is_valid_before_rotation(tmp_path):
    value = "synthetic#hash-only"
    path = tmp_path / "application.yml"
    path.write_text(f"password: {value}\n")
    client = MagicMock()
    with patch("lease_mcp.server.get_vault_client", return_value=client):
        quarantined = quarantine_secret(str(path), 1)
    stored = client.secrets.kv.v2.create_or_update_secret.call_args.kwargs["secret"]
    assert stored["credential"] == value
    client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": stored}}
    connection = MagicMock()
    connection.is_connected.return_value = True

    def authenticate(**kwargs):
        if kwargs["password"] != value:
            raise mysql.connector.Error("Synthetic rejected", errno=1045)
        return connection

    with patch("lease_mcp.server.get_vault_client", return_value=client), patch(
        "mysql.connector.connect", side_effect=authenticate,
    ):
        proof = prove_dead(quarantined.quarantine_id)
    assert proof.result == "ACCEPTED"
    assert proof.proof_status == "ERROR_CREDENTIAL_STILL_ACTIVE"


def test_zero_ttl_is_expired_and_malformed_lease_is_an_error():
    client = MagicMock()
    client.sys.read_lease.return_value = {"data": {"ttl": 0, "renewable": False}}
    with patch("lease_mcp.server.get_vault_client", return_value=client):
        assert lookup_lease("lease-test").status == "EXPIRED"
        client.sys.read_lease.return_value = {"data": {"ttl": "unknown"}}
        with pytest.raises(LeaseMcpError, match="LEASE_DATA_INVALID"):
            lookup_lease("lease-test")


def test_existing_mount_must_be_a_database_engine():
    client = MagicMock()
    client.sys.enable_secrets_engine.side_effect = hvac.exceptions.InvalidRequest("path in use")
    client.sys.list_mounted_secrets_engines.return_value = {"data": {"database/": {"type": "kv"}}}
    with patch("lease_mcp.server.get_vault_client", return_value=client):
        with pytest.raises(LeaseMcpError, match="DATABASE_MOUNT_CONFLICT"):
            enable_db_engine()
        client.sys.list_mounted_secrets_engines.return_value = {"data": {"database/": {"type": "database"}}}
        assert enable_db_engine().status == "ALREADY_EXISTS"


def test_explicit_empty_sql_is_rejected_before_vault():
    with patch("lease_mcp.server.get_vault_client") as vault:
        with pytest.raises(LeaseMcpError, match="ROLE_SQL_INVALID"):
            create_dynamic_role("role", creation_statements=[], revocation_statements=[])
        with pytest.raises(LeaseMcpError, match="ROTATION_SQL_INVALID"):
            configure_mysql_connection("quar-test", root_rotation_statements=[])
    vault.assert_not_called()


@pytest.mark.parametrize("operation", ["configure", "create_role", "rotate_root_credentials"])
def test_database_errors_never_echo_dependency_secrets(operation, caplog):
    value = "synthetic-sensitive-exception"
    client = MagicMock()
    client.secrets.kv.v2.read_secret_version.return_value = record()
    getattr(client.secrets.database, operation).side_effect = RuntimeError(value)
    from lease_mcp.server import rotate_root
    invoke = {
        "configure": lambda: configure_mysql_connection("quar-test"),
        "create_role": lambda: create_dynamic_role("role"),
        "rotate_root_credentials": rotate_root,
    }[operation]
    with patch("lease_mcp.server.get_vault_client", return_value=client):
        with pytest.raises(LeaseMcpError) as error:
            invoke()
    assert value not in str(error.value) + caplog.text


def test_source_snapshot_repr_cannot_expose_credentials(tmp_path):
    value = "synthetic-private-snapshot"
    path = tmp_path / "application.yml"
    path.write_text(f"password: {value}\n")
    assert value not in repr(prepare_secret_line(path, 1))


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="Named-pipe source test requires Unix")
def test_nonregular_source_is_rejected_without_opening_it(tmp_path):
    path = tmp_path / "source.yml"
    os.mkfifo(path)
    with pytest.raises(ValueError, match="regular file"):
        prepare_secret_line(path, 1)


def test_proof_model_has_no_success_defaults_or_extra_secret_fields():
    with pytest.raises(ValidationError):
        ProveDeadResult(connection_rejected=False, error_code=None)
    with pytest.raises(ValidationError):
        ProveDeadResult(
            connection_rejected=False, result="INCONCLUSIVE", error_code=None,
            proof_status="INCONCLUSIVE_DB_UNREACHABLE", password="synthetic-extra",
        )
