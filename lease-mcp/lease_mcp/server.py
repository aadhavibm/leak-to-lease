"""Reference-only Vault/MySQL credential remediation tools."""

from __future__ import annotations

from contextlib import contextmanager
import json
import logging
import os
from pathlib import Path
import re
import ssl
from typing import Iterator, List, Literal, NoReturn, Optional
from urllib.parse import urlsplit
import uuid

from dotenv import load_dotenv
from fastmcp import FastMCP
import hvac
import mysql.connector

from lease_mcp.models import (
    ConfigureMysqlResult, CreateRoleResult, EnableDbEngineResult,
    LookupLeaseResult, ProveDeadResult, QuarantineResult, RotateRootResult,
)
from lease_mcp.security import (
    compute_fingerprint, prepare_secret_line, replace_secret_line,
    source_file_lock, SourceChangedError, validate_secret_value,
)

logger = logging.getLogger(__name__)


def _production_mode() -> bool:
    profile = os.environ.get("LEASE_MCP_PROFILE", "development")
    if profile not in ("development", "production"):
        _fail("PROFILE_INVALID", "LEASE_MCP_PROFILE must be development or production.")
    return profile == "production"


class LeaseMcpError(RuntimeError):
    """Safe error text suitable for MCP responses and logs."""


def _fail(code: str, message: str) -> NoReturn:
    logger.error("%s", code)
    raise LeaseMcpError(f"{code}: {message}") from None


@contextmanager
def _vault_operation(code: str, message: str) -> Iterator[None]:
    try:
        yield
    except LeaseMcpError:
        raise
    except (hvac.exceptions.Forbidden, hvac.exceptions.Unauthorized):
        _fail("VAULT_ACCESS_DENIED", "Vault denied the operation. Check authentication and policy.")
    except Exception:
        _fail(code, message)


def _load_env_config() -> None:
    env_paths = [
        Path(__file__).resolve().parent.parent / ".env",
        Path.cwd() / "lease-mcp" / ".env",
        Path.cwd() / ".env",
    ]
    for env_file in env_paths:
        if env_file.is_file():
            try:
                load_dotenv(dotenv_path=env_file)
            except (OSError, UnicodeError):
                _fail("VAULT_CONFIG_UNREADABLE", "The private environment file could not be loaded.")
            break
    if not os.environ.get("VAULT_TOKEN"):
        token_file = Path.home() / ".vault-token"
        if token_file.is_file():
            try:
                token = token_file.read_text(encoding="utf-8").strip()
            except (OSError, UnicodeError):
                _fail("VAULT_TOKEN_FILE_UNREADABLE", "The private Vault token file could not be loaded.")
            if token:
                os.environ["VAULT_TOKEN"] = token


_load_env_config()
mcp = FastMCP("lease-mcp")


def get_vault_client() -> hvac.Client:
    _load_env_config()
    address = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
    token = os.environ.get("VAULT_TOKEN")
    try:
        parsed = urlsplit(address)
        parsed.port
    except ValueError:
        _fail("VAULT_ADDRESS_INVALID", "VAULT_ADDR must be a valid HTTP(S) endpoint.")
    if (
        parsed.scheme not in ("http", "https") or not parsed.hostname
        or parsed.username or parsed.password or parsed.query or parsed.fragment
    ):
        _fail("VAULT_ADDRESS_INVALID", "VAULT_ADDR must be an HTTP(S) endpoint without embedded credentials.")
    production = _production_mode()
    if production and parsed.scheme != "https":
        _fail("VAULT_TLS_REQUIRED", "Production requires an HTTPS Vault endpoint with verified certificates.")
    if os.environ.get("VAULT_SKIP_VERIFY", "").lower() in ("1", "true", "yes"):
        _fail("VAULT_TLS_BYPASS_FORBIDDEN", "Certificate verification cannot be disabled.")
    ca_file = os.environ.get("VAULT_CACERT")
    if ca_file and not Path(ca_file).is_file():
        _fail("VAULT_CA_INVALID", "The configured Vault CA certificate file does not exist.")
    if not token:
        _fail("VAULT_TOKEN_MISSING", "Vault authentication token is missing. Configure VAULT_TOKEN privately.")
    with _vault_operation("VAULT_UNAVAILABLE", "Failed to connect or authenticate with HashiCorp Vault."):
        client = hvac.Client(
            url=address, token=token, verify=ca_file or True,
            namespace=os.environ.get("VAULT_NAMESPACE"), allow_redirects=False,
        )
        authenticated = client.is_authenticated()
    if not authenticated:
        _fail("VAULT_AUTHENTICATION_FAILED", "Vault is not authenticated with the configured token.")
    if production:
        with _vault_operation("VAULT_AUTHORIZATION_CHECK_FAILED", "Production token metadata could not be verified."):
            metadata = client.auth.token.lookup_self().get("data", {})
        if not isinstance(metadata, dict):
            _fail("VAULT_PRODUCTION_AUTH_INVALID", "Production token metadata is invalid.")
        policies = metadata.get("policies")
        ttl = metadata.get("ttl")
        if (
            not isinstance(policies, list) or "root" in policies
            or not isinstance(ttl, int) or isinstance(ttl, bool) or ttl <= 0
        ):
            _fail("VAULT_PRODUCTION_AUTH_INVALID", "Production requires a finite-lived, non-root, least-privilege token.")
    return client


def is_vault_available() -> bool:
    try:
        get_vault_client()
    except LeaseMcpError:
        return False
    return True


def _quarantined_secret(client: hvac.Client, quarantine_id: str) -> str:
    if not re.fullmatch(r"quar-[A-Za-z0-9_-]{1,128}", quarantine_id):
        _fail("QUARANTINE_ID_INVALID", "Use a quarantine reference returned by quarantine_secret.")
    with _vault_operation("QUARANTINE_READ_FAILED", "Failed to retrieve the quarantined credential. Check its reference and KV policy."):
        try:
            response = client.secrets.kv.v2.read_secret_version(
                mount_point="secret", path=f"quarantine/{quarantine_id}", raise_on_deleted_version=True,
            )
            data = response.get("data", {}).get("data")
        except hvac.exceptions.InvalidPath:
            response = client.secrets.kv.v1.read_secret(
                mount_point="secret", path=f"quarantine/{quarantine_id}",
            )
            data = response.get("data")
    if not isinstance(data, dict):
        _fail("QUARANTINE_DATA_INVALID", "Quarantine record is missing valid credential metadata.")
    credential = data.get("credential")
    if not isinstance(credential, str):
        _fail("QUARANTINE_DATA_INVALID", "Quarantine record has no valid static credential.")
    try:
        value = validate_secret_value(credential)
    except ValueError:
        _fail("QUARANTINE_DATA_INVALID", "Quarantine record has no valid static credential.")
    fingerprint = data.get("fingerprint")
    if not isinstance(fingerprint, str) or compute_fingerprint(value) != fingerprint:
        _fail("QUARANTINE_FINGERPRINT_MISMATCH", "Quarantine record integrity could not be verified.")
    return value


def _mysql_tls_options() -> tuple[dict, dict]:
    certificate = os.environ.get("LEASE_MCP_MYSQL_CACERT")
    server_name = os.environ.get("LEASE_MCP_MYSQL_SERVER_NAME")
    if _production_mode() and (not certificate or not server_name):
        _fail("MYSQL_TLS_REQUIRED", "Production requires LEASE_MCP_MYSQL_CACERT and LEASE_MCP_MYSQL_SERVER_NAME.")
    if not certificate:
        return {}, {}
    try:
        pem = Path(certificate).read_text(encoding="ascii")
        if "PRIVATE KEY" in pem:
            _fail("MYSQL_CA_INVALID", "Provide a CA certificate file without private keys.")
        ssl.create_default_context(cafile=certificate)
    except (OSError, UnicodeError, ssl.SSLError):
        _fail("MYSQL_CA_INVALID", "The configured MySQL CA certificate is invalid or unreadable.")
    plugin = {"tls_ca": pem, "tls_skip_verify": False}
    if server_name:
        plugin["tls_server_name"] = server_name
    connector = {"ssl_ca": certificate, "ssl_verify_cert": True, "ssl_verify_identity": True}
    return plugin, connector


@mcp.tool()
def quarantine_secret(
    source_path: str,
    line_number: int,
    mount_path: str = "secret",
    expected_fingerprint: Optional[str] = None,
) -> QuarantineResult:
    """Store a validated static credential, then replace its unchanged source line."""
    if mount_path != "secret":
        _fail("QUARANTINE_MOUNT_UNSUPPORTED", "This workflow requires the quarantine KV mount named secret.")
    if expected_fingerprint is not None and not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_fingerprint):
        _fail("FINGERPRINT_INVALID", "Expected fingerprint must be a SHA-256 reference.")
    approved_root = os.environ.get("LEASE_MCP_SOURCE_ROOT")
    if _production_mode() and not approved_root:
        _fail("SOURCE_ROOT_REQUIRED", "Production quarantine requires an approved LEASE_MCP_SOURCE_ROOT.")
    if approved_root:
        try:
            root = Path(approved_root).resolve(strict=True)
            source = Path(source_path).resolve(strict=True)
        except OSError:
            _fail("SOURCE_NOT_APPROVED", "Approved source root or selected source is unavailable.")
        if not root.is_dir() or not source.is_relative_to(root):
            _fail("SOURCE_NOT_APPROVED", "Selected source is outside the approved source root.")
    with source_file_lock(source_path):
        snapshot = prepare_secret_line(source_path, line_number)
        fingerprint = compute_fingerprint(snapshot.raw_secret)
        if expected_fingerprint is not None and expected_fingerprint != fingerprint:
            _fail("SOURCE_FINGERPRINT_MISMATCH", "The current credential does not match the approved finding.")
        quarantine_id = f"quar-{uuid.uuid4().hex[:12]}"
        path = f"quarantine/{quarantine_id}"
        client = get_vault_client()
        data = {"credential": snapshot.raw_secret, "fingerprint": fingerprint, "source": str(snapshot.path)}
        with _vault_operation("QUARANTINE_WRITE_FAILED", "Failed to store secret in Vault KV. Source was not sanitized."):
            try:
                client.secrets.kv.v2.create_or_update_secret(mount_point="secret", path=path, secret=data)
            except hvac.exceptions.InvalidPath:
                client.secrets.kv.v1.create_or_update_secret(mount_point="secret", path=path, secret=data)
        try:
            replace_secret_line(snapshot)
        except (ValueError, OSError) as error:
            metadata = {
                "quarantine_id": quarantine_id,
                "fingerprint": fingerprint,
                "vault_kv_path": f"secret/{path}",
                "error_code": "SOURCE_CHANGED" if isinstance(error, SourceChangedError) else "SOURCE_REPLACE_FAILED",
            }
            _fail("QUARANTINED_NOT_SANITIZED", json.dumps(metadata, sort_keys=True))
    return QuarantineResult(
        quarantine_id=quarantine_id, fingerprint=fingerprint,
        vault_kv_path=f"secret/{path}", source_path=str(snapshot.path),
        status="QUARANTINED_AND_SANITIZED",
    )


@mcp.tool()
def enable_db_engine(mount_path: str = "database") -> EnableDbEngineResult:
    """Enable a database engine, verifying the type of an existing mount."""
    client = get_vault_client()
    status: Literal["MOUNTED", "ALREADY_EXISTS"] = "MOUNTED"
    with _vault_operation("DATABASE_MOUNT_FAILED", "Failed to enable the database secrets engine."):
        try:
            client.sys.enable_secrets_engine(
                backend_type="database", path=mount_path,
                description="Vault database secrets engine for dynamic credentials",
            )
        except hvac.exceptions.InvalidRequest:
            mounts = client.sys.list_mounted_secrets_engines().get("data", {})
            existing = mounts.get(mount_path.strip("/") + "/")
            if not isinstance(existing, dict) or existing.get("type") != "database":
                _fail("DATABASE_MOUNT_CONFLICT", "The requested path is not an existing database engine.")
            status = "ALREADY_EXISTS"
    return EnableDbEngineResult(mount_path=mount_path, engine_type="database", status=status)


@mcp.tool()
def configure_mysql_connection(
    quarantine_id: str,
    name: str = "mysql-petclinic",
    connection_url: str = "{{username}}:{{password}}@tcp(127.0.0.1:3306)/petclinic",
    admin_username: str = "root",
    allowed_roles: Optional[List[str]] = None,
    mount_path: str = "database",
    root_rotation_statements: Optional[List[str]] = None,
) -> ConfigureMysqlResult:
    """Configure MySQL using a verified quarantine reference, never a raw password."""
    if "{{username}}" not in connection_url or "{{password}}" not in connection_url:
        _fail("DATABASE_TEMPLATE_INVALID", "Use the literal username/password placeholders in the connection URL.")
    if _production_mode() and re.search(r"(?:[?&])tls=(?:false|skip-verify)(?:&|$)", connection_url, re.IGNORECASE):
        _fail("MYSQL_TLS_BYPASS_FORBIDDEN", "Production database connections cannot disable TLS verification.")
    roles = ["customers", "vets", "visits"] if allowed_roles is None else allowed_roles
    statements = [
        "ALTER USER '{{username}}'@'%' IDENTIFIED BY '{{password}}';",
        "ALTER USER '{{username}}'@'localhost' IDENTIFIED BY '{{password}}';",
    ] if root_rotation_statements is None else root_rotation_statements
    if not statements or any(not statement.strip() for statement in statements):
        _fail("ROTATION_SQL_INVALID", "Provide non-empty reviewed root-rotation statements.")
    client = get_vault_client()
    admin_password = _quarantined_secret(client, quarantine_id)
    tls, _ = _mysql_tls_options()
    with _vault_operation("DATABASE_CONFIG_FAILED", "Failed to configure the MySQL connection. Check endpoint, privileges, and template."):
        client.secrets.database.configure(
            name=name, plugin_name="mysql-database-plugin", connection_url=connection_url,
            allowed_roles=roles, username=admin_username, password=admin_password,
            root_rotation_statements=statements, mount_point=mount_path, **tls,
        )
    return ConfigureMysqlResult(
        connection_name=name, plugin_name="mysql-database-plugin",
        admin_user=admin_username, status="CONFIGURED",
    )


@mcp.tool()
def create_dynamic_role(
    role_name: str,
    db_name: str = "mysql-petclinic",
    default_ttl: str = "1h",
    max_ttl: str = "24h",
    creation_statements: Optional[List[str]] = None,
    revocation_statements: Optional[List[str]] = None,
    mount_path: str = "database",
) -> CreateRoleResult:
    """Create a reviewed dynamic role without silently replacing explicit empty SQL."""
    statements = [
        "CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}';",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON petclinic.* TO '{{name}}'@'%';",
    ] if creation_statements is None else creation_statements
    revocations = ["DROP USER '{{name}}'@'%';"] if revocation_statements is None else revocation_statements
    if not statements or not revocations or any(not item.strip() for item in statements + revocations):
        _fail("ROLE_SQL_INVALID", "Provide non-empty reviewed creation and revocation statements.")
    client = get_vault_client()
    with _vault_operation("DATABASE_ROLE_FAILED", "Failed to create the database role. Check connection, SQL permissions, and TTLs."):
        client.secrets.database.create_role(
            name=role_name, db_name=db_name, creation_statements=statements,
            revocation_statements=revocations, default_ttl=default_ttl,
            max_ttl=max_ttl, mount_point=mount_path,
        )
    return CreateRoleResult(
        role_name=role_name, db_name=db_name, default_ttl=default_ttl,
        max_ttl=max_ttl, status="ROLE_ACTIVE",
    )


@mcp.tool()
def rotate_root(db_name: str = "mysql-petclinic", mount_path: str = "database") -> RotateRootResult:
    """Rotate the approved administrator account managed by Vault."""
    client = get_vault_client()
    with _vault_operation("DATABASE_ROTATION_FAILED", "Root rotation failed. Check state with the owner before any retry."):
        client.secrets.database.rotate_root_credentials(name=db_name, mount_point=mount_path)
    return RotateRootResult(db_name=db_name, rotated=True, status="ROOT_ROTATED")


@mcp.tool()
def lookup_lease(lease_id: str) -> LookupLeaseResult:
    """Inspect lease metadata, distinguishing expiration from an active lease."""
    client = get_vault_client()
    try:
        with _vault_operation("LEASE_LOOKUP_FAILED", "Failed to inspect the lease. Check policy and Vault availability."):
            try:
                response = client.sys.read_lease(lease_id=lease_id)
            except hvac.exceptions.InvalidPath:
                response = None
            except hvac.exceptions.InvalidRequest as error:
                if not any(
                    "invalid lease" in message.lower() or "lease not found" in message.lower()
                    for message in (error.errors or [])
                ):
                    raise
                response = None
    except LeaseMcpError:
        raise
    if response is None:
        return LookupLeaseResult(
            lease_id=lease_id, issue_time="", ttl_remaining_seconds=0, renewable=False, status="NOT_FOUND",
        )
    if not isinstance(response, dict) or not isinstance(response.get("data"), dict):
        _fail("LEASE_DATA_INVALID", "Vault returned invalid lease metadata.")
    data = response["data"]
    ttl = data.get("ttl")
    if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl < 0:
        _fail("LEASE_DATA_INVALID", "Vault returned an invalid remaining lease TTL.")
    renewable = data.get("renewable", False)
    if not isinstance(renewable, bool):
        _fail("LEASE_DATA_INVALID", "Vault returned an invalid lease renewable flag.")
    issue_time = data.get("issue_time", response.get("issue_time", ""))
    if not isinstance(issue_time, str):
        _fail("LEASE_DATA_INVALID", "Vault returned an invalid lease issue time.")
    return LookupLeaseResult(
        lease_id=lease_id, issue_time=issue_time, ttl_remaining_seconds=ttl,
        renewable=renewable, status="ACTIVE" if ttl > 0 else "EXPIRED",
    )


@mcp.tool()
def prove_dead(
    quarantine_id: str,
    host: str = "127.0.0.1",
    port: int = 3306,
    database: str = "petclinic",
    username: str = "root",
) -> ProveDeadResult:
    """Test a verified quarantined value; only MySQL error 1045 proves rejection."""
    client = get_vault_client()
    candidate = _quarantined_secret(client, quarantine_id)
    _, tls = _mysql_tls_options()
    connection = None
    result: Literal["INCONCLUSIVE", "ACCEPTED", "REJECTED"] = "INCONCLUSIVE"
    proof: Literal[
        "INCONCLUSIVE_DB_UNREACHABLE", "ERROR_CREDENTIAL_STILL_ACTIVE", "CREDENTIAL_PROVEN_DEAD",
    ] = "INCONCLUSIVE_DB_UNREACHABLE"
    code: Optional[str] = "NOT_CONNECTED"
    rejected = False
    try:
        connection = mysql.connector.connect(
            host=host, port=port, user=username, password=candidate,
            database=database, connection_timeout=3, **tls,
        )
        if connection.is_connected():
            result = "ACCEPTED"
            proof = "ERROR_CREDENTIAL_STILL_ACTIVE"
            code = None
        else:
            logger.warning("MYSQL_PROBE_NOT_CONNECTED")
    except mysql.connector.Error as error:
        code = str(error.errno) if error.errno is not None else "UNKNOWN"
        if error.errno == 1045:
            rejected, result, proof = True, "REJECTED", "CREDENTIAL_PROVEN_DEAD"
        else:
            logger.warning("MYSQL_PROBE_INCONCLUSIVE")
    except Exception:
        _fail("MYSQL_PROBE_FAILED", "The credential probe failed unexpectedly; no revocation proof is available.")
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                _fail("MYSQL_PROBE_CLEANUP_FAILED", "The credential probe connection could not be closed.")
    return ProveDeadResult(
        tested_user=username, connection_rejected=rejected,
        result=result, error_code=code, proof_status=proof,
    )


def main():
    mcp.run()


if __name__ == "__main__":
    main()
