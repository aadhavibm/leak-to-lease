"""Integration tests for Vault database engine, dynamic roles, root rotation, and prove_dead.

Runs against local Vault dev server and test MySQL on port 3307.
Never touches MySQL on port 3306 or real files in targets/.
Requires a caller-provisioned, labelled disposable database; never recreates it.
Skips only when neither the integration opt-in nor test password is configured.
"""

from __future__ import annotations

import os
import json
from pathlib import Path
import pytest

from lease_mcp.server import (
    configure_mysql_connection,
    create_dynamic_role,
    enable_db_engine,
    get_vault_client,
    lookup_lease,
    prove_dead,
    quarantine_secret,
    rotate_root,
)

@pytest.fixture(autouse=True)
def setup_test_environment(request):
    """Skip this surface before requesting the shared live-service fixture."""
    test_db_password = os.environ.get("LEASE_MCP_TEST_DB_PASSWORD", "")
    opt_in = os.environ.get("LEASE_MCP_RUN_DB_INTEGRATION", "0")
    if not test_db_password and opt_in in {"", "0"}:
        pytest.skip("Disposable database integration is not opted in.")
    if opt_in != "1" or not test_db_password:
        pytest.fail("Integration opt-in requires LEASE_MCP_RUN_DB_INTEGRATION=1 and a test password.", pytrace=False)
    request.getfixturevalue("disposable_service_environment")


def test_full_remediation_lifecycle_on_test_database(tmp_path: Path):
    """End-to-end integration test of quarantine -> mount -> config -> roles -> lease -> root rotation -> prove_dead.

    Uses isolated Vault mount 'database-test' and MySQL port 3307.
    """
    test_db_password = os.environ["LEASE_MCP_TEST_DB_PASSWORD"]
    client = get_vault_client()

    # 1. Create a temporary copy of config file with dynamic password from env var (never touch targets/)
    sample_config = tmp_path / "application.yml"
    sample_config.write_text(
        "# COMMON APPLICATION PROPERTIES\n"
        "spring:\n"
        "  config:\n"
        "    activate:\n"
        "      on-profile: mysql\n"
        "  datasource:\n"
        "    url: jdbc:mysql://127.0.0.1:3307/petclinic?allowPublicKeyRetrieval=true&useSSL=false\n"
        "    username: root\n"
        f"    password: {json.dumps(test_db_password)}\n",
        encoding="utf-8",
    )

    # 2. Quarantine secret from line 9
    quar_res = quarantine_secret(
        source_path=str(sample_config),
        line_number=9,
        mount_path="secret",
    )
    assert quar_res.quarantine_id.startswith("quar-")
    assert quar_res.fingerprint.startswith("sha256:")
    assert quar_res.status == "QUARANTINED_AND_SANITIZED"
    assert "${DB_PASSWORD_QUARANTINED}" in sample_config.read_text(encoding="utf-8")

    # 3. Mount separate Vault database engine for test: 'database-test'
    test_mount = "database-test"
    engine_res = enable_db_engine(mount_path=test_mount)
    assert engine_res.mount_path == test_mount
    assert engine_res.status in ("MOUNTED", "ALREADY_EXISTS")

    # 4. Configure MySQL connection on 127.0.0.1:3307 with root_rotation_statements
    conn_name = "mysql-petclinic-test"
    conn_res = configure_mysql_connection(
        quarantine_id=quar_res.quarantine_id,
        name=conn_name,
        connection_url=os.environ.get(
            "LEASE_MCP_TEST_DB_CONNECTION_URL",
            "{{username}}:{{password}}@tcp(127.0.0.1:3307)/petclinic",
        ),
        admin_username="root",
        allowed_roles=["customers", "vets", "visits"],
        mount_path=test_mount,
    )
    assert conn_res.connection_name == conn_name
    assert conn_res.plugin_name == "mysql-database-plugin"
    assert conn_res.status == "CONFIGURED"

    # Verify Vault database configuration has root rotation statements for '%' and 'localhost'
    conn_read = client.secrets.database.read_connection(name=conn_name, mount_point=test_mount)
    rotation_stmts = (
        conn_read["data"].get("root_credentials_rotate_statements")
        or conn_read["data"].get("root_rotation_statements")
        or []
    )
    assert any("'root'@'%'" in stmt or "'{{username}}'@'%'" in stmt for stmt in rotation_stmts)
    assert any("'root'@'localhost'" in stmt or "'{{username}}'@'localhost'" in stmt for stmt in rotation_stmts)

    # 5. Create dynamic roles: customers, vets, visits
    roles = ["customers", "vets", "visits"]
    for role_name in roles:
        role_res = create_dynamic_role(
            role_name=role_name,
            db_name=conn_name,
            default_ttl="1h",
            max_ttl="24h",
            mount_path=test_mount,
        )
        assert role_res.role_name == role_name
        assert role_res.db_name == conn_name
        assert role_res.default_ttl == "1h"
        assert role_res.max_ttl == "24h"
        assert role_res.status == "ROLE_ACTIVE"

        # Verify role statements in Vault
        role_read = client.secrets.database.read_role(name=role_name, mount_point=test_mount)
        assert "petclinic.*" in role_read["data"]["creation_statements"][1]
        assert "DROP USER" in role_read["data"]["revocation_statements"][0]

    # 6. Generate a dynamic lease and verify lookup_lease
    gen_creds = client.secrets.database.generate_credentials(name="customers", mount_point=test_mount)
    lease_id = gen_creds["lease_id"]
    assert lease_id.startswith(f"{test_mount}/creds/customers/")

    lease_res = lookup_lease(lease_id=lease_id)
    assert lease_res.lease_id == lease_id
    assert lease_res.ttl_remaining_seconds > 0
    assert lease_res.renewable is True
    assert lease_res.status == "ACTIVE"

    before = prove_dead(quarantine_id=quar_res.quarantine_id, port=3307)
    assert before.result == "ACCEPTED"
    print("Before rotation: ACCEPTED")

    # 7. Rotate root password via Vault
    rot_res = rotate_root(db_name=conn_name, mount_path=test_mount)
    assert rot_res.db_name == conn_name
    assert rot_res.rotated is True
    assert rot_res.status == "ROOT_ROTATED"

    # 8. Prove dead: old quarantined password must now be rejected by MySQL on port 3307
    prove_res = prove_dead(
        quarantine_id=quar_res.quarantine_id,
        host="127.0.0.1",
        port=3307,
        database="petclinic",
        username="root",
    )
    assert prove_res.tested_user == "root"
    assert prove_res.connection_rejected is True
    assert prove_res.result == "REJECTED"
    assert prove_res.error_code == "1045"
    assert prove_res.proof_status == "CREDENTIAL_PROVEN_DEAD"
    print("After rotation: REJECTED (MySQL error 1045)")
