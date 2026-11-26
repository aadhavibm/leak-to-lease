"""Opt-in skill workflow verification over real MCP stdio and disposable services."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

from fastmcp import Client
from fastmcp.client.transports import StdioTransport
import hvac
import mysql.connector
import pytest


@pytest.mark.skipif(
    os.environ.get("LEASE_MCP_RUN_SKILL_INTEGRATION") != "1",
    reason="Requires explicitly approved disposable Vault and MySQL services",
)
def test_skill_workflow_over_stdio(tmp_path: Path, disposable_service_environment):
    required = ("VAULT_ADDR", "VAULT_TOKEN", "LEASE_MCP_TEST_DB_PASSWORD")
    if any(not os.environ.get(name) for name in required):
        pytest.fail("Disposable service configuration is missing", pytrace=False)

    vault_addr = os.environ["VAULT_ADDR"]
    token = os.environ["VAULT_TOKEN"]
    password = os.environ["LEASE_MCP_TEST_DB_PASSWORD"]
    vault = hvac.Client(url=vault_addr, token=token)
    source = tmp_path / "application.yml"
    source.write_text(f"password: {password}\n", encoding="utf-8")
    log = tmp_path / "mcp-server.log"
    gate = Path(__file__).resolve().parents[2] / "scripts/ci-vault-radar-gate.sh"
    connection_name = "mysql-skill-test"
    mount = "database-skill-test"
    roles = ["customers", "vets", "visits"]
    secrets = [password, token]

    def check_no_secrets(text: str):
        if any(value in text for value in secrets):
            pytest.fail("A test credential appeared in tool output or logs", pytrace=False)

    def scan() -> int:
        environment = dict(
            os.environ, HCP_PROJECT_ID="", HCP_CLIENT_ID="", HCP_CLIENT_SECRET="",
            HCP_ACCESS_TOKEN="", EXIT_ON_FAILURE="true",
        )
        result = subprocess.run(
            ["bash", str(gate), str(source), str(tmp_path / "scan-report.json")],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        check_no_secrets(result.stdout + result.stderr)
        return result.returncode

    with mysql.connector.connect(
        host="127.0.0.1", port=3307, user="root", password=password, database="petclinic"
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute("CREATE TABLE IF NOT EXISTS skill_health (id INT PRIMARY KEY, value INT)")
            cursor.execute("INSERT INTO skill_health VALUES (1, 0) ON DUPLICATE KEY UPDATE value=0")
        connection.commit()

    assert scan() == 1

    def exercise_database(username: str, credential: str):
        with mysql.connector.connect(
            host="127.0.0.1", port=3307, user=username, password=credential, database="petclinic"
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute("UPDATE skill_health SET value=value+1 WHERE id=1")
                cursor.execute("SELECT value FROM skill_health WHERE id=1")
                row = cursor.fetchone()
                assert row is not None and row[0] > 0
            connection.commit()

    async def workflow():
        transport = StdioTransport(
            command=sys.executable,
            args=["-m", "lease_mcp.server"],
            cwd=str(tmp_path),
            env={"VAULT_ADDR": vault_addr, "VAULT_TOKEN": token},
            log_file=log,
        )
        async with Client(transport, timeout=30) as client:
            tools = await client.list_tools()
            assert {tool.name for tool in tools} == {
                "quarantine_secret", "enable_db_engine", "configure_mysql_connection",
                "create_dynamic_role", "rotate_root", "lookup_lease", "prove_dead",
            }
            forbidden = {"password", "secret", "raw_secret", "admin_password", "credential"}
            for tool in tools:
                assert not forbidden.intersection(tool.input_schema.get("properties", {}))

            async def call(name: str, arguments: dict):
                result = await client.call_tool(name, arguments)
                assert not result.is_error
                assert isinstance(result.structured_content, dict)
                check_no_secrets(json.dumps(result.structured_content) + str(result.content))
                return result.structured_content

            quarantine = await call("quarantine_secret", {
                "source_path": str(source), "line_number": 1, "mount_path": "secret",
            })
            assert quarantine["status"] == "QUARANTINED_AND_SANITIZED"
            assert quarantine["fingerprint"].startswith("sha256:")
            assert source.read_text(encoding="utf-8") == "password: ${DB_PASSWORD_QUARANTINED}\n"
            assert scan() == 0
            reference = quarantine["quarantine_id"]

            engine = await call("enable_db_engine", {"mount_path": mount})
            assert engine["status"] in ("MOUNTED", "ALREADY_EXISTS")
            existing = await call("enable_db_engine", {"mount_path": mount})
            assert existing["status"] == "ALREADY_EXISTS"
            configured = await call("configure_mysql_connection", {
                "quarantine_id": reference,
                "name": connection_name,
                "connection_url": os.environ.get(
                    "LEASE_MCP_TEST_DB_CONNECTION_URL",
                    "{{username}}:{{password}}@tcp(127.0.0.1:3307)/petclinic",
                ),
                "allowed_roles": roles,
                "mount_path": mount,
            })
            assert configured["status"] == "CONFIGURED"
            credentials = []
            for role in roles:
                created = await call("create_dynamic_role", {
                    "role_name": role, "db_name": connection_name, "mount_path": mount,
                })
                assert created["status"] == "ROLE_ACTIVE"
                issued = vault.secrets.database.generate_credentials(name=role, mount_point=mount)
                data = issued["data"]
                secrets.append(data["password"])
                credentials.append(data)
                exercise_database(data["username"], data["password"])
                lease = await call("lookup_lease", {"lease_id": issued["lease_id"]})
                assert lease["status"] == "ACTIVE"
                assert lease["ttl_remaining_seconds"] > 0

            active = await call("prove_dead", {"quarantine_id": reference, "port": 3307})
            assert active["result"] == "ACCEPTED"
            assert active["connection_rejected"] is False
            assert active["proof_status"] == "ERROR_CREDENTIAL_STILL_ACTIVE"
            with socket.socket() as unused_endpoint:
                unused_endpoint.bind(("127.0.0.1", 0))
                port = unused_endpoint.getsockname()[1]
                inconclusive = await call("prove_dead", {"quarantine_id": reference, "port": port})
                assert inconclusive["result"] == "INCONCLUSIVE"
                assert inconclusive["connection_rejected"] is False
                assert inconclusive["proof_status"] == "INCONCLUSIVE_DB_UNREACHABLE"

            rotated = await call("rotate_root", {"db_name": connection_name, "mount_path": mount})
            assert rotated["status"] == "ROOT_ROTATED"
            dead = await call("prove_dead", {"quarantine_id": reference, "port": 3307})
            assert dead["connection_rejected"] is True
            assert dead["result"] == "REJECTED"
            assert dead["error_code"] == "1045"
            assert dead["proof_status"] == "CREDENTIAL_PROVEN_DEAD"
            for data in credentials:
                exercise_database(data["username"], data["password"])
            for role in roles:
                issued = vault.secrets.database.generate_credentials(name=role, mount_point=mount)
                data = issued["data"]
                secrets.append(data["password"])
                exercise_database(data["username"], data["password"])
            missing = await call("lookup_lease", {"lease_id": "nonexistent-skill-test-lease"})
            assert missing["status"] == "NOT_FOUND"
            invalid = await client.call_tool(
                "prove_dead", {"quarantine_id": "quar-nonexistent"}, raise_on_error=False
            )
            assert invalid.is_error
            check_no_secrets(str(invalid.content))
            assert scan() == 0

    asyncio.run(workflow())
    check_no_secrets(log.read_text(encoding="utf-8"))
