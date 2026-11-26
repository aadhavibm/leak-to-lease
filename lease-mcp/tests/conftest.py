"""Opt-in verification of caller-owned disposable integration services."""

from __future__ import annotations

import json
import os
import socket
import subprocess
from urllib.parse import urlparse

import pytest


def is_mysql_3307_available() -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(1.0)
            connection.connect(("127.0.0.1", 3307))
        return True
    except OSError:
        return False


def is_vault_available() -> bool:
    try:
        import hvac

        return hvac.Client(
            url=os.environ["VAULT_ADDR"], token=os.environ["VAULT_TOKEN"], timeout=2,
            verify=os.environ.get("VAULT_CACERT") or True,
        ).is_authenticated()
    except Exception:
        return False


def verify_disposable_test_container() -> None:
    """Verify that local port 3307 belongs to the approved task-owned container."""
    required = (
        "LEASE_MCP_TEST_MYSQL_CONTAINER", "LEASE_MCP_DISPOSABLE_DOCKER_CONTEXT",
        "LEASE_MCP_TEST_OWNER", "VAULT_ADDR", "VAULT_TOKEN",
    )
    if any(not os.environ.get(name) for name in required):
        raise RuntimeError("Disposable integration environment configuration is missing.")
    context = os.environ["LEASE_MCP_DISPOSABLE_DOCKER_CONTEXT"]
    if context in {"default", "desktop-linux"}:
        raise RuntimeError("Integration requires a dedicated disposable Docker context.")
    if urlparse(os.environ["VAULT_ADDR"]).hostname not in {"127.0.0.1", "localhost"}:
        raise RuntimeError("Integration requires explicitly configured local disposable Vault.")

    def inspect(*arguments):
        try:
            result = subprocess.run(
                ["docker", *arguments], capture_output=True, text=True, check=False,
            )
        except OSError:
            raise RuntimeError("Docker is unavailable for disposable resource verification.") from None
        if result.returncode:
            raise RuntimeError("Disposable Docker resource verification failed.")
        return result.stdout

    if inspect("context", "show").strip() != context:
        raise RuntimeError("Active Docker context does not match the disposable context.")
    try:
        contexts = json.loads(inspect("context", "inspect", context))
        if not contexts[0]["Endpoints"]["docker"]["Host"].startswith("unix://"):
            raise RuntimeError("Integration Docker context must use the local daemon.")
        containers = json.loads(inspect("--context", context, "inspect", os.environ["LEASE_MCP_TEST_MYSQL_CONTAINER"]))
        if len(containers) != 1:
            raise RuntimeError("Disposable MySQL container identity is invalid.")
        info = containers[0]
        labels = info.get("Config", {}).get("Labels") or {}
        if labels.get("io.leak-to-lease.disposable") != "true" or labels.get("io.leak-to-lease.owner") != os.environ["LEASE_MCP_TEST_OWNER"]:
            raise RuntimeError("MySQL container is not labelled as this task's owned disposable resource.")
        if not info.get("State", {}).get("Running"):
            raise RuntimeError("Disposable MySQL container is not running.")
        ports = info.get("NetworkSettings", {}).get("Ports") or {}
        bindings = ports.get("3306/tcp") or []
        if not any(binding.get("HostPort") == "3307" and binding.get("HostIp") in {"127.0.0.1", "0.0.0.0"} for binding in bindings):
            raise RuntimeError("Disposable MySQL container must publish local test port 3307.")
        if any(binding.get("HostPort") == "3306" for entries in ports.values() for binding in (entries or [])):
            raise RuntimeError("Integration refuses a container publishing shared MySQL port 3306.")
    except (ValueError, KeyError, IndexError, TypeError, AttributeError):
        raise RuntimeError("Docker returned invalid disposable resource metadata.") from None


def verify_test_mysql_instance(password: str) -> None:
    """Fail on login mismatch; never remove or recreate a caller's database."""
    try:
        import mysql.connector

        connection = mysql.connector.connect(
            host="127.0.0.1", port=3307, user="root", password=password,
            database="petclinic", connection_timeout=2,
        )
        connection.close()
    except Exception:
        raise RuntimeError("Disposable test MySQL login failed; provision a fresh database with the configured credential.") from None


@pytest.fixture
def disposable_service_environment():
    """Validate ownership and initial logins only after either explicit opt-in."""
    opt_ins = [
        os.environ.get("LEASE_MCP_RUN_DB_INTEGRATION", "0"),
        os.environ.get("LEASE_MCP_RUN_SKILL_INTEGRATION", "0"),
        os.environ.get("LEASE_MCP_RUN_ROLLOVER_INTEGRATION", "0"),
    ]
    password = os.environ.get("LEASE_MCP_TEST_DB_PASSWORD", "")
    if not password and all(value in {"", "0"} for value in opt_ins):
        pytest.skip("Disposable service integration is not opted in.")
    if any(value not in {"", "0", "1"} for value in opt_ins) or "1" not in opt_ins or not password:
        pytest.fail("Disposable integration requires an explicit integration opt-in and test password.", pytrace=False)
    try:
        verify_disposable_test_container()
        if not is_vault_available() or not is_mysql_3307_available():
            raise RuntimeError("Configured disposable Vault or test MySQL is unreachable.")
        verify_test_mysql_instance(password)
    except RuntimeError as error:
        pytest.fail(str(error), pytrace=False)
    yield
