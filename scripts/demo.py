#!/usr/bin/env python3
"""Replay remediation using owned disposable services, never tracked source edits."""

from __future__ import annotations

import argparse
from datetime import date
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from urllib.error import URLError
from urllib.request import Request, urlopen
import uuid

import hvac
import mysql.connector

from lease_mcp.security import prepare_secret_line
from lease_mcp.server import (
    configure_mysql_connection, create_dynamic_role, enable_db_engine,
    get_vault_client, lookup_lease, prove_dead, quarantine_secret, rotate_root,
)

ROOT = Path(__file__).resolve().parents[1]
PETCLINIC = ROOT / "targets/spring-petclinic-microservices"
SERVICES = ("config-server", "discovery-server", "customers-service", "vets-service", "visits-service", "api-gateway")
PORTS = (18888, 18761, 18081, 18083, 18082, 18080)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def wait_for_json(url: str, processes: list[subprocess.Popen], predicate=lambda value: bool(value)):
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        require(all(p.poll() is None for p in processes), "A PetClinic process exited; see private demo logs.")
        try:
            with urlopen(Request(url, headers={"Accept": "application/json"}), timeout=3) as response:
                value = json.load(response)
            if predicate(value):
                return value
        except (URLError, TimeoutError, json.JSONDecodeError):
            pass
        time.sleep(2)
    raise RuntimeError(f"Timed out waiting for {url}; see private demo logs.")


def wait_for_service(service: str, port: int, processes: list[subprocess.Popen]):
    base = f"http://127.0.0.1:{port}"
    if service == "config-server":
        return wait_for_json(base + "/customers-service/mysql", processes, lambda x: bool(x.get("propertySources")))
    if service == "discovery-server":
        return wait_for_json(base + "/eureka/apps", processes, lambda x: "applications" in x)
    return wait_for_json(base + "/actuator/health", processes, lambda x: x.get("status") == "UP")


def application_environment(environment: dict[str, str], token: str | None) -> dict[str, str]:
    inherited = {
        "PATH", "JAVA_HOME", "HOME", "USERPROFILE", "TMPDIR", "TMP", "TEMP",
        "LANG", "LC_ALL", "TZ", "SystemRoot", "SYSTEMROOT", "WINDIR", "VAULT_ADDR",
    }
    result = {key: value for key, value in environment.items() if key in inherited}
    result.update(
        CONFIG_SERVER_URL="http://127.0.0.1:18888",
        EUREKA_CLIENT_SERVICEURL_DEFAULTZONE="http://127.0.0.1:18761/eureka/",
        EUREKA_INSTANCE_PREFER_IP_ADDRESS="false", EUREKA_INSTANCE_HOSTNAME="127.0.0.1",
        SPRING_DATASOURCE_URL="jdbc:mysql://127.0.0.1:3307/petclinic?allowPublicKeyRetrieval=true&useSSL=false",
    )
    if token is not None:
        result["SPRING_CLOUD_VAULT_TOKEN"] = token
    return result


def check_application(processes: list[subprocess.Popen]) -> None:
    wait_for_json("http://127.0.0.1:18080/api/customer/owners", processes, lambda x: isinstance(x, list) and len(x) > 0)
    wait_for_json("http://127.0.0.1:18080/api/vet/vets", processes, lambda x: isinstance(x, list) and len(x) > 0)
    visits_url = "http://127.0.0.1:18080/api/visit/owners/1/pets/1/visits"
    wait_for_json(visits_url, processes, lambda x: isinstance(x, list))
    payload = json.dumps({"date": date.today().isoformat(), "description": "Leak to Lease replay verification"}).encode()
    request = Request(visits_url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(request, timeout=5) as response:
        require(response.status == 201, "Visit creation did not return HTTP 201.")
    wait_for_json("http://127.0.0.1:18080/api/gateway/owners/1", processes,
                  lambda x: x.get("pets") and not x.get("visitsUnavailable", False) and any(p.get("visits") for p in x["pets"]))
    print("PetClinic gateway: customers, vets and visits verified.", flush=True)


def run_demo(test_file: str | None = None) -> None:
    context = os.environ.get("LEASE_MCP_DISPOSABLE_DOCKER_CONTEXT", "")
    require(bool(context) and context not in {"default", "desktop-linux"}, "Set a dedicated LEASE_MCP_DISPOSABLE_DOCKER_CONTEXT.")
    require(os.environ.get("DOCKER_CONTEXT") == context, "DOCKER_CONTEXT must match the dedicated disposable context.")
    checked_ports = (3307, 18200) if test_file else (3307, 18200, *PORTS)
    for port in checked_ports:
        with socket.socket() as connection:
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            connection.bind(("127.0.0.1", port))
    for service in (() if test_file else SERVICES):
        require(len(list((PETCLINIC / f"spring-petclinic-{service}/target").glob("*.jar"))) == 1,
                "Build the PetClinic jars with ./mvnw -B package -DskipTests first.")

    workspace = Path(tempfile.mkdtemp(prefix="ltl-demo-"))
    owner = "ltl-" + uuid.uuid4().hex
    env = dict(os.environ, LEASE_MCP_TEST_OWNER=owner, VAULT_TOKEN=secrets.token_urlsafe(32),
               VAULT_ADDR="http://127.0.0.1:18200", LEASE_MCP_PYTHON=sys.executable)
    template = ROOT / "targets/spring-petclinic-microservices-config"
    config = template / "application.yml"
    line = next(i for i, text in enumerate(config.read_text().splitlines(), 1) if text.lstrip().startswith("password:"))
    env["MYSQL_ROOT_PASSWORD"] = prepare_secret_line(config, line).raw_secret
    compose_command = ["docker-compose"] if shutil.which("docker-compose") else ["docker", "--context", context, "compose"]
    compose = [*compose_command, "--env-file", "/dev/null",
               "-f", str(ROOT / "compose.demo.yml"), "-p", owner]
    processes: list[subprocess.Popen] = []
    started = False
    succeeded = False

    def command(arguments: list[str], name: str) -> str:
        result = subprocess.run(arguments, env=env, cwd=ROOT, capture_output=True, text=True)
        if result.returncode:
            log = workspace / f"{name}.log"
            log.write_text(result.stdout + result.stderr)
            log.chmod(0o600)
            raise RuntimeError(f"{name} failed (exit {result.returncode}); see private demo logs.")
        return result.stdout.strip()

    try:
        contexts = json.loads(command(["docker", "context", "inspect", context], "context"))
        require(contexts[0]["Endpoints"]["docker"]["Host"].startswith("unix://"), "Use a local disposable Docker daemon.")
        command([*compose, "config", "--quiet"], "compose-config")
        started = True
        command([*compose, "up", "-d", "--wait", "--wait-timeout", "240"], "compose-up")
        os.environ.update(VAULT_ADDR=env["VAULT_ADDR"], VAULT_TOKEN=env["VAULT_TOKEN"])
        if test_file:
            test_env = {
                "LEASE_MCP_RUN_DB_INTEGRATION": "1" if test_file == "test_integration.py" else "0",
                "LEASE_MCP_RUN_SKILL_INTEGRATION": "1" if test_file == "test_skill_mcp.py" else "0",
                "LEASE_MCP_TEST_DB_PASSWORD": env["MYSQL_ROOT_PASSWORD"],
                "LEASE_MCP_TEST_MYSQL_CONTAINER": command([*compose, "ps", "-q", "mysql"], "mysql-id"),
                "LEASE_MCP_TEST_DB_CONNECTION_URL": "{{username}}:{{password}}@tcp(mysql:3306)/petclinic",
            }
            env.update(test_env)
            output = command(
                [sys.executable, "-m", "pytest", "-q", "-s", str(ROOT / "lease-mcp/tests" / test_file)],
                "live-tests",
            )
            for text in output.splitlines():
                if re.match(r"^(?:Before rotation:|After rotation:|\d+ passed)", text):
                    print(text, flush=True)
        else:
            private_config = workspace / "config"
            shutil.copytree(template, private_config)
            source = private_config / "application.yml"
            quarantined = quarantine_secret(str(source), line)
            readme = workspace / "README.md"
            readme.write_text((PETCLINIC / "README.md").read_text())
            readme_line = next(i for i, text in enumerate(readme.read_text().splitlines(), 1)
                               if "docker run -e MYSQL_ROOT_PASSWORD=" in text)
            second = quarantine_secret(str(readme), readme_line)
            require(second.fingerprint == quarantined.fingerprint, "Demo source fingerprints differ.")
            before = prove_dead(quarantined.quarantine_id, port=3307)
            require(before.result == "ACCEPTED", "Initial credential was not ACCEPTED.")
            print("Before rotation: ACCEPTED", flush=True)
            enable_db_engine()
            configure_mysql_connection(quarantined.quarantine_id,
                                       connection_url="{{username}}:{{password}}@tcp(mysql:3306)/petclinic")
            client = get_vault_client()
            connection = mysql.connector.connect(host="127.0.0.1", port=3307, user="root",
                                                 password=env["MYSQL_ROOT_PASSWORD"], database="petclinic")
            try:
                with connection.cursor() as cursor:
                    for service in ("customers", "vets", "visits"):
                        for name in ("schema", "data"):
                            sql = PETCLINIC / f"spring-petclinic-{service}-service/src/main/resources/db/mysql/{name}.sql"
                            cursor.execute(sql.read_text())
                            while cursor.nextset():
                                pass
                connection.commit()
            finally:
                connection.close()
            tokens = {}
            for role in ("customers", "vets", "visits"):
                create_dynamic_role(role)
                policy = f"demo-{role}"
                client.sys.create_or_update_policy(policy, f'path "database/creds/{role}" {{ capabilities = ["read"] }}')
                tokens[f"{role}-service"] = client.auth.token.create(policies=[policy], ttl="1h")["auth"]["client_token"]
            source.write_text("".join(text for text in source.read_text().splitlines(keepends=True)
                                      if not text.lstrip().startswith(("username:", "password:"))))
            for service, port in zip(SERVICES, PORTS):
                jar = next((PETCLINIC / f"spring-petclinic-{service}/target").glob("*.jar"))
                service_env = application_environment(env, tokens.get(service))
                profiles = "native" if service == "config-server" else "mysql"
                with (workspace / f"{service}.log").open("w") as log:
                    process = subprocess.Popen(
                        ["java", "-Xmx384m", "-jar", str(jar), f"--server.port={port}", "--server.address=127.0.0.1",
                         f"--spring.profiles.active={profiles}", "--management.tracing.enabled=false",
                         f"--eureka.client.serviceUrl.defaultZone={service_env['EUREKA_CLIENT_SERVICEURL_DEFAULTZONE']}",
                         f"--spring.cloud.config.server.native.search-locations={private_config.as_uri()}/"],
                        env=service_env, stdout=log, stderr=subprocess.STDOUT,
                    )
                processes.append(process)
                wait_for_service(service, port, processes)
                print(f"Ready: {service}", flush=True)
            check_application(processes)
            leases = client.sys.list_leases(prefix="database/creds")["data"]["keys"]
            require(set(key.rstrip("/") for key in leases) == {"customers", "vets", "visits"}, "Expected all service leases.")
            for role in ("customers", "vets", "visits"):
                ids = client.sys.list_leases(prefix=f"database/creds/{role}")["data"]["keys"]
                require(len(ids) == 1, "Expected one lease per service.")
                lease = lookup_lease(f"database/creds/{role}/{ids[0]}")
                require(lease.status == "ACTIVE" and lease.ttl_remaining_seconds > 0, "Service lease is not active.")
            rotate_root()
            for reference in (quarantined, second):
                after = prove_dead(reference.quarantine_id, port=3307)
                require(after.result == "REJECTED" and after.error_code == "1045", "Old credential was not proven dead.")
            print("After rotation: REJECTED (MySQL error 1045)", flush=True)
            check_application(processes)
        succeeded = True
    finally:
        primary_error = sys.exc_info()[1]
        cleanup_errors = []
        for process in reversed(processes):
            try:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=20)
            except (OSError, subprocess.TimeoutExpired) as error:
                cleanup_errors.append(error)
                print(f"Java cleanup failed ({type(error).__name__}).", file=sys.stderr)
        if started:
            try:
                command([*compose, "down", "--volumes"], "compose-down")
            except (RuntimeError, OSError) as error:
                cleanup_errors.append(error)
                print(f"Compose cleanup failed ({type(error).__name__}); inspect private logs.", file=sys.stderr)
        if succeeded and not cleanup_errors:
            try:
                shutil.rmtree(workspace)
            except OSError as error:
                cleanup_errors.append(error)
                print(f"Diagnostic cleanup failed ({type(error).__name__}).", file=sys.stderr)
        if not succeeded or cleanup_errors:
            print(f"Private diagnostic logs retained at {workspace}", file=sys.stderr)
        if cleanup_errors and primary_error is None:
            raise RuntimeError("Owned-resource cleanup failed; private diagnostic logs were retained.") from cleanup_errors[0]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-disposable-changes", action="store_true",
                        help="Approve fresh demo databases, role creation, root rotation and owned-resource cleanup.")
    parser.add_argument("--integration-tests", action="store_true",
                        help="Run each live Python test surface against a fresh database instead of starting PetClinic.")
    args = parser.parse_args()
    if not args.allow_disposable_changes:
        parser.error("--allow-disposable-changes is required; existing databases must never be used.")
    os.umask(0o077)
    try:
        if args.integration_tests:
            for test_file in ("test_integration.py", "test_skill_mcp.py"):
                run_demo(test_file)
        else:
            run_demo()
    except RuntimeError as error:
        print(f"Demo failed: {error}", file=sys.stderr)
        raise SystemExit(1) from None
    except (OSError, ValueError, mysql.connector.Error, hvac.exceptions.VaultError) as error:
        print(f"Demo failed ({type(error).__name__}); inspect the private diagnostic logs.", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
