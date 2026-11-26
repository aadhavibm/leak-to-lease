"""Opt-in real AppRole/TLS/Vault-max-TTL/JDBC-pool acceptance test."""

import json
import os
from pathlib import Path
import signal
import subprocess
import time

import hvac
import mysql.connector
import pytest
import requests

from lease_mcp.server import (
    configure_mysql_connection, create_dynamic_role, enable_db_engine,
    prove_dead, quarantine_secret, rotate_root,
)


@pytest.mark.skipif(
    os.environ.get("LEASE_MCP_RUN_ROLLOVER_INTEGRATION") != "1",
    reason="Requires explicitly owned TLS Vault/MySQL and built application JARs",
)
def test_real_approle_max_ttl_rollover_and_outage_recovery(tmp_path, disposable_service_environment):
    root = Path(__file__).resolve().parents[2]
    application = root / "targets/spring-petclinic-microservices"
    address = os.environ["VAULT_ADDR"]
    ca = os.environ.get("VAULT_CACERT")
    truststore = os.environ.get("PETCLINIC_TEST_TRUSTSTORE")
    vault_pid = int(os.environ.get("PETCLINIC_TEST_VAULT_PID", "0"))
    if not address.startswith("https://") or not ca or not truststore or vault_pid <= 1:
        pytest.fail("Rollover acceptance requires caller-owned TLS resources and a specific Vault PID.", pytrace=False)
    owner_uid = subprocess.run(
        ["ps", "-p", str(vault_pid), "-o", "uid=", "-o", "comm="],
        capture_output=True, text=True, check=True,
    ).stdout.strip().split(None, 1)
    if len(owner_uid) != 2 or int(owner_uid[0]) != os.getuid() or Path(owner_uid[1]).name != "vault":
        pytest.fail("Refusing to pause a process that is not the current user's approved Vault.", pytrace=False)

    client = hvac.Client(url=address, token=os.environ["VAULT_TOKEN"], verify=ca, timeout=3)
    password = os.environ["LEASE_MCP_TEST_DB_PASSWORD"]
    protected = [password, os.environ["VAULT_TOKEN"]]
    roles = ("customers", "vets", "visits")
    ports = {"customers": 18401, "vets": 18402, "visits": 18403}
    management_ports = {"customers": 19401, "vets": 19402, "visits": 19403}
    processes = {}
    logs = {}
    streams = []
    paused = False
    counts = {role: 0 for role in roles}
    observed_users = {role: set() for role in roles}
    failures = []

    def wait_healthy(role, timeout=60):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if processes[role].poll() is not None:
                pytest.fail(f"{role} exited during startup; inspect its private test log.", pytrace=False)
            try:
                if requests.get(f"http://127.0.0.1:{management_ports[role]}/actuator/health", timeout=3).status_code == 200:
                    return
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                pass
            time.sleep(0.5)
        pytest.fail(f"{role} did not become healthy.", pytrace=False)

    def exercise(role):
        base = f"http://127.0.0.1:{ports[role]}"
        if role == "customers":
            response = requests.post(base + "/owners", json={
                "firstName": "Rollover", "lastName": "Acceptance", "address": "1 Test Street",
                "city": "Test City", "telephone": "1234567890",
            }, timeout=5)
            expected = 201
        elif role == "vets":
            response = requests.get(base + "/vets", timeout=5)
            expected = 200
        else:
            response = requests.post(base + "/owners/1/pets/1/visits", json={
                "date": "2026-01-01", "description": "Rollover acceptance",
            }, timeout=5)
            expected = 201
        return response.status_code == expected

    def observe_connections():
        with mysql.connector.connect(
            host="127.0.0.1", port=3307, user="root", password=password,
            database="petclinic", connection_timeout=2,
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT USER FROM information_schema.PROCESSLIST WHERE USER LIKE 'v-%'")
                for (username,) in cursor:
                    for role in roles:
                        if role in username:
                            observed_users[role].add(username)

    try:
        seed_environment = dict(os.environ)
        seed_environment.update({
            "MYSQL_CONTAINER_NAME": os.environ["LEASE_MCP_TEST_MYSQL_CONTAINER"],
            "MYSQL_ROOT_PASSWORD": password,
            "LEASE_MCP_ALLOW_DESTRUCTIVE_RESET": "1",
        })
        seed = subprocess.run(
            ["bash", str(root / "scripts/reset-demo.sh"), "--seed-only"],
            cwd=root, env=seed_environment, capture_output=True, text=True, check=False,
        )
        assert seed.returncode == 0, "Owned disposable schema seed failed."
        source = tmp_path / "application.yml"
        source.write_text("password: " + json.dumps(password) + "\n")
        quarantine = quarantine_secret(str(source), 1)
        mount = "database-rollover"
        connection_name = "mysql-rollover"
        enable_db_engine(mount)
        configure_mysql_connection(
            quarantine.quarantine_id, name=connection_name,
            connection_url="{{username}}:{{password}}@tcp(127.0.0.1:3307)/petclinic",
            allowed_roles=list(roles), mount_path=mount,
        )
        for role in roles:
            create_dynamic_role(
                role, db_name=connection_name, default_ttl="20s", max_ttl="45s", mount_path=mount,
            )
        client.sys.enable_auth_method("approle", path="approle-rollover")
        for role in roles:
            client.sys.create_or_update_policy(
                f"rollover-{role}",
                f'path "{mount}/creds/{role}" {{ capabilities = ["read"] }}\n'
                'path "sys/leases/renew" {\n capabilities = ["update"]\n'
                f' allowed_parameters = {{ "lease_id" = ["{mount}/creds/{role}/*"], "increment" = [] }}\n'
                '}\npath "sys/leases/revoke" {\n capabilities = ["update"]\n'
                f' allowed_parameters = {{ "lease_id" = ["{mount}/creds/{role}/*"] }}\n'
                '}',
            )
            client.auth.approle.create_or_update_approle(
                role_name=role, mount_point="approle-rollover", token_policies=[f"rollover-{role}"],
                token_ttl="30s", token_max_ttl="90s", secret_id_ttl="10m",
            )
            role_id = client.auth.approle.read_role_id(role, mount_point="approle-rollover")["data"]["role_id"]
            secret_id = client.auth.approle.generate_secret_id(role, mount_point="approle-rollover")["data"]["secret_id"]
            protected.extend((role_id, secret_id))
            module = f"spring-petclinic-{role}-service"
            jar = application / module / "target" / f"{module}-4.0.1.jar"
            if not jar.is_file():
                pytest.fail("Build all application JARs before opting into rollover acceptance.", pytrace=False)
            environment = dict(os.environ)
            for name in list(environment):
                if any(marker in name for marker in ("TOKEN", "PASSWORD", "SECRET", "API_KEY", "HCP_", "CLIENT_ID", "VAULT_")):
                    environment.pop(name, None)
            environment.update({
                "SPRING_PROFILES_ACTIVE": "mysql,production",
                "SPRING_CLOUD_CONFIG_ENABLED": "false",
                "SPRING_CLOUD_CONFIG_IMPORT_CHECK_ENABLED": "false",
                "SPRING_CONFIG_IMPORT": "",
                "SPRING_CLOUD_VAULT_URI": address,
                "SPRING_CLOUD_VAULT_AUTHENTICATION": "APPROLE",
                "SPRING_CLOUD_VAULT_APP_ROLE_ROLE_ID": role_id,
                "SPRING_CLOUD_VAULT_APP_ROLE_SECRET_ID": secret_id,
                "SPRING_CLOUD_VAULT_APP_ROLE_APP_ROLE_PATH": "approle-rollover",
                "SPRING_CLOUD_VAULT_SSL_TRUST_STORE": "file:" + truststore,
                "SPRING_CLOUD_VAULT_SSL_TRUST_STORE_PASSWORD": "changeit",
                "SPRING_CLOUD_VAULT_SSL_TRUST_STORE_TYPE": "PKCS12",
                "SPRING_CLOUD_VAULT_DATABASE_BACKEND": mount,
                "SPRING_CLOUD_VAULT_DATABASE_ROLE": role,
                "SPRING_CLOUD_VAULT_CONFIG_LIFECYCLE_MIN_RENEWAL": "1s",
                "SPRING_CLOUD_VAULT_CONFIG_LIFECYCLE_EXPIRY_THRESHOLD": "5s",
                "SPRING_CLOUD_VAULT_CONNECTION_TIMEOUT": "2000",
                "SPRING_CLOUD_VAULT_READ_TIMEOUT": "2000",
                "SPRING_CLOUD_VAULT_FAIL_FAST": "true",
                "SPRING_DATASOURCE_URL": (
                    "jdbc:mysql://127.0.0.1:3307/petclinic?sslMode=VERIFY_IDENTITY"
                    "&trustCertificateKeyStoreUrl=file:" + truststore
                    + "&trustCertificateKeyStorePassword=changeit&trustCertificateKeyStoreType=PKCS12"
                ),
                "SPRING_DATASOURCE_HIKARI_MINIMUM_IDLE": "1",
                "SPRING_DATASOURCE_HIKARI_MAXIMUM_POOL_SIZE": "3",
                "SPRING_DATASOURCE_HIKARI_CONNECTION_TIMEOUT": "2000",
                "SPRING_JPA_HIBERNATE_DDL_AUTO": "none",
                "SPRING_SQL_INIT_MODE": "never",
                "SPRING_CACHE_TYPE": "none",
                "EUREKA_CLIENT_ENABLED": "false",
                "MANAGEMENT_SERVER_PORT": str(management_ports[role]),
                "MANAGEMENT_SERVER_ADDRESS": "127.0.0.1",
                "MANAGEMENT_TRACING_ENABLED": "false",
                "LOGGING_LEVEL_ROOT": "WARN",
            })
            logfile = tmp_path / f"{role}.log"
            descriptor = os.open(logfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            stream = os.fdopen(descriptor, "w")
            streams.append(stream)
            logs[role] = logfile
            processes[role] = subprocess.Popen(
                ["java", "-Xmx192m", "-jar", str(jar), f"--server.port={ports[role]}", "--server.address=127.0.0.1"],
                env=environment, cwd=application, stdout=stream, stderr=subprocess.STDOUT,
            )
            wait_healthy(role)
            assert requests.get(f"http://127.0.0.1:{management_ports[role]}/actuator/env", timeout=3).status_code == 404
            assert requests.get(f"http://127.0.0.1:{management_ports[role]}/actuator/heapdump", timeout=3).status_code == 404

        initial_pids = {role: process.pid for role, process in processes.items()}
        deadline = time.monotonic() + 105
        while time.monotonic() < deadline:
            for role in roles:
                if exercise(role):
                    counts[role] += 1
                else:
                    failures.append(role)
            observe_connections()
            time.sleep(0.5)
        assert not failures, "Application work failed during normal max-TTL rollover."
        assert all(len(users) >= 2 for users in observed_users.values()), "Each live JDBC pool must actually change database users."

        os.kill(vault_pid, signal.SIGSTOP)
        paused = True
        time.sleep(25)
        for role in roles:
            response = requests.get(f"http://127.0.0.1:{management_ports[role]}/actuator/health/readiness", timeout=5)
            assert response.status_code == 503, "Expired credentials must not report readiness."
            assert not exercise(role), "Application must not continue using expired credentials."
        os.kill(vault_pid, signal.SIGCONT)
        paused = False
        for role in roles:
            wait_healthy(role, timeout=60)
            assert exercise(role), "Application must recover without a restart after Vault returns."
            assert processes[role].pid == initial_pids[role]
        assert prove_dead(quarantine.quarantine_id, port=3307).result == "ACCEPTED"
        rotate_root(db_name=connection_name, mount_path=mount)
        proof = prove_dead(quarantine.quarantine_id, port=3307)
        assert proof.result == "REJECTED" and proof.error_code == "1045"
        for role in roles:
            assert exercise(role)
        for path in logs.values():
            contents = path.read_text()
            assert not any(value in contents for value in protected), "A credential appeared in application logs."
        result = {
            "production_tls_and_approle": "passed",
            "max_ttl_seconds": 45, "traffic_seconds": 105,
            "successful_operations": counts,
            "different_pool_users_per_role": {role: len(users) for role, users in observed_users.items()},
            "normal_rollover_failures": len(failures),
            "expired_lease_readiness_and_work_blocking": "passed",
            "vault_outage_recovery_without_restart": "passed",
            "root_rotation_and_old_credential_1045": "passed",
            "private_management_and_secret_free_logs": "passed",
        }
        output = os.environ.get("PETCLINIC_TEST_RESULTS")
        if output:
            Path(output).write_text(json.dumps(result, indent=2))
    finally:
        if paused:
            os.kill(vault_pid, signal.SIGCONT)
        for process in processes.values():
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        for stream in streams:
            stream.close()
