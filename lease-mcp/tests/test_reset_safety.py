"""Reset and integration isolation guards, with no live Docker/Vault/MySQL calls."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import Mock

import mysql.connector
import pytest


ROOT = Path(__file__).resolve().parents[2]
SYNTHETIC = 'synthetic-only-pass#with"quotes\\slash'
CONTEXT = "ltl-disposable-tests"
OWNER = "synthetic-task-owner"


@pytest.fixture
def reset_workspace(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    script = scripts / "reset-demo.sh"
    script.write_bytes((ROOT / "scripts/reset-demo.sh").read_bytes())
    config = tmp_path / "targets/spring-petclinic-microservices-config/application.yml"
    config.parent.mkdir(parents=True)
    config.write_text("spring:\n  datasource:\n    username: root\n    password: ${DB_PASSWORD_QUARANTINED}\n")
    readme = tmp_path / "targets/spring-petclinic-microservices/README.md"
    readme.parent.mkdir(parents=True)
    readme.write_text("Synthetic demo password: ${DB_PASSWORD_QUARANTINED}\n")
    sql_paths = []
    for service in ("customers", "vets", "visits"):
        directory = readme.parent / f"spring-petclinic-{service}-service/src/main/resources/db/mysql"
        directory.mkdir(parents=True)
        for name in ("schema", "data"):
            path = directory / f"{name}.sql"
            path.write_text("-- synthetic nonexecuted SQL\nSELECT 1;\n" if name == "data" else "-- synthetic schema\n")
            sql_paths.append(path)
    binary = tmp_path / "docker"
    binary.write_text(
        f"#!{sys.executable}\n"
        "import json, os, pathlib, sys\n"
        "args = sys.argv[1:]\n"
        "mode = os.environ.get('DOCKER_TEST_MODE', 'success')\n"
        "stdin = sys.stdin.read() if 'exec' in args else ''\n"
        "with pathlib.Path(os.environ['DOCKER_ARGUMENTS']).open('a') as out:\n"
        " out.write(json.dumps({'args': args, 'stdin_has_password': os.environ['MYSQL_ROOT_PASSWORD'] in stdin}) + '\\n')\n"
        "if args == ['context', 'show']:\n"
        " print('other-context' if mode == 'wrong-context' else os.environ['LEASE_MCP_DISPOSABLE_DOCKER_CONTEXT'])\n"
        "elif 'inspect' in args:\n"
        " labels = {'io.leak-to-lease.disposable': 'true', 'io.leak-to-lease.owner': os.environ['LEASE_MCP_TEST_OWNER']}\n"
        " if mode == 'unowned': labels = {}\n"
        " if mode == 'wrong-owner': labels['io.leak-to-lease.owner'] = 'someone-else'\n"
        " print(json.dumps([{'Config': {'Labels': labels}, 'State': {'Running': mode != 'stopped'}, "
        "'NetworkSettings': {'Ports': {'3306/tcp': [{'HostPort': '3306' if mode == 'shared-port' else '3307', 'HostIp': '127.0.0.1'}]}}}]))\n"
        "elif 'exec' in args and (mode == 'login-failure' or (mode == 'seed-failure' and stdin.endswith('-- synthetic schema\\n'))):\n"
        " print(os.environ['MYSQL_ROOT_PASSWORD'])\n"
        " print(os.environ['MYSQL_ROOT_PASSWORD'], file=sys.stderr)\n"
        " sys.exit(7)\n",
        encoding="utf-8",
    )
    binary.chmod(0o700)
    environment = dict(
        os.environ, LEASE_MCP_ALLOW_DESTRUCTIVE_RESET="1",
        LEAK_DEMO_PASSWORD=SYNTHETIC, MYSQL_ROOT_PASSWORD=SYNTHETIC,
        MYSQL_CONTAINER_NAME="owned-disposable-mysql",
        LEASE_MCP_DISPOSABLE_DOCKER_CONTEXT=CONTEXT, LEASE_MCP_TEST_OWNER=OWNER,
        DOCKER_ARGUMENTS=str(tmp_path / "docker-arguments.jsonl"),
        PATH=str(tmp_path) + os.pathsep + os.environ["PATH"],
    )
    return script, config, readme, sql_paths, environment


def run_reset(workspace, *, arguments=(), **overrides):
    script, config, readme, sql_paths, environment = workspace
    result = subprocess.run(
        ["bash", str(script), *arguments], cwd=script.parent.parent,
        env=dict(environment, **overrides), capture_output=True, text=True, check=False,
    )
    assert SYNTHETIC not in result.stdout + result.stderr
    arguments_path = script.parent.parent / "docker-arguments.jsonl"
    if arguments_path.exists():
        assert SYNTHETIC not in arguments_path.read_text()
    return result


def test_reset_requires_explicit_acknowledgement_before_any_operation(reset_workspace):
    result = run_reset(reset_workspace, LEASE_MCP_ALLOW_DESTRUCTIVE_RESET="")
    assert result.returncode == 1
    assert not Path(reset_workspace[4]["DOCKER_ARGUMENTS"]).exists()
    assert "${DB_PASSWORD_QUARANTINED}" in reset_workspace[1].read_text()


@pytest.mark.parametrize("name", [
    "LEAK_DEMO_PASSWORD", "MYSQL_ROOT_PASSWORD", "MYSQL_CONTAINER_NAME",
    "LEASE_MCP_DISPOSABLE_DOCKER_CONTEXT", "LEASE_MCP_TEST_OWNER",
])
def test_reset_missing_required_configuration_fails_before_edits(reset_workspace, name):
    result = run_reset(reset_workspace, **{name: ""})
    assert result.returncode == 1
    assert not Path(reset_workspace[4]["DOCKER_ARGUMENTS"]).exists()
    assert "${DB_PASSWORD_QUARANTINED}" in reset_workspace[1].read_text()


@pytest.mark.parametrize("missing", ["config", "readme", "schema", "data"])
def test_reset_missing_source_or_sql_fails_before_docker_or_edits(reset_workspace, missing):
    script, config, readme, sql_paths, environment = reset_workspace
    path = {"config": config, "readme": readme, "schema": sql_paths[0], "data": sql_paths[1]}[missing]
    path.unlink()
    assert run_reset(reset_workspace).returncode == 1
    assert not Path(environment["DOCKER_ARGUMENTS"]).exists()
    if config.exists():
        assert "${DB_PASSWORD_QUARANTINED}" in config.read_text()


@pytest.mark.parametrize("mode", [
    "wrong-context", "unowned", "wrong-owner", "stopped", "shared-port",
    "login-failure", "seed-failure",
])
def test_reset_refuses_unsafe_resources_and_suppresses_raw_failures(reset_workspace, mode):
    result = run_reset(reset_workspace, DOCKER_TEST_MODE=mode)
    assert result.returncode == 1
    assert "${DB_PASSWORD_QUARANTINED}" in reset_workspace[1].read_text()
    assert "${DB_PASSWORD_QUARANTINED}" in reset_workspace[2].read_text()


def test_reset_refuses_shared_default_context(reset_workspace):
    assert run_reset(reset_workspace, LEASE_MCP_DISPOSABLE_DOCKER_CONTEXT="default").returncode == 1
    assert not Path(reset_workspace[4]["DOCKER_ARGUMENTS"]).exists()


def test_reset_refuses_unreadable_sql_before_operations(reset_workspace):
    path = reset_workspace[3][0]
    path.chmod(0)
    try:
        assert run_reset(reset_workspace).returncode == 1
        assert not Path(reset_workspace[4]["DOCKER_ARGUMENTS"]).exists()
    finally:
        path.chmod(0o600)


def test_reset_uses_private_mysql_options_not_password_argv(reset_workspace):
    result = run_reset(reset_workspace)
    assert result.returncode == 0
    script, config, readme, _, environment = reset_workspace
    rows = [json.loads(line) for line in Path(environment["DOCKER_ARGUMENTS"]).read_text().splitlines()]
    executions = [row for row in rows if "exec" in row["args"]]
    assert len(executions) == 7
    # The credential is escaped in a MySQL option file, never an argv element.
    for row in executions:
        assert "--defaults-extra-file" in row["args"][-1]
        assert "trap" in row["args"][-1]
        assert not any(argument.startswith("-p") for argument in row["args"])
    import yaml
    assert yaml.safe_load(config.read_text())["spring"]["datasource"]["password"] == SYNTHETIC
    assert SYNTHETIC in readme.read_text()


def test_reset_restores_dynamic_username_without_ambiguous_insertion(reset_workspace):
    config = reset_workspace[1]
    config.write_text(config.read_text().replace("username: root", "username: ${MYSQL_USERNAME}"))
    assert run_reset(reset_workspace).returncode == 0
    assert "username: root" in config.read_text()


def test_seed_only_does_not_read_or_modify_credential_sources(reset_workspace):
    config, readme = reset_workspace[1:3]
    originals = (config.read_bytes(), readme.read_bytes())
    result = run_reset(reset_workspace, arguments=["--seed-only"], LEAK_DEMO_PASSWORD="")
    assert result.returncode == 0
    assert (config.read_bytes(), readme.read_bytes()) == originals
    assert "not read or modified" in result.stdout


def test_seed_only_does_not_require_credential_source_files(reset_workspace):
    reset_workspace[1].unlink()
    reset_workspace[2].unlink()
    assert run_reset(reset_workspace, arguments=["--seed-only"], LEAK_DEMO_PASSWORD="").returncode == 0


def test_seed_only_still_requires_destructive_acknowledgement(reset_workspace):
    assert run_reset(
        reset_workspace, arguments=["--seed-only"], LEASE_MCP_ALLOW_DESTRUCTIVE_RESET="",
    ).returncode == 1
    assert not Path(reset_workspace[4]["DOCKER_ARGUMENTS"]).exists()


@pytest.mark.parametrize("exit_code", [0, 6])
def test_mysql_option_file_is_private_and_removed_on_success_or_failure(reset_workspace, exit_code):
    assert run_reset(reset_workspace).returncode == 0
    script, _, _, _, environment = reset_workspace
    rows = [json.loads(line) for line in Path(environment["DOCKER_ARGUMENTS"]).read_text().splitlines()]
    shell_script = next(row["args"][-1] for row in rows if "exec" in row["args"])
    mysql = script.parent.parent / "mysql"
    mysql.write_text(
        f"#!{sys.executable}\n"
        "import os, pathlib, sys\n"
        "assert len(sys.argv) == 3\n"
        "assert sys.argv[1].startswith('--defaults-extra-file=')\n"
        "config = pathlib.Path(sys.argv[1].split('=', 1)[1])\n"
        "assert config.stat().st_mode & 0o777 == 0o600\n"
        "assert '[client]\\nuser=root\\npassword=' in config.read_text()\n"
        "assert all(os.environ['MYSQL_ROOT_PASSWORD'] not in argument for argument in sys.argv)\n"
        "sys.stdin.read()\n"
        "sys.exit(int(os.environ['MYSQL_TEST_EXIT']))\n"
    )
    mysql.chmod(0o700)
    escaped = SYNTHETIC.replace("\\", "\\\\").replace('"', '\\"')
    result = subprocess.run(
        ["/bin/sh", "-c", shell_script],
        input=f'[client]\nuser=root\npassword="{escaped}"\nSELECT 1;\n',
        cwd=script.parent.parent,
        env=dict(environment, HOME=str(script.parent.parent), MYSQL_TEST_EXIT=str(exit_code)),
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == exit_code
    assert SYNTHETIC not in result.stdout + result.stderr
    assert not list(script.parent.parent.glob(".ltl-reset-mysql-*.cnf"))


@pytest.fixture
def integration_module():
    spec = importlib.util.spec_from_file_location("isolated_integration_guards", ROOT / "lease-mcp/tests/conftest.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_failed_mysql_login_never_recreates_container(integration_module, monkeypatch):
    subprocess_run = Mock(side_effect=AssertionError("No Docker command should run after login failure"))
    monkeypatch.setattr(integration_module.subprocess, "run", subprocess_run)
    monkeypatch.setattr(mysql.connector, "connect", Mock(side_effect=RuntimeError(SYNTHETIC)))
    with pytest.raises(RuntimeError, match="provision a fresh database") as error:
        integration_module.verify_test_mysql_instance(SYNTHETIC)
    assert SYNTHETIC not in str(error.value)
    subprocess_run.assert_not_called()


def test_default_integration_skips_without_contacting_services(integration_module, monkeypatch):
    monkeypatch.setenv("LEASE_MCP_TEST_DB_PASSWORD", "")
    monkeypatch.delenv("LEASE_MCP_RUN_DB_INTEGRATION", raising=False)
    monkeypatch.setenv("LEASE_MCP_RUN_SKILL_INTEGRATION", "0")
    check = Mock(side_effect=AssertionError("Default suite must not contact live services"))
    monkeypatch.setattr(integration_module, "verify_disposable_test_container", check)
    monkeypatch.setattr(integration_module, "is_vault_available", check)
    monkeypatch.setattr(integration_module, "is_mysql_3307_available", check)
    with pytest.raises(pytest.skip.Exception):
        next(integration_module.disposable_service_environment.__wrapped__())
    check.assert_not_called()


@pytest.mark.parametrize("password,opt_in", [("", "1"), ("", "typo"), ("synthetic", ""), ("synthetic", "1")])
def test_opted_in_invalid_integration_fails_instead_of_skipping(integration_module, monkeypatch, password, opt_in):
    monkeypatch.setenv("LEASE_MCP_TEST_DB_PASSWORD", password)
    monkeypatch.setenv("LEASE_MCP_RUN_DB_INTEGRATION", opt_in)
    monkeypatch.setenv("LEASE_MCP_RUN_SKILL_INTEGRATION", "0")
    monkeypatch.setattr(integration_module, "verify_disposable_test_container", Mock(side_effect=RuntimeError("Invalid disposable configuration")))
    with pytest.raises(pytest.fail.Exception):
        next(integration_module.disposable_service_environment.__wrapped__())


@pytest.mark.parametrize("vault,mysql", [(False, True), (True, False)])
def test_opted_in_unreachable_services_fail_instead_of_skipping(integration_module, monkeypatch, vault, mysql):
    monkeypatch.setenv("LEASE_MCP_TEST_DB_PASSWORD", "synthetic")
    monkeypatch.setenv("LEASE_MCP_RUN_DB_INTEGRATION", "1")
    monkeypatch.setenv("LEASE_MCP_RUN_SKILL_INTEGRATION", "0")
    monkeypatch.setattr(integration_module, "verify_disposable_test_container", Mock())
    monkeypatch.setattr(integration_module, "is_vault_available", Mock(return_value=vault))
    monkeypatch.setattr(integration_module, "is_mysql_3307_available", Mock(return_value=mysql))
    login = Mock(side_effect=AssertionError("No login against unreachable services"))
    monkeypatch.setattr(integration_module, "verify_test_mysql_instance", login)
    with pytest.raises(pytest.fail.Exception, match="unreachable"):
        next(integration_module.disposable_service_environment.__wrapped__())
    login.assert_not_called()


@pytest.mark.parametrize("db_opt_in,skill_opt_in", [("1", "0"), ("0", "1"), ("1", "1")])
def test_shared_fixture_accepts_either_live_surface_opt_in(integration_module, monkeypatch, db_opt_in, skill_opt_in):
    monkeypatch.setenv("LEASE_MCP_TEST_DB_PASSWORD", "synthetic")
    monkeypatch.setenv("LEASE_MCP_RUN_DB_INTEGRATION", db_opt_in)
    monkeypatch.setenv("LEASE_MCP_RUN_SKILL_INTEGRATION", skill_opt_in)
    ownership = Mock()
    login = Mock()
    monkeypatch.setattr(integration_module, "verify_disposable_test_container", ownership)
    monkeypatch.setattr(integration_module, "is_vault_available", Mock(return_value=True))
    monkeypatch.setattr(integration_module, "is_mysql_3307_available", Mock(return_value=True))
    monkeypatch.setattr(integration_module, "verify_test_mysql_instance", login)
    fixture = integration_module.disposable_service_environment.__wrapped__()
    assert next(fixture) is None
    fixture.close()
    ownership.assert_called_once_with()
    login.assert_called_once_with("synthetic")


def test_skill_opt_in_invalid_ownership_prevents_live_requests(integration_module, monkeypatch):
    monkeypatch.setenv("LEASE_MCP_TEST_DB_PASSWORD", "synthetic")
    monkeypatch.setenv("LEASE_MCP_RUN_DB_INTEGRATION", "0")
    monkeypatch.setenv("LEASE_MCP_RUN_SKILL_INTEGRATION", "1")
    monkeypatch.setattr(integration_module, "verify_disposable_test_container", Mock(side_effect=RuntimeError("Invalid disposable ownership")))
    live = Mock(side_effect=AssertionError("Ownership must be checked before live requests"))
    monkeypatch.setattr(integration_module, "is_vault_available", live)
    monkeypatch.setattr(integration_module, "is_mysql_3307_available", live)
    monkeypatch.setattr(integration_module, "verify_test_mysql_instance", live)
    with pytest.raises(pytest.fail.Exception, match="ownership"):
        next(integration_module.disposable_service_environment.__wrapped__())
    live.assert_not_called()


@pytest.mark.parametrize("opt_in,password", [("0", ""), ("1", ""), ("1", "synthetic")])
def test_database_surface_requests_shared_fixture_only_after_its_opt_in(monkeypatch, opt_in, password):
    spec = importlib.util.spec_from_file_location("isolated_database_test", ROOT / "lease-mcp/tests/test_integration.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    monkeypatch.setenv("LEASE_MCP_RUN_DB_INTEGRATION", opt_in)
    monkeypatch.setenv("LEASE_MCP_TEST_DB_PASSWORD", password)
    request = Mock()
    if opt_in == "0":
        with pytest.raises(pytest.skip.Exception):
            module.setup_test_environment.__wrapped__(request)
        request.getfixturevalue.assert_not_called()
    elif not password:
        with pytest.raises(pytest.fail.Exception):
            module.setup_test_environment.__wrapped__(request)
        request.getfixturevalue.assert_not_called()
    else:
        module.setup_test_environment.__wrapped__(request)
        request.getfixturevalue.assert_called_once_with("disposable_service_environment")


@pytest.mark.parametrize("invalid", ["owner", "port", "context", "remote-context"])
def test_integration_container_isolation_checks(integration_module, monkeypatch, invalid):
    for name, value in {
        "LEASE_MCP_TEST_MYSQL_CONTAINER": "owned-disposable-mysql",
        "LEASE_MCP_DISPOSABLE_DOCKER_CONTEXT": CONTEXT,
        "LEASE_MCP_TEST_OWNER": OWNER,
        "VAULT_ADDR": "http://127.0.0.1:1", "VAULT_TOKEN": "synthetic-dummy",
    }.items():
        monkeypatch.setenv(name, value)
    info = {
        "Config": {"Labels": {"io.leak-to-lease.disposable": "true", "io.leak-to-lease.owner": OWNER}},
        "State": {"Running": True},
        "NetworkSettings": {"Ports": {"3306/tcp": [{"HostPort": "3307", "HostIp": "127.0.0.1"}]}},
    }
    if invalid == "owner":
        info["Config"]["Labels"]["io.leak-to-lease.owner"] = "another-task"
    if invalid == "port":
        info["NetworkSettings"]["Ports"]["3306/tcp"][0]["HostPort"] = "3306"
    responses = [
        subprocess.CompletedProcess([], 0, "other" if invalid == "context" else CONTEXT, ""),
        subprocess.CompletedProcess([], 0, json.dumps([{"Endpoints": {"docker": {"Host": "tcp://remote" if invalid == "remote-context" else "unix:///synthetic.sock"}}}]), ""),
        subprocess.CompletedProcess([], 0, json.dumps([info]), ""),
    ]
    mocked = Mock(side_effect=responses)
    monkeypatch.setattr(integration_module.subprocess, "run", mocked)
    with pytest.raises(RuntimeError):
        integration_module.verify_disposable_test_container()
    assert all("rm" not in call.args[0] and "run" not in call.args[0] for call in mocked.call_args_list)
