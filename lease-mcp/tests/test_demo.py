"""The public replay must refuse unapproved or shared environments."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import MagicMock, Mock

import pytest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/demo.py"


def load_demo():
    spec = importlib.util.spec_from_file_location("public_demo", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_application_check_creates_a_visit_instead_of_assuming_seed_owner_has_one(monkeypatch):
    module = load_demo()
    waiting = Mock()
    posting = MagicMock()
    posting.return_value.__enter__.return_value.status = 201
    monkeypatch.setattr(module, "wait_for_json", waiting)
    monkeypatch.setattr(module, "urlopen", posting)
    module.check_application([])
    request = posting.call_args.args[0]
    assert request.method == "POST"
    assert request.full_url.endswith("/api/visit/owners/1/pets/1/visits")
    assert json.loads(request.data)["description"] == "Leak to Lease replay verification"
    aggregate_predicate = waiting.call_args.args[2]
    assert not aggregate_predicate({"pets": [{"visits": []}], "visitsUnavailable": False})
    assert aggregate_predicate({"pets": [{"visits": [{"id": 1}]}], "visitsUnavailable": False})


@pytest.mark.parametrize("service,suffix,ready", [
    ("config-server", "/customers-service/mysql", {"propertySources": [{"name": "synthetic"}]}),
    ("discovery-server", "/eureka/apps", {"applications": {}}),
    ("customers-service", "/actuator/health", {"status": "UP"}),
])
def test_startup_checks_the_service_contract_not_a_config_route_named_health(monkeypatch, service, suffix, ready):
    module = load_demo()
    waiting = Mock()
    monkeypatch.setattr(module, "wait_for_json", waiting)
    module.wait_for_service(service, 12345, [])
    url, processes, predicate = waiting.call_args.args
    assert url == "http://127.0.0.1:12345" + suffix
    assert processes == []
    assert predicate(ready)
    assert not predicate({})
    assert not predicate({"name": "actuator", "profiles": ["health"], "propertySources": []})


@pytest.mark.parametrize("token", [None, "synthetic-service-only"])
def test_java_environment_drops_admin_credentials_and_preserves_service_auth(token):
    module = load_demo()
    environment = {
        "PATH": "/synthetic/bin", "VAULT_ADDR": "http://127.0.0.1:18200",
        "VAULT_TOKEN": "synthetic-admin", "MYSQL_ROOT_PASSWORD": "synthetic-admin",
        "LEASE_MCP_TEST_DB_PASSWORD": "synthetic-admin", "BOB_API_KEY": "synthetic-private",
        "HCP_CLIENT_SECRET": "synthetic-private", "HCP_ACCESS_TOKEN": "synthetic-private",
        "SPRING_CLOUD_VAULT_TOKEN": "synthetic-inherited",
        "SPRING_CLOUD_VAULT_APP_ROLE_SECRET_ID": "synthetic-private",
        "UNRELATED_OPAQUE_SETTING": "synthetic-private",
    }
    result = module.application_environment(environment, token)
    assert result["PATH"] == environment["PATH"]
    assert result["VAULT_ADDR"] == environment["VAULT_ADDR"]
    assert not ({"VAULT_TOKEN", "MYSQL_ROOT_PASSWORD", "LEASE_MCP_TEST_DB_PASSWORD", "BOB_API_KEY"} & result.keys())
    assert not any(key.startswith("HCP_") for key in result)
    assert "SPRING_CLOUD_VAULT_APP_ROLE_SECRET_ID" not in result
    assert "UNRELATED_OPAQUE_SETTING" not in result
    assert result.get("SPRING_CLOUD_VAULT_TOKEN") == token
    assert environment["VAULT_TOKEN"] == "synthetic-admin"


@pytest.mark.parametrize(("primary_failure", "cleanup_failure"), [
    (True, "compose"), (False, "compose"), (False, "diagnostics"),
])
def test_cleanup_failure_retains_logs_and_does_not_mask_primary_error(monkeypatch, tmp_path, capsys, primary_failure, cleanup_failure):
    module = load_demo()
    workspace = tmp_path / "private-workspace"
    workspace.mkdir()
    monkeypatch.setattr(module.tempfile, "mkdtemp", lambda **kwargs: str(workspace))
    monkeypatch.setattr(module.socket, "socket", MagicMock())
    if cleanup_failure == "diagnostics":
        monkeypatch.setattr(module.shutil, "rmtree", Mock(side_effect=PermissionError("synthetic-only")))
    for key, value in {
        "LEASE_MCP_DISPOSABLE_DOCKER_CONTEXT": "owned-test-context",
        "DOCKER_CONTEXT": "owned-test-context",
        "VAULT_ADDR": "http://127.0.0.1:1", "VAULT_TOKEN": "synthetic-only",
    }.items():
        monkeypatch.setenv(key, value)

    def command(arguments, **kwargs):
        if arguments[:3] == ["docker", "context", "inspect"]:
            return subprocess.CompletedProcess(arguments, 0, '[{"Endpoints":{"docker":{"Host":"unix:///synthetic"}}}]', "")
        if "down" in arguments and cleanup_failure == "compose":
            return subprocess.CompletedProcess(arguments, 1, "", "synthetic-cleanup-failure")
        if "up" in arguments and primary_failure:
            return subprocess.CompletedProcess(arguments, 1, "", "synthetic-primary-failure")
        output = "synthetic-container" if "ps" in arguments else "1 passed"
        return subprocess.CompletedProcess(arguments, 0, output, "")

    monkeypatch.setattr(module.subprocess, "run", command)
    expected = "compose-up failed" if primary_failure else "Owned-resource cleanup failed"
    with pytest.raises(RuntimeError, match=expected):
        module.run_demo("test_integration.py")
    stderr = capsys.readouterr().err
    assert ("Compose cleanup failed" if cleanup_failure == "compose" else "Diagnostic cleanup failed") in stderr
    assert str(workspace) in stderr
    assert workspace.is_dir()


def test_demo_requires_explicit_approval():
    result = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 2
    assert "--allow-disposable-changes is required" in result.stderr


@pytest.mark.parametrize("context", ["", "default", "desktop-linux", "unmatched-context"])
def test_demo_refuses_unapproved_context_before_docker_or_database_calls(monkeypatch, context):
    spec = importlib.util.spec_from_file_location("public_demo", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    monkeypatch.setenv("LEASE_MCP_DISPOSABLE_DOCKER_CONTEXT", context)
    monkeypatch.setenv("DOCKER_CONTEXT", "different-context")
    docker = Mock(side_effect=AssertionError("Unapproved environment must not contact Docker"))
    monkeypatch.setattr(module.subprocess, "run", docker)
    with pytest.raises(RuntimeError, match="dedicated|match"):
        module.run_demo()
    docker.assert_not_called()
