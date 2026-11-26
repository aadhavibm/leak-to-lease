import os
from unittest.mock import MagicMock, patch

import pytest

from lease_mcp.server import get_vault_client, LeaseMcpError, quarantine_secret, _mysql_tls_options


@pytest.fixture
def production_environment():
    with patch.dict(os.environ, {
        "LEASE_MCP_PROFILE": "production",
        "VAULT_ADDR": "https://vault.example.test:8200",
        "VAULT_TOKEN": "synthetic-only-token",
    }, clear=True), patch("lease_mcp.server._load_env_config"):
        yield


def test_production_rejects_plain_http_before_constructing_a_client(production_environment):
    with patch.dict(os.environ, {"VAULT_ADDR": "http://vault.example.test"}), patch("hvac.Client") as client:
        with pytest.raises(LeaseMcpError, match="VAULT_TLS_REQUIRED"):
            get_vault_client()
    client.assert_not_called()


def test_certificate_verification_cannot_be_bypassed(production_environment):
    with patch.dict(os.environ, {"VAULT_SKIP_VERIFY": "true"}), patch("hvac.Client") as client:
        with pytest.raises(LeaseMcpError, match="VAULT_TLS_BYPASS_FORBIDDEN"):
            get_vault_client()
    client.assert_not_called()


def test_private_ca_and_namespace_are_forwarded_with_redirects_disabled(production_environment, tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text("synthetic-public-ca-fixture")
    client = MagicMock()
    client.is_authenticated.return_value = True
    client.auth.token.lookup_self.return_value = {"data": {"policies": ["remediator"], "ttl": 3600}}
    with patch.dict(os.environ, {"VAULT_CACERT": str(ca), "VAULT_NAMESPACE": "team"}), patch(
        "hvac.Client", return_value=client,
    ) as factory:
        assert get_vault_client() is client
    assert factory.call_args.kwargs["verify"] == str(ca)
    assert factory.call_args.kwargs["namespace"] == "team"
    assert factory.call_args.kwargs["allow_redirects"] is False


@pytest.mark.parametrize("metadata", [
    {"policies": ["root"], "ttl": 3600},
    {"policies": ["remediator"], "ttl": 0},
    {"policies": ["remediator"], "ttl": -1},
    {"policies": ["remediator"], "ttl": True},
    {"policies": None, "ttl": 3600},
])
def test_production_requires_finite_nonroot_backend_authentication(production_environment, metadata):
    client = MagicMock()
    client.is_authenticated.return_value = True
    client.auth.token.lookup_self.return_value = {"data": metadata}
    with patch("hvac.Client", return_value=client):
        with pytest.raises(LeaseMcpError, match="VAULT_PRODUCTION_AUTH_INVALID"):
            get_vault_client()


def test_source_root_required_before_any_source_or_vault_operation(production_environment):
    with patch("lease_mcp.server.get_vault_client") as vault:
        with pytest.raises(LeaseMcpError, match="SOURCE_ROOT_REQUIRED"):
            quarantine_secret("/not-opened/application.yml", 1)
    vault.assert_not_called()


def test_configured_source_root_rejects_outside_files_before_vault(production_environment, tmp_path):
    approved = tmp_path / "approved"
    approved.mkdir()
    outside = tmp_path / "outside.yml"
    outside.write_text("password: synthetic-only\n")
    with patch.dict(os.environ, {"LEASE_MCP_SOURCE_ROOT": str(approved)}), patch(
        "lease_mcp.server.get_vault_client",
    ) as vault:
        with pytest.raises(LeaseMcpError, match="SOURCE_NOT_APPROVED"):
            quarantine_secret(str(outside), 1)
    vault.assert_not_called()
    assert outside.read_text() == "password: synthetic-only\n"


def test_production_requires_verified_mysql_transport(production_environment):
    with pytest.raises(LeaseMcpError, match="MYSQL_TLS_REQUIRED"):
        _mysql_tls_options()


def test_configured_mysql_ca_does_not_allow_private_key_material(production_environment, tmp_path):
    certificate = tmp_path / "wrong.pem"
    certificate.write_text("-----BEGIN PRIVATE KEY-----\nsynthetic-only\n")
    with patch.dict(os.environ, {
        "LEASE_MCP_MYSQL_CACERT": str(certificate), "LEASE_MCP_MYSQL_SERVER_NAME": "localhost",
    }):
        with pytest.raises(LeaseMcpError, match="MYSQL_CA_INVALID"):
            _mysql_tls_options()
