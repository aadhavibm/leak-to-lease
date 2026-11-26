"""No-service CLI checks using synthetic credentials and a fake Radar binary."""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys

import pytest


GATE = Path(__file__).resolve().parents[2] / "scripts/ci-vault-radar-gate.sh"
SYNTHETIC = "synthetic-only-credential#tail"


def run_gate(workspace: Path, target: Path, **overrides):
    environment = dict(os.environ)
    environment.update({
        "LEASE_MCP_PYTHON": sys.executable, "EXIT_ON_FAILURE": "true",
        "HCP_PROJECT_ID": "", "HCP_CLIENT_ID": "", "HCP_CLIENT_SECRET": "",
        "HCP_ACCESS_TOKEN": "",
    })
    environment.update(overrides)
    result = subprocess.run(
        ["bash", str(GATE), str(target), str(workspace / "safe-report.json")],
        cwd=workspace, env=environment, capture_output=True, text=True, check=False,
    )
    assert SYNTHETIC not in result.stdout + result.stderr
    assert not list(workspace.glob(".ltl-radar-*"))
    return result


@pytest.mark.parametrize("content,suffix", [
    (f"password: {SYNTHETIC} # comment\n", ".yaml"),
    (f"password: '{SYNTHETIC}' # comment\n", ".yml"),
    (f'password: "{SYNTHETIC}" # comment\n', ".yaml"),
    (f"spring.datasource.password={SYNTHETIC} # comment\n", ".properties"),
    (f"spring.datasource.password: {SYNTHETIC} # comment\n", ".properties"),
    (f"spring.cloud.vault.token={SYNTHETIC}\n", ".properties"),
    (f"MYSQL_ROOT_PASSWORD='{SYNTHETIC}'\n", ".env"),
    ('password: "literal\\u0023escaped"\n', ".yaml"),
])
def test_local_finds_credentials_without_printing_values(tmp_path, content, suffix):
    target = tmp_path / ("config with spaces\nand-newline" + suffix)
    target.write_text(content, encoding="utf-8")
    result = run_gate(tmp_path, target)
    assert result.returncode == 1
    report = json.loads((tmp_path / "safe-report.json").read_text())
    assert report["scanner"] == "local-backend-parser"
    assert len(report["findings"]) == 1
    finding = report["findings"][0]
    assert finding["path"] == str(target)
    assert finding["line"] == 1
    assert finding["status"] == "UNQUARANTINED_STATIC_SECRET"
    assert finding["fingerprint"].startswith("sha256:")
    assert (tmp_path / "safe-report.json").stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("content,suffix", [
    ("spring:\n  datasource:\n    password: ${DB_PASSWORD_QUARANTINED}\n", ".yaml"),
    ("password: '${DB_PASSWORD_QUARANTINED}' # comment\n", ".yaml"),
    ("password: ${SPRING_CLOUD_VAULT_TOKEN:}\n", ".yaml"),
    ("password: '${SPRING_CLOUD_VAULT_TOKEN:}'\n", ".yaml"),
    ("spring.cloud.vault.token=${SPRING_CLOUD_VAULT_TOKEN:}\n", ".properties"),
    ("MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PASSWORD:-}\n", ".env"),
    ("MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PASSWORD-}\n", ".env"),
    ("password=${DB_PASSWORD_QUARANTINED}\n", ".properties"),
    ("MYSQL_ROOT_PASSWORD=$DB_PASSWORD_QUARANTINED\n", ".env"),
    ("# password: fake-comment-only\nname: service\n", ".yaml"),
    ("password:\n", ".yaml"),
    ("", ".yaml"),
    ("", ".properties"),
])
def test_local_clean_and_placeholders(tmp_path, content, suffix):
    target = tmp_path / ("application" + suffix)
    target.write_text(content, encoding="utf-8")
    assert run_gate(tmp_path, target).returncode == 0


def test_repeated_directory_scan_does_not_scan_its_own_sanitized_report(tmp_path):
    (tmp_path / "application.yml").write_text("password: ${DB_PASSWORD:}\n")
    for _ in range(2):
        result = run_gate(tmp_path, tmp_path)
        assert result.returncode == 0
        assert json.loads((tmp_path / "safe-report.json").read_text())["findings"] == []


@pytest.mark.parametrize("content", [
    '{"password":"synthetic-source-not-a-report"}',
    '{"scanner":"local-backend-parser","findings":[],"password":"synthetic-source"}',
    '{"scanner":"local-backend-parser","findings":[{"password":"synthetic-source"}]}',
    '{"scanner":[],"findings":[]}',
])
def test_report_reuse_never_overwrites_ordinary_scan_inputs(tmp_path, content):
    report = tmp_path / "safe-report.json"
    report.write_text(content)
    assert run_gate(tmp_path, tmp_path).returncode == 2
    assert report.read_text() == content


@pytest.mark.parametrize("content", [
    "password: ${PASSWORD:-hardcoded-default}\n",
    "password: secret${PASSWORD}\n",
    "password: 123456\n",
    "password: |\n  synthetic-multiline\n",
])
def test_local_unsupported_credentials_are_not_silently_clean(tmp_path, content):
    target = tmp_path / "application.yml"
    target.write_text(content, encoding="utf-8")
    assert run_gate(tmp_path, target).returncode == 1


@pytest.mark.parametrize("content", [
    "password=${PASSWORD}#hardcoded-suffix\n",
    "password=${PASSWORD} #Java-properties-value-not-comment\n",
    "password=literal#hash-data\n",
    r"password=literal\#escaped-hash" + "\n",
])
def test_properties_hash_and_placeholder_suffixes_are_not_hidden(tmp_path, content):
    target = tmp_path / "application.properties"
    target.write_text(content, encoding="utf-8")
    assert run_gate(tmp_path, target).returncode == 1


@pytest.mark.parametrize("content,suffix,decoded", [
    ("password: literal#hash # comment\n", ".yaml", "literal#hash"),
    ("password: 'literal # hash' # comment\n", ".yaml", "literal # hash"),
    (r'password: "literal\u0023hash" # comment' + "\n", ".yaml", "literal#hash"),
    ("password=literal#hash #Java-value\n", ".properties", "literal#hash #Java-value"),
    (r"password: literal\u0023hash" + "\n", ".properties", "literal#hash"),
])
def test_local_fingerprint_uses_backend_format_semantics(tmp_path, content, suffix, decoded):
    target = tmp_path / ("application" + suffix)
    target.write_text(content, encoding="utf-8")
    assert run_gate(tmp_path, target).returncode == 1
    finding = json.loads((tmp_path / "safe-report.json").read_text())["findings"][0]
    assert finding["fingerprint"] == "sha256:" + hashlib.sha256(decoded.encode()).hexdigest()


def test_local_directory_handles_newline_paths_and_nested_yaml(tmp_path):
    target = tmp_path / "target with spaces\nand-newline"
    target.mkdir()
    config = target / "nested file\nconfig.yml"
    config.write_text(f"services:\n  - password: '{SYNTHETIC}' # actual secret\n", encoding="utf-8")
    result = run_gate(tmp_path, target)
    assert result.returncode == 1
    assert json.loads((tmp_path / "safe-report.json").read_text())["findings"][0]["line"] == 2


@pytest.mark.parametrize("failure", ["missing", "unreadable", "invalid-utf8", "invalid-yaml"])
def test_local_scan_errors_fail_even_with_findings_override(tmp_path, failure):
    target = tmp_path / "application.yaml"
    if failure == "unreadable":
        target.write_text("name: demo\n")
        target.chmod(0)
    elif failure == "invalid-utf8":
        target.write_bytes(b"\xff")
    elif failure == "invalid-yaml":
        target.write_text("name: [unterminated\n")
    try:
        assert run_gate(tmp_path, target, EXIT_ON_FAILURE="false").returncode == 2
    finally:
        if target.exists():
            target.chmod(0o600)


def test_unreadable_directory_fails_closed(tmp_path):
    target = tmp_path / "unreadable-target"
    target.mkdir()
    target.chmod(0)
    try:
        assert run_gate(tmp_path, target, EXIT_ON_FAILURE="false").returncode == 2
    finally:
        target.chmod(0o700)


def test_override_only_applies_to_findings_and_is_validated(tmp_path):
    target = tmp_path / "application.yaml"
    target.write_text(f"password: '{SYNTHETIC}'\n")
    assert run_gate(tmp_path, target, EXIT_ON_FAILURE="false").returncode == 0
    assert run_gate(tmp_path, target, EXIT_ON_FAILURE="typo").returncode == 2


@pytest.fixture
def fake_radar(tmp_path):
    binary = tmp_path / "vault-radar"
    binary.write_text(
        f"#!{sys.executable}\n"
        "import json, os, pathlib, sys\n"
        "pathlib.Path(os.environ['RADAR_ARGUMENTS']).write_text(json.dumps(sys.argv[1:]))\n"
        "print(os.environ['SYNTHETIC_RAW_ERROR'])\n"
        "print(os.environ['SYNTHETIC_RAW_ERROR'], file=sys.stderr)\n"
        "mode = os.environ['RADAR_TEST_MODE']\n"
        "report = pathlib.Path(sys.argv[sys.argv.index('-o') + 1])\n"
        "finding = {'path': 'application.yaml', 'metadata': {'start_line': 3}, "
        "'value_hash': 'a' * 64, 'textual_context': os.environ['SYNTHETIC_RAW_ERROR']}\n"
        "if mode == 'radar-052':\n"
        " finding = {'path': 'application.yml', 'metadata': {'start_line': '3', 'end_line': '3', "
        "'start_col': '15', 'end_col': '31', 'folder/file_hash': 'b' * 64}, 'value_hash': 'a' * 64}\n"
        "elif mode == 'location':\n"
        " finding['metadata'].pop('start_line')\n"
        " field = os.environ['RADAR_LOCATION_FIELD']\n"
        " value = json.loads(os.environ['RADAR_LOCATION_JSON'])\n"
        " if field == 'metadata.start_line': finding['metadata']['start_line'] = value\n"
        " else: finding[field] = value; finding.pop('metadata')\n"
        "if mode == 'empty': report.write_text('')\n"
        "elif mode in {'object', 'location'}: report.write_text(json.dumps(finding, indent=2))\n"
        "elif mode in {'ndjson', 'radar-052'}: report.write_text(json.dumps(finding) + '\\n' + json.dumps(finding) + '\\n')\n"
        "elif mode == 'array': report.write_text(json.dumps([finding]))\n"
        "elif mode == 'clean-array': report.write_text('[]')\n"
        "elif mode == 'malformed': report.write_text('{oops')\n"
        "elif mode == 'invalid-shape': report.write_text('{}')\n"
        "elif mode == 'failure': report.write_text('')\n"
        "sys.exit(9 if mode == 'failure' else 0)\n",
        encoding="utf-8",
    )
    binary.chmod(0o700)
    return {
        "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
        "HCP_PROJECT_ID": "synthetic-project", "HCP_CLIENT_ID": "synthetic-client",
        "HCP_CLIENT_SECRET": "synthetic-client-secret",
        "RADAR_ARGUMENTS": str(tmp_path / "radar-arguments.json"),
        "SYNTHETIC_RAW_ERROR": SYNTHETIC,
    }


@pytest.mark.parametrize("mode,count", [
    ("empty", 0), ("clean-array", 0), ("object", 1), ("ndjson", 2), ("array", 1),
    ("radar-052", 2),
])
def test_radar_supported_real_output_shapes_are_sanitized(tmp_path, fake_radar, mode, count):
    target = tmp_path / "target"
    target.mkdir()
    result = run_gate(tmp_path, target, **fake_radar, RADAR_TEST_MODE=mode)
    assert result.returncode == (1 if count else 0)
    report_path = tmp_path / "safe-report.json"
    report = json.loads(report_path.read_text())
    assert report["scanner"] == "vault-radar"
    assert len(report["findings"]) == count
    assert all(set(finding) == {"path", "line", "status", "fingerprint"} for finding in report["findings"])
    assert SYNTHETIC not in report_path.read_text()
    assert "--disable-ui" in json.loads((tmp_path / "radar-arguments.json").read_text())
    assert report_path.stat().st_mode & 0o777 == 0o600
    if mode == "radar-052":
        assert all(finding["path"] == "application.yml" and finding["line"] == 3 for finding in report["findings"])
        assert all(type(finding["line"]) is int for finding in report["findings"])


@pytest.mark.parametrize("field", ["metadata.start_line", "line", "line_number", "start_line"])
@pytest.mark.parametrize("line", [3, "003"])
def test_radar_positive_integer_and_digit_string_locations(tmp_path, fake_radar, field, line):
    target = tmp_path / "target"
    target.mkdir()
    result = run_gate(
        tmp_path, target, **fake_radar, RADAR_TEST_MODE="location",
        RADAR_LOCATION_FIELD=field, RADAR_LOCATION_JSON=json.dumps(line),
    )
    assert result.returncode == 1
    finding = json.loads((tmp_path / "safe-report.json").read_text())["findings"][0]
    assert finding["line"] == 3
    assert type(finding["line"]) is int


@pytest.mark.parametrize("line", [None, True, 0, "0", -1, "-1", "3.5", " 3", "bad", 3.0])
def test_radar_invalid_locations_still_fail_closed(tmp_path, fake_radar, line):
    target = tmp_path / "target"
    target.mkdir()
    result = run_gate(
        tmp_path, target, **fake_radar, RADAR_TEST_MODE="location",
        RADAR_LOCATION_FIELD="metadata.start_line", RADAR_LOCATION_JSON=json.dumps(line),
        EXIT_ON_FAILURE="false",
    )
    assert result.returncode == 2


@pytest.mark.parametrize("mode", ["failure", "missing", "malformed", "invalid-shape"])
def test_radar_scan_and_report_errors_fail_closed_without_raw_errors(tmp_path, fake_radar, mode):
    target = tmp_path / "target"
    target.mkdir()
    result = run_gate(tmp_path, target, **fake_radar, RADAR_TEST_MODE=mode, EXIT_ON_FAILURE="false")
    assert result.returncode == 2
    assert "ERROR" in result.stderr
    assert "local-backend-parser" not in result.stdout


def test_configured_missing_radar_does_not_fall_back(tmp_path):
    target = tmp_path / "application.yaml"
    target.write_text("name: demo\n")
    empty_path = tmp_path / "empty-path"
    empty_path.mkdir()
    bash = empty_path / "bash"
    bash.symlink_to("/bin/bash")
    (empty_path / "dirname").symlink_to("/usr/bin/dirname")
    # Invoke Bash directly because PATH deliberately contains no Radar.
    result = subprocess.run(
        ["/bin/bash", str(GATE), str(target), str(tmp_path / "safe-report.json")],
        cwd=tmp_path,
        env=dict(os.environ, PATH=str(empty_path), LEASE_MCP_PYTHON=sys.executable,
                 HCP_PROJECT_ID="synthetic-project", EXIT_ON_FAILURE="false"),
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 2
    assert "no local fallback" in result.stderr
