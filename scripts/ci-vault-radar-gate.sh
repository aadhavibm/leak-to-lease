#!/usr/bin/env bash
# Offline credential checks reuse the backend parser. Configured Radar never falls back.
set -euo pipefail
set +x
umask 077

SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${LEASE_MCP_PYTHON:-$SCRIPT_ROOT/lease-mcp/.venv/bin/python}"
if [ ! -x "$PYTHON" ]; then
    echo "[CI Gate] ERROR: backend Python is unavailable; configure LEASE_MCP_PYTHON." >&2
    exit 2
fi

"$PYTHON" - "$SCRIPT_ROOT" "${1:-targets}" "${2:-radar-scan-report.json}" <<'PY'
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import uuid

root, target_name, report_name = sys.argv[1:]
sys.path.insert(0, str(Path(root) / "lease-mcp"))
try:
    import yaml
    from lease_mcp.security import (
        compute_fingerprint, is_credential_key, parse_and_sanitize_text_line,
        validate_secret_value,
    )
except (ImportError, OSError):
    print("[CI Gate] ERROR: backend credential parser is unavailable.", file=sys.stderr)
    raise SystemExit(2)


def fail(message):
    print(f"[CI Gate] ERROR: {message}", file=sys.stderr)
    raise SystemExit(2)


def readable(path):
    mode = path.stat().st_mode
    if not mode & 0o444 or (stat.S_ISDIR(mode) and not mode & 0o111):
        raise OSError("unreadable scan input")


exit_on_failure = os.environ.get("EXIT_ON_FAILURE", "true")
if exit_on_failure not in {"true", "false"}:
    fail("EXIT_ON_FAILURE must be explicitly true or false.")
target = Path(target_name)
try:
    readable(target)
    if target.is_file():
        files = [target]
    elif target.is_dir():
        files = []
        def traversal_error(error):
            raise error
        for directory, directories, names in os.walk(target, onerror=traversal_error):
            readable(Path(directory))
            directories[:] = [name for name in directories if name not in {".git", ".venv", "target", "node_modules"}]
            for name in names:
                path = Path(directory) / name
                readable(path)
                if not path.is_file():
                    raise OSError("unsupported scan input")
                files.append(path)
    else:
        raise OSError("unsupported scan input")
except OSError:
    fail("Scan target is missing, unreadable, or cannot be traversed.")

report = Path(report_name)
try:
    if report.is_symlink() or (report.exists() and report.stat().st_nlink != 1):
        fail("Report destination must not be a symbolic or hard link.")
    if report.resolve() == target.resolve():
        fail("Report path must not overwrite a scan input.")
    if any(report.resolve() == path.resolve() for path in files):
        try:
            previous = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError):
            fail("Report path must not overwrite a scan input.")
        known_statuses = {"RADAR_FINDING", "UNSUPPORTED_CREDENTIAL_VALUE", "UNQUARANTINED_STATIC_SECRET"}
        valid = (
            target.is_dir() and isinstance(previous, dict)
            and set(previous) == {"scanner", "findings"}
            and isinstance(previous["scanner"], str)
            and previous["scanner"] in {"vault-radar", "local-backend-parser"}
            and isinstance(previous["findings"], list)
            and all(
                isinstance(row, dict) and {"path", "line", "status"} <= set(row)
                and set(row) <= {"path", "line", "status", "fingerprint"}
                and isinstance(row["path"], str)
                and type(row["line"]) is int and row["line"] > 0
                and isinstance(row["status"], str) and row["status"] in known_statuses
                and ("fingerprint" not in row or (
                    isinstance(row["fingerprint"], str)
                    and re.fullmatch(r"sha256:[a-f0-9]{64}", row["fingerprint"])
                ))
                for row in previous["findings"]
            )
        )
        if not valid:
            fail("Report path must not overwrite a scan input.")
        files = [path for path in files if report.resolve() != path.resolve()]
except OSError:
    fail("Report path cannot be resolved.")

findings = []
radar_configured = any(os.environ.get(name) for name in ("HCP_PROJECT_ID", "HCP_CLIENT_ID", "HCP_CLIENT_SECRET", "HCP_ACCESS_TOKEN"))
scanner = "vault-radar" if radar_configured else "local-backend-parser"
print(f"[CI Gate] Scanner: {scanner}")

if radar_configured:
    binary = shutil.which("vault-radar")
    if not binary:
        fail("Configured Vault Radar is unavailable; no local fallback was performed.")
    raw_report = Path.cwd() / f".ltl-radar-{uuid.uuid4().hex}.json"
    try:
        descriptor = os.open(raw_report, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        raw_report.unlink()
        result = subprocess.run(
            [binary, "scan", "folder", "-p", str(target), "-o", str(raw_report), "-f", "json", "--disable-ui"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        if result.returncode:
            fail(f"Vault Radar failed (exit {result.returncode}); check scanner authentication/configuration.")
        if not raw_report.is_file() or raw_report.is_symlink():
            fail("Vault Radar did not produce a readable report.")
        readable(raw_report)
        content = raw_report.read_text(encoding="utf-8")
        if not content.strip():
            rows = []
        else:
            try:
                parsed = json.loads(content)
                rows = parsed if isinstance(parsed, list) else [parsed]
            except json.JSONDecodeError:
                rows = [json.loads(line) for line in content.splitlines() if line.strip()]
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("path"), str) or not row["path"]:
                fail("Vault Radar report contains an unsupported finding shape.")
            metadata = row.get("metadata", {})
            if not isinstance(metadata, dict):
                fail("Vault Radar report contains invalid finding metadata.")
            line = metadata.get("start_line", row.get("line", row.get("line_number", row.get("start_line"))))
            if isinstance(line, str) and re.fullmatch(r"[0-9]+", line):
                line = int(line)
            if type(line) is not int or line < 1:
                fail("Vault Radar report contains an invalid finding location.")
            finding = {"path": row["path"], "line": line, "status": "RADAR_FINDING"}
            for field in ("value_hash", "fingerprint"):
                value = row.get(field)
                if isinstance(value, str) and re.fullmatch(r"(?:sha256:)?[a-fA-F0-9]{64}", value):
                    finding["fingerprint"] = "sha256:" + value.removeprefix("sha256:").lower()
                    break
            findings.append(finding)
    except (OSError, UnicodeError, ValueError):
        fail("Vault Radar failed or produced an unreadable/invalid JSON report.")
    finally:
        raw_report.unlink(missing_ok=True)
else:
    placeholder = r"(?:\$\{[A-Za-z_][A-Za-z0-9_]*(?::?-|:)?\}|\$[A-Za-z_][A-Za-z0-9_]*|\{\{[A-Za-z_][A-Za-z0-9_.-]*\}\}|<QUARANTINED>)"
    placeholder_value = re.compile(placeholder)
    placeholder_assignment = rf"\s*(?:export\s+)?[\w.-]+\s*[:=]\s*(?:{placeholder}|'{placeholder}'|\"{placeholder}\")"
    placeholder_line = re.compile(placeholder_assignment + r"\s*")
    shell_placeholder_line = re.compile(placeholder_assignment + r"(?:\s+#.*)?\s*")

    def add_finding(path, line, raw, hint):
        try:
            value, _ = parse_and_sanitize_text_line(raw, format_hint=hint)
            value = validate_secret_value(value)
        except ValueError:
            findings.append({"path": str(path), "line": line, "status": "UNSUPPORTED_CREDENTIAL_VALUE"})
            return
        findings.append({
            "path": str(path), "line": line, "status": "UNQUARANTINED_STATIC_SECRET",
            "fingerprint": compute_fingerprint(value),
        })

    def yaml_credentials(node, path, lines):
        if isinstance(node, yaml.MappingNode):
            for key, value in node.value:
                if isinstance(key, yaml.ScalarNode) and is_credential_key(key.value):
                    if isinstance(value, yaml.ScalarNode) and (
                        not value.value or placeholder_value.fullmatch(value.value)
                    ):
                        continue
                    line = key.start_mark.line + 1
                    add_finding(path, line, lines[line - 1], "yaml")
                else:
                    yaml_credentials(value, path, lines)
        elif isinstance(node, yaml.SequenceNode):
            for value in node.value:
                yaml_credentials(value, path, lines)

    try:
        for path in files:
            suffix = path.suffix.lower()
            if target.is_dir() and suffix not in {".yaml", ".yml", ".properties", ".conf", ".env"} and path.name != ".env":
                continue
            text = path.read_text(encoding="utf-8")
            lines = text.splitlines(keepends=True)
            if suffix in {".yaml", ".yml"}:
                for document in yaml.compose_all(text):
                    yaml_credentials(document, path, lines)
            else:
                hint = "shell" if suffix == ".env" or path.name == ".env" else "properties"
                for line, raw in enumerate(lines, 1):
                    assignment = re.match(r"^\s*(?:export\s+)?(?P<key>[\w.-]+)\s*[:=]", raw)
                    if not assignment or not is_credential_key(assignment["key"]):
                        continue
                    clean_reference = shell_placeholder_line if hint == "shell" else placeholder_line
                    if clean_reference.fullmatch(raw):
                        continue
                    if re.fullmatch(r"\s*[\w.-]+\s*[:=]\s*", raw):
                        continue
                    add_finding(path, line, raw, hint)
    except (OSError, UnicodeError, yaml.YAMLError, RecursionError):
        fail("Local scanner encountered an unreadable input or invalid YAML.")

try:
    if report.exists() and (report.is_symlink() or not report.is_file()):
        fail("Report destination must be a regular file, not a symlink.")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(report, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            fail("Report destination is not a regular file.")
        os.fchmod(stream.fileno(), 0o600)
        json.dump({"scanner": scanner, "findings": findings}, stream, indent=2)
        stream.write("\n")
except OSError:
    fail("Private sanitized report cannot be written.")

for finding in findings:
    print("[CI Gate] Finding: " + json.dumps(finding, ensure_ascii=True))
print(f"[CI Gate] {'FAILURE' if findings else 'SUCCESS'}: {len(findings)} finding(s).")
raise SystemExit(1 if findings and exit_on_failure == "true" else 0)
PY
