#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077

MODE="${1:-reset}"
if [ "$#" -gt 1 ] || { [ "$MODE" != "reset" ] && [ "$MODE" != "--seed-only" ]; }; then
    echo "Usage: reset-demo.sh [--seed-only]" >&2
    exit 1
fi

if [ "${LEASE_MCP_ALLOW_DESTRUCTIVE_RESET:-}" != "1" ]; then
    echo "Error: reset destroys demo tables (and reinjects credentials unless --seed-only); set LEASE_MCP_ALLOW_DESTRUCTIVE_RESET=1 only for an owned disposable environment." >&2
    exit 1
fi

SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_ROOT"

python3 - "$MODE" <<'PY'
import json
import os
from pathlib import Path
import subprocess
import sys


def fail(message):
    print(f"Error: {message}", file=sys.stderr)
    raise SystemExit(1)


def docker(*arguments, input=None):
    try:
        result = subprocess.run(
            ["docker", "--context", context, *arguments],
            input=input, capture_output=True, text=True, check=False,
        )
    except OSError:
        fail("Docker is unavailable.")
    if result.returncode:
        fail("Docker/MySQL operation failed; check the disposable environment configuration.")
    return result.stdout


seed_only = sys.argv[1] == "--seed-only"
required = (
    "MYSQL_ROOT_PASSWORD", "MYSQL_CONTAINER_NAME",
    "LEASE_MCP_DISPOSABLE_DOCKER_CONTEXT", "LEASE_MCP_TEST_OWNER",
) + (() if seed_only else ("LEAK_DEMO_PASSWORD",))
if any(not os.environ.get(key) for key in required):
    fail("Required password, container, disposable context or owner configuration is missing.")

context = os.environ["LEASE_MCP_DISPOSABLE_DOCKER_CONTEXT"]
container = os.environ["MYSQL_CONTAINER_NAME"]
owner = os.environ["LEASE_MCP_TEST_OWNER"]
if context in {"default", "desktop-linux"}:
    fail("A dedicated, explicitly named disposable Docker context is required.")

config_path = Path("targets/spring-petclinic-microservices-config/application.yml")
readme_path = Path("targets/spring-petclinic-microservices/README.md")
sql_paths = [
    Path(f"targets/spring-petclinic-microservices/spring-petclinic-{service}-service/src/main/resources/db/mysql/{name}.sql")
    for service in ("customers", "vets", "visits")
    for name in ("schema", "data")
]
paths = sql_paths if seed_only else [config_path, readme_path, *sql_paths]
try:
    if any(not path.is_file() or path.is_symlink() for path in paths):
        fail("A required demo source or schema/data file is missing or is a symlink.")
    if any(not path.stat().st_mode & 0o444 for path in paths):
        fail("A required demo source or schema/data file is not readable.")
    contents = {path: path.read_text(encoding="utf-8") for path in paths}
    if not seed_only and any(not path.stat().st_mode & 0o222 for path in (config_path, readme_path)):
        fail("Demo credential source files are not writable.")
except (OSError, UnicodeError):
    fail("A required demo source or schema/data file cannot be read.")

try:
    active = subprocess.run(
        ["docker", "context", "show"], capture_output=True, text=True, check=False,
    )
except OSError:
    fail("Docker is unavailable.")
if active.returncode or active.stdout.strip() != context:
    fail("The active Docker context does not match the approved disposable context.")

try:
    inspected = json.loads(docker("inspect", container))
    if not isinstance(inspected, list) or len(inspected) != 1:
        fail("The disposable container identity is invalid.")
    info = inspected[0]
    labels = info.get("Config", {}).get("Labels") or {}
    if labels.get("io.leak-to-lease.disposable") != "true" or labels.get("io.leak-to-lease.owner") != owner:
        fail("The container is not labelled as this task's owned disposable resource.")
    if not info.get("State", {}).get("Running"):
        fail("The approved disposable container is not running.")
    ports = info.get("NetworkSettings", {}).get("Ports") or {}
    if any(binding.get("HostPort") == "3306" for bindings in ports.values() for binding in (bindings or [])):
        fail("A container publishing the shared MySQL port 3306 cannot be reset.")
except (ValueError, TypeError, AttributeError):
    fail("Docker returned invalid disposable container metadata.")

# MySQL reads a private option file from stdin; credentials never enter argv.
password = os.environ["MYSQL_ROOT_PASSWORD"]
if any(character in password for character in "\r\n\0"):
    fail("The database credential cannot be encoded safely.")
escaped = password.replace("\\", "\\\\").replace('"', '\\"')
mysql_script = """set -eu
umask 077
config="$HOME/.ltl-reset-mysql-$$.cnf"
IFS= read -r option_header
IFS= read -r option_user
IFS= read -r option_password
set -C
printf '%s\\n' "$option_header" "$option_user" "$option_password" > "$config"
trap 'rm -f "$config"' EXIT HUP INT TERM
set +C
mysql --defaults-extra-file="$config" petclinic
"""
options = f'[client]\nuser=root\npassword="{escaped}"\n'
docker("exec", "-i", container, "sh", "-c", mysql_script, input=options + "SELECT 1;\n")

if not seed_only:
    demo_password = os.environ["LEAK_DEMO_PASSWORD"]
    if any(character in demo_password for character in "\r\n\0"):
        fail("The demo credential cannot be encoded safely.")
    config = contents[config_path]
    lines = config.splitlines(keepends=True)
    password_lines = [index for index, line in enumerate(lines) if line.lstrip().startswith("password:")]
    username_lines = [index for index, line in enumerate(lines) if line.lstrip().startswith("username:")]
    if len(password_lines) != 1 or len(username_lines) != 1:
        fail("Demo datasource username/password markers are missing or ambiguous.")
    username_index = username_lines[0]
    username_indent = lines[username_index][:len(lines[username_index]) - len(lines[username_index].lstrip())]
    lines[username_index] = f"{username_indent}username: root\n"
    index = password_lines[0]
    indent = lines[index][:len(lines[index]) - len(lines[index].lstrip())]
    lines[index] = f"{indent}password: {json.dumps(demo_password)} # Intentional fake for the demo.\n"
    if "${DB_PASSWORD_QUARANTINED}" not in contents[readme_path]:
        fail("The README quarantine marker is missing; refusing an ambiguous reinjection.")
    readme = contents[readme_path].replace("${DB_PASSWORD_QUARANTINED}", demo_password)

for path in sql_paths:
    docker("exec", "-i", container, "sh", "-c", mysql_script, input=options + contents[path])

if seed_only:
    print("Disposable demo schemas seeded; credential source files were not read or modified.")
else:
    try:
        config_path.write_text("".join(lines), encoding="utf-8")
        readme_path.write_text(readme, encoding="utf-8")
    except OSError:
        fail("Demo credential source files could not be updated.")
    print("Disposable demo schemas seeded and credential sources restored.")
PY
