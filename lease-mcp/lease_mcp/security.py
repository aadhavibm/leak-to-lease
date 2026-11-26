"""Credential parsing, fingerprinting, and source replacement."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import re
import shlex
import stat
import tempfile
from typing import Iterator

import yaml


class SourceChangedError(ValueError):
    """The source no longer matches the snapshot being quarantined."""


class SourceBusyError(ValueError):
    """Another remediation operation holds the source lock."""


@dataclass(frozen=True)
class SecretLineSnapshot:
    path: Path
    original_bytes: bytes = field(repr=False)
    sanitized_bytes: bytes = field(repr=False)
    raw_secret: str = field(repr=False)
    identity: tuple[int, int]
    mode: int


def compute_fingerprint(secret_value: str) -> str:
    digest = hashlib.sha256(secret_value.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def mask_secret(secret_value: str, visible_suffix_len: int = 0) -> str:
    if not secret_value or visible_suffix_len <= 0 or len(secret_value) <= visible_suffix_len:
        return "********"
    return "*" * (len(secret_value) - visible_suffix_len) + secret_value[-visible_suffix_len:]


def is_credential_key(key: str) -> bool:
    return bool(re.search(
        r"(?:^|[._-])(?:password|passwd|pwd|secret|token|api[_-]?key)(?:$|[._-])",
        key, re.IGNORECASE,
    ))


def validate_secret_value(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Credential must be a non-empty string.")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("Multiline and control-character credentials are not supported.")
    if any(marker in value for marker in ("${", "{{", "<QUARANTINED>", "$DB_PASSWORD_QUARANTINED")):
        raise ValueError("Credential is already a placeholder or reference, not a static secret.")
    return value


def _decode_properties_value(value: str) -> str:
    if (len(value) - len(value.rstrip("\\"))) % 2:
        raise ValueError("Continued properties credentials are not supported.")

    def replace(match: re.Match[str]) -> str:
        escaped = match.group(1)
        if escaped.startswith("u"):
            return chr(int(escaped[1:], 16))
        return {"t": "\t", "n": "\n", "r": "\r", "f": "\f"}.get(escaped, escaped)

    if re.search(r"\\u(?![0-9a-fA-F]{4})", value):
        raise ValueError("Invalid properties escape.")
    decoded = re.sub(r"\\(u[0-9a-fA-F]{4}|.)", replace, value)
    try:
        return decoded.encode("utf-16-le", "surrogatepass").decode("utf-16-le")
    except UnicodeError:
        raise ValueError("Invalid properties Unicode escape.") from None


def _decode_shell_literal(value: str) -> str:
    if value.startswith("~"):
        raise ValueError("Shell-expanded credentials are not supported; use a literal value.")
    quote = None
    index = 0
    normalized = []
    while index < len(value):
        character = value[index]
        if character == "\\" and quote != "'":
            escaped = value[index:index + 2]
            # shlex preserves these escapes inside double quotes; Bash does not.
            normalized.append(escaped[1:] if quote == '"' and escaped[1:] in ("$", "`") else escaped)
            index += 2
            continue
        if character in ("'", '"'):
            if quote is None:
                quote = character
            elif quote == character:
                quote = None
        elif quote != "'" and character in ("$", "`"):
            raise ValueError("Shell-expanded credentials are not supported; use a literal value.")
        normalized.append(character)
        index += 1
    try:
        values = shlex.split("".join(normalized), comments=False, posix=True)
    except ValueError:
        raise ValueError("Unsupported shell credential quoting.") from None
    if len(values) != 1:
        raise ValueError("Unsupported shell credential value.")
    return validate_secret_value(values[0])


def parse_and_sanitize_text_line(
    raw_line: str,
    placeholder: str = "${DB_PASSWORD_QUARANTINED}",
    *,
    format_hint: str | None = None,
) -> tuple[str, str]:
    """Parse one static YAML, properties, or literal shell assignment."""
    line = raw_line.rstrip("\r\n")
    ending = raw_line[len(line):]
    if "\n" in line or "\r" in line or format_hint not in (None, "yaml", "properties", "shell"):
        raise ValueError("Unsupported credential line format.")

    shell_line = format_hint == "shell" or (
        format_hint is None and bool(re.search(r"(?:^|\s)(?:export|docker|--env|-e)(?:\s|$)", line))
    )
    if shell_line:
        assignments = [
            match for match in re.finditer(r"(?<!\S)([A-Za-z_][A-Za-z0-9_]*)=", line)
            if is_credential_key(match.group(1))
        ]
        if len(assignments) != 1:
            raise ValueError("Expected exactly one literal credential assignment on the line.")
        assignment = assignments[0]
        value_start = assignment.end()
        token = re.match(
            r"""(?:'[^']*'|"(?:[^"\\]|\\.)*"|\\[^\r\n]|[^\s'"\\;|&<>])+""",
            line[value_start:],
        )
        if token is None:
            raise ValueError("Unsupported shell credential quoting.")
        value_end = value_start + token.end()
        if value_end < len(line) and line[value_end] not in " \t;|&<>":
            raise ValueError("Unsupported shell credential quoting.")
        encoded = token.group()
        value = _decode_shell_literal(encoded)
        quote = encoded[0] if encoded[0] in ("'", '"') and encoded[-1] == encoded[0] else ""
        return value, line[:value_start] + quote + placeholder + quote + line[value_end:] + ending

    assignment = re.match(r"^([ \t]*)([\w.-]+)[ \t]*([:=])[ \t]*(.*)$", line)
    if assignment is None or not is_credential_key(assignment.group(2)):
        raise ValueError("The selected line is not a supported credential assignment.")
    encoded = assignment.group(4)
    prefix = f"{assignment.group(1)}{assignment.group(2)}{assignment.group(3)} "
    if format_hint == "properties" or (format_hint is None and assignment.group(3) == "="):
        value = validate_secret_value(_decode_properties_value(encoded))
        return value, prefix + placeholder + ending
    try:
        if any(isinstance(token, (yaml.tokens.AnchorToken, yaml.tokens.AliasToken)) for token in yaml.scan(encoded)):
            raise ValueError("YAML credential anchors and aliases are not supported.")
        node = yaml.compose(encoded)
    except yaml.YAMLError:
        raise ValueError("Unsupported YAML credential value.") from None
    if not isinstance(node, yaml.ScalarNode) or node.tag != "tag:yaml.org,2002:str" or node.style in ("|", ">"):
        raise ValueError("Credential must be a single-line YAML string; quote ambiguous values.")
    value = validate_secret_value(node.value)
    return value, prefix + encoded[:node.start_mark.index] + placeholder + encoded[node.end_mark.index:] + ending


def prepare_secret_line(
    source_path: str | Path,
    line_number: int,
    placeholder: str = "${DB_PASSWORD_QUARANTINED}",
) -> SecretLineSnapshot:
    path = Path(source_path).absolute()
    if path.is_symlink():
        raise ValueError("Credential source must not be a symbolic link.")
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError("Credential source must be a regular file.")
        descriptor = os.open(
            path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        )
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("Credential source must be a regular file.")
            if hasattr(os, "getuid") and info.st_uid != os.getuid():
                raise ValueError("Credential source must be owned by the current user.")
            if info.st_nlink != 1:
                raise ValueError("Credential source must not have hard-link aliases.")
            content = source.read()
    except OSError:
        raise ValueError("Credential source is missing or unreadable.") from None
    lines = content.splitlines(keepends=True)
    if isinstance(line_number, bool) or not isinstance(line_number, int) or not 1 <= line_number <= len(lines):
        raise ValueError("Credential line number is out of bounds.")
    format_hint = {
        ".yml": "yaml", ".yaml": "yaml", ".properties": "properties",
        ".sh": "shell", ".env": "shell",
    }.get(path.suffix)
    if path.name == ".env":
        format_hint = "shell"
    try:
        value, replacement = parse_and_sanitize_text_line(
            lines[line_number - 1].decode("utf-8"), placeholder, format_hint=format_hint,
        )
    except UnicodeError:
        raise ValueError("Credential source must be UTF-8 text.") from None
    lines[line_number - 1] = replacement.encode("utf-8")
    return SecretLineSnapshot(
        path, content, b"".join(lines), value,
        (info.st_dev, info.st_ino), stat.S_IMODE(info.st_mode),
    )


def replace_secret_line(snapshot: SecretLineSnapshot) -> None:
    def verify_source() -> None:
        try:
            info = snapshot.path.lstat()
            unchanged = (
                stat.S_ISREG(info.st_mode)
                and (info.st_dev, info.st_ino) == snapshot.identity
                and snapshot.path.read_bytes() == snapshot.original_bytes
            )
        except OSError:
            unchanged = False
        if not unchanged:
            raise SourceChangedError("Credential source changed; no source replacement was performed.")

    verify_source()
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=snapshot.path.parent, prefix=".lease-mcp-", delete=False) as output:
            temporary = Path(output.name)
            os.chmod(output.name, snapshot.mode)
            output.write(snapshot.sanitized_bytes)
            output.flush()
            os.fsync(output.fileno())
        verify_source()
        os.replace(temporary, snapshot.path)
        temporary = None
    except OSError:
        raise ValueError("Credential source could not be replaced safely.") from None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


@contextmanager
def source_file_lock(source_path: str | Path) -> Iterator[None]:
    identity = str(Path(source_path).resolve())
    owner = str(os.getuid()) if hasattr(os, "getuid") else "user"
    directory = Path(tempfile.gettempdir()) / f"lease-mcp-locks-{owner}"
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.is_symlink() or (hasattr(os, "getuid") and directory.stat().st_uid != os.getuid()):
        raise ValueError("Credential lock directory is not owned by the current user.")
    os.chmod(directory, 0o700)
    filename = directory / (hashlib.sha256(identity.encode()).hexdigest() + ".lock")
    with filename.open("a+b") as lock:
        os.chmod(filename, 0o600)
        if os.name == "nt":
            import msvcrt
            lock.seek(0)
            if not lock.read(1):
                lock.write(b"\0")
                lock.flush()
            lock.seek(0)
            try:
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                raise SourceBusyError("Another remediation operation is using this source.") from None
        else:
            import fcntl
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SourceBusyError("Another remediation operation is using this source.") from None
        try:
            yield
        finally:
            if os.name == "nt":
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def extract_secret_line(source_path: str | Path, line_number: int) -> str:
    return prepare_secret_line(source_path, line_number).raw_secret


def sanitize_secret_line(
    source_path: str | Path,
    line_number: int,
    placeholder: str = "${DB_PASSWORD_QUARANTINED}",
) -> None:
    with source_file_lock(source_path):
        replace_secret_line(prepare_secret_line(source_path, line_number, placeholder))


def extract_and_sanitize_line(
    source_path: str | Path,
    line_number: int,
    placeholder: str = "${DB_PASSWORD_QUARANTINED}",
) -> str:
    with source_file_lock(source_path):
        snapshot = prepare_secret_line(source_path, line_number, placeholder)
        replace_secret_line(snapshot)
        return snapshot.raw_secret
