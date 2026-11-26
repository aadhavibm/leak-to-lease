"""Pydantic data models for lease-mcp tool inputs and outputs.

All models strictly prohibit raw credential attributes in output payloads.
"""

from __future__ import annotations

from typing import Literal, Optional
from pydantic import BaseModel, ConfigDict, Field


class ReferenceResult(BaseModel):
    model_config = ConfigDict(extra="forbid")


class QuarantineResult(ReferenceResult):
    """Output returned when a leaked credential is quarantined and sanitized."""

    quarantine_id: str = Field(..., description="Unique tracking identifier (quar-<uuid>)")
    fingerprint: str = Field(..., description="SHA-256 fingerprint of the quarantined secret (sha256:<hash>)")
    vault_kv_path: str = Field(..., description="Vault KV storage path where credential is saved")
    source_path: str = Field(..., description="Target file path that was sanitized")
    status: Literal["QUARANTINED_AND_SANITIZED"] = "QUARANTINED_AND_SANITIZED"


class EnableDbEngineResult(ReferenceResult):
    """Output returned when Vault database engine is enabled."""

    mount_path: str = Field(..., description="Vault mount path of the database engine")
    engine_type: str = Field(default="database", description="Engine backend type")
    status: Literal["MOUNTED", "ALREADY_EXISTS"]


class ConfigureMysqlResult(ReferenceResult):
    """Output returned when MySQL connection is configured in Vault."""

    connection_name: str = Field(..., description="Name of the configured database connection in Vault")
    plugin_name: str = Field(default="mysql-database-plugin", description="Vault database plugin identifier")
    admin_user: str = Field(default="root", description="Administrative username")
    status: Literal["CONFIGURED"] = "CONFIGURED"


class CreateRoleResult(ReferenceResult):
    """Output returned when a dynamic database role is created in Vault."""

    role_name: str = Field(..., description="Name of the registered dynamic role (e.g., customers, vets, visits)")
    db_name: str = Field(..., description="Target database connection name in Vault")
    default_ttl: str = Field(..., description="Default lease TTL duration")
    max_ttl: str = Field(..., description="Maximum lease TTL duration")
    status: Literal["ROLE_ACTIVE"] = "ROLE_ACTIVE"


class RotateRootResult(ReferenceResult):
    """Output returned when the MySQL root credential is rotated by Vault."""

    db_name: str = Field(..., description="Target database connection name in Vault")
    rotated: bool = Field(..., description="True if root rotation succeeded")
    status: Literal["ROOT_ROTATED"] = "ROOT_ROTATED"


class LookupLeaseResult(ReferenceResult):
    """Output returned when inspecting a dynamic credential lease."""

    lease_id: str = Field(..., description="Target Vault dynamic credential lease ID")
    issue_time: str = Field(..., description="ISO-8601 lease creation timestamp")
    ttl_remaining_seconds: int = Field(..., description="Seconds remaining before lease expiration")
    renewable: bool = Field(..., description="True if lease can be renewed")
    status: Literal["ACTIVE", "EXPIRED", "NOT_FOUND"]


class ProveDeadResult(ReferenceResult):
    """Output returned when proving a legacy credential is dead and rejected by MySQL."""

    tested_user: str = Field(default="root", description="Target database user tested")
    connection_rejected: bool = Field(..., description="True if database rejected authentication as expected")
    result: Literal["REJECTED", "ACCEPTED", "INCONCLUSIVE"]
    error_code: Optional[str] = Field(default=None, description="Database error code received on rejection (e.g., 1045)")
    proof_status: Literal[
        "CREDENTIAL_PROVEN_DEAD", "ERROR_CREDENTIAL_STILL_ACTIVE", "INCONCLUSIVE_DB_UNREACHABLE",
    ]
