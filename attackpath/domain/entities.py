"""Domain models for graph entities (nodes) with strict Pydantic validation."""

from typing import Any, Literal, Optional
from pydantic import BaseModel, Field, field_validator


# Allowed Literal Types
IdentityKind = Literal["human", "service_account"]
WorkloadKind = Literal["virtual_machine", "container"]
DataAssetKind = Literal["database", "object_store", "secret_store"]
DataClassification = Literal["crown_jewel", "confidential", "internal"]


class BaseEntityNode(BaseModel):
  """Base model for any node in the AttackPath graph."""

  id: str = Field(
      ..., min_length=1, max_length=128, description="Unique node identifier"
  )
  label: str = Field(..., description="Primary node label in FalkorDB")
  name: str = Field(..., min_length=1, description="Human-readable entity name")
  is_synthetic: bool = Field(
      default=True,
      description="Explicit indicator that this entity belongs to synthetic security data",
  )
  properties: dict[str, Any] = Field(
      default_factory=dict, description="Additional entity attributes"
  )

  @field_validator("id")
  @classmethod
  def validate_id_format(cls, v: str) -> str:
    cleaned = v.strip()
    if not cleaned:
      raise ValueError("Entity ID cannot be empty or whitespace")
    return cleaned


class IdentityNode(BaseEntityNode):
  """Represents a human user or service identity."""

  label: str = "Identity"
  kind: IdentityKind = "human"
  email: str = Field(..., min_length=3)
  department: str = Field(default="Engineering")
  compromised: bool = Field(
      default=False,
      description="Whether this identity is known to be compromised",
  )
  mfa_enabled: bool = Field(
      default=True, description="Whether Multi-Factor Authentication is enforced"
  )


class WorkloadNode(BaseEntityNode):
  """Represents a server, VM, or container workload."""

  label: str = "Workload"
  kind: WorkloadKind = "virtual_machine"
  ip_address: str = Field(default="127.0.0.1")
  is_internet_facing: bool = Field(
      default=False, description="Whether workload is accessible from public IP"
  )
  os: str = Field(default="Linux")


class IAMRoleNode(BaseEntityNode):
  """Represents a cloud IAM role or system permission container."""

  label: str = "IAMRole"
  arn: str = Field(..., min_length=5, description="Full IAM ARN or role identifier")
  is_privileged: bool = Field(
      default=False, description="Whether this role holds elevated administrative rights"
  )


class DataAssetNode(BaseEntityNode):
  """Represents a sensitive data store or crown jewel asset."""

  label: str = "DataAsset"
  kind: DataAssetKind = "database"
  classification: DataClassification = Field(
      default="internal", description="Data sensitivity tier"
  )
  is_encrypted: bool = Field(
      default=True, description="Whether at-rest encryption is active"
  )
