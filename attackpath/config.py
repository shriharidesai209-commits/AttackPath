"""Application configuration management using Pydantic Settings."""

from functools import lru_cache
import os
import re
from typing import Literal, Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
  """Central configuration model for the AttackPath platform.

  Loads settings from environment variables and an optional local '.env' file.
  Provides strict validation and helper properties for database connectivity and
  environments.
  """

  # Application Core
  APP_ENV: Literal["development", "testing", "production"] = Field(
      default="development", description="Current operating environment"
  )
  APP_HOST: str = Field(
      default="127.0.0.1", description="FastAPI bind hostname"
  )
  APP_PORT: int = Field(
      default=8000, ge=1, le=65535, description="FastAPI bind port"
  )
  LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
      default="INFO", description="Global logging level"
  )

  # FalkorDB Graph Database Configuration
  FALKORDB_HOST: str = Field(
      default="localhost",
      description="FalkorDB server hostname (remote cloud or local)",
  )
  FALKORDB_PORT: int = Field(
      default=6379, ge=1, le=65535, description="FalkorDB server port"
  )
  FALKORDB_USERNAME: Optional[str] = Field(
      default=None, description="Optional username for FalkorDB authentication (e.g. cloud instances)"
  )
  FALKORDB_PASSWORD: Optional[str] = Field(
      default=None, description="Optional password for FalkorDB authentication"
  )
  FALKORDB_SSL: bool = Field(
      default=False, description="Enable TLS/SSL for remote FalkorDB connection"
  )
  FALKORDB_TIMEOUT_MS: int = Field(
      default=5000,
      ge=100,
      le=60000,
      description="Connection and query timeout in milliseconds",
  )
  FALKORDB_BASELINE_GRAPH: str = Field(
      default="attackpath_baseline",
      description="Canonical graph key in FalkorDB",
  )

  # Pluggable Agent / LLM Settings (Optional)
  LLM_PROVIDER: Literal["none", "openai", "gemini"] = Field(
      default="none",
      description="LLM provider for threat explanation ('none' uses deterministic rules)",
  )
  OPENAI_API_KEY: Optional[str] = Field(
      default=None, description="Optional OpenAI API key"
  )
  GEMINI_API_KEY: Optional[str] = Field(
      default=None, description="Optional Google Gemini API key"
  )

  model_config = SettingsConfigDict(
      env_file=".env",
      env_file_encoding="utf-8",
      case_sensitive=True,
      extra="ignore",
  )

  @field_validator("FALKORDB_BASELINE_GRAPH")
  @classmethod
  def validate_graph_name(cls, v: str) -> str:
    """Ensure graph key matches safe identifier regex."""
    clean = v.strip()
    if not clean:
      raise ValueError("FALKORDB_BASELINE_GRAPH cannot be empty")
    if not re.match(r"^[a-zA-Z0-9_\-]+$", clean):
      raise ValueError(
          "FALKORDB_BASELINE_GRAPH must contain only alphanumeric characters, dashes, or underscores"
      )
    return clean

  @property
  def is_development(self) -> bool:
    return self.APP_ENV == "development"

  @property
  def is_testing(self) -> bool:
    return self.APP_ENV == "testing"

  @property
  def is_production(self) -> bool:
    return self.APP_ENV == "production"

  @property
  def falkordb_connection_uri(self) -> str:
    """Constructs a diagnostic connection URI with masked credentials for logging."""
    auth_part = ""
    if self.FALKORDB_PASSWORD and self.FALKORDB_PASSWORD.strip():
      user_prefix = f"{self.FALKORDB_USERNAME}:" if self.FALKORDB_USERNAME else ""
      auth_part = f"{user_prefix}***@"
    scheme = "rediss" if self.FALKORDB_SSL else "redis"
    return f"{scheme}://{auth_part}{self.FALKORDB_HOST}:{self.FALKORDB_PORT}/{self.FALKORDB_BASELINE_GRAPH}"


@lru_cache
def get_settings() -> Settings:
  """Returns a cached singleton instance of application settings."""
  return Settings()
