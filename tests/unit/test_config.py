"""Unit tests for AttackPath application configuration."""

import pytest
from pydantic import ValidationError
from attackpath.config import Settings, get_settings


def test_default_settings(clean_env):
  """Verify that Settings loads with expected defaults when no env is provided."""
  settings = Settings(_env_file=None)

  assert settings.APP_ENV == "development"
  assert settings.APP_HOST == "127.0.0.1"
  assert settings.APP_PORT == 8000
  assert settings.LOG_LEVEL == "INFO"

  assert settings.FALKORDB_HOST == "localhost"
  assert settings.FALKORDB_PORT == 6379
  assert settings.FALKORDB_PASSWORD is None
  assert settings.FALKORDB_SSL is False
  assert settings.FALKORDB_TIMEOUT_MS == 5000
  assert settings.FALKORDB_BASELINE_GRAPH == "attackpath_baseline"

  assert settings.LLM_PROVIDER == "none"
  assert settings.OPENAI_API_KEY is None
  assert settings.GEMINI_API_KEY is None

  assert settings.is_development is True
  assert settings.is_testing is False
  assert settings.is_production is False


def test_environment_variable_overrides(clean_env):
  """Verify that environment variables properly override default settings."""
  clean_env.setenv("APP_ENV", "production")
  clean_env.setenv("APP_PORT", "9000")
  clean_env.setenv("FALKORDB_HOST", "falkor-prod.internal")
  clean_env.setenv("FALKORDB_PORT", "6380")
  clean_env.setenv("FALKORDB_PASSWORD", "super_secret_token")
  clean_env.setenv("FALKORDB_SSL", "true")
  clean_env.setenv("FALKORDB_BASELINE_GRAPH", "enterprise_baseline_v1")

  settings = Settings()

  assert settings.APP_ENV == "production"
  assert settings.APP_PORT == 9000
  assert settings.FALKORDB_HOST == "falkor-prod.internal"
  assert settings.FALKORDB_PORT == 6380
  assert settings.FALKORDB_PASSWORD == "super_secret_token"
  assert settings.FALKORDB_SSL is True
  assert settings.FALKORDB_BASELINE_GRAPH == "enterprise_baseline_v1"
  assert settings.is_production is True


def test_invalid_port_validation(clean_env):
  """Verify that out-of-range ports trigger validation errors."""
  clean_env.setenv("FALKORDB_PORT", "99999")
  with pytest.raises(ValidationError):
    Settings()

  clean_env.setenv("FALKORDB_PORT", "-1")
  with pytest.raises(ValidationError):
    Settings()


def test_invalid_timeout_validation(clean_env):
  """Verify that unrealistic timeouts trigger validation errors."""
  clean_env.setenv("FALKORDB_TIMEOUT_MS", "10")
  with pytest.raises(ValidationError):
    Settings()


def test_graph_name_sanitization(clean_env):
  """Verify that baseline graph names with invalid characters are rejected."""
  clean_env.setenv("FALKORDB_BASELINE_GRAPH", "invalid name with spaces!")
  with pytest.raises(ValidationError):
    Settings()


def test_connection_uri_masks_secrets(test_settings):
  """Verify that diagnostic URI masks the password and reflects SSL scheme."""
  uri = test_settings.falkordb_connection_uri
  assert "mock_secure_pass" not in uri
  assert "***@" in uri
  assert uri.startswith("rediss://")
  assert "test-cluster.cloud.falkordb.com:6380/test_attackpath_baseline" in uri


def test_get_settings_singleton():
  """Verify that get_settings caches the Settings instance."""
  s1 = get_settings()
  s2 = get_settings()
  assert s1 is s2
