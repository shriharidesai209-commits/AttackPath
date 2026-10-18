"""Global pytest configuration and fixtures for the AttackPath test suite."""

import os
import pytest
from attackpath.config import Settings, get_settings


@pytest.fixture
def clean_env(monkeypatch):
  """Clears any ambient FalkorDB / App environment variables to guarantee isolated tests."""
  keys_to_clear = [
      "APP_ENV",
      "APP_HOST",
      "APP_PORT",
      "LOG_LEVEL",
      "FALKORDB_HOST",
      "FALKORDB_PORT",
      "FALKORDB_PASSWORD",
      "FALKORDB_SSL",
      "FALKORDB_TIMEOUT_MS",
      "FALKORDB_BASELINE_GRAPH",
      "LLM_PROVIDER",
      "OPENAI_API_KEY",
      "GEMINI_API_KEY",
  ]
  for key in keys_to_clear:
    monkeypatch.delenv(key, raising=False)
  # Clear cached get_settings instance
  get_settings.cache_clear()
  yield monkeypatch
  get_settings.cache_clear()


@pytest.fixture
def test_settings(clean_env):
  """Provides a test-configured Settings instance."""
  clean_env.setenv("APP_ENV", "testing")
  clean_env.setenv("FALKORDB_HOST", "test-cluster.cloud.falkordb.com")
  clean_env.setenv("FALKORDB_PORT", "6380")
  clean_env.setenv("FALKORDB_PASSWORD", "mock_secure_pass")
  clean_env.setenv("FALKORDB_SSL", "true")
  clean_env.setenv("FALKORDB_BASELINE_GRAPH", "test_attackpath_baseline")
  return Settings()
