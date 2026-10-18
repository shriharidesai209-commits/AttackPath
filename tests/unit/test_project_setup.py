"""Unit tests verifying project structure, packaging, and configuration integrity for Milestone 1."""

from pathlib import Path
import attackpath


def test_package_metadata():
  """Verify package exposes expected version and metadata."""
  assert hasattr(attackpath, "__version__")
  assert attackpath.__version__ == "0.1.0"


def test_directory_structure_complete():
  """Verify that all modular architecture directories and package inits exist."""
  root = Path(__file__).resolve().parent.parent.parent

  expected_dirs = [
      root / "attackpath",
      root / "attackpath" / "database",
      root / "attackpath" / "domain",
      root / "attackpath" / "services",
      root / "attackpath" / "api",
      root / "attackpath" / "api" / "routes",
      root / "attackpath" / "mcp_server",
      root / "ui",
      root / "tests",
      root / "tests" / "unit",
  ]

  for d in expected_dirs:
    assert d.is_dir(), f"Expected directory does not exist: {d}"
    init_file = d / "__init__.py"
    assert init_file.is_file(), f"Expected __init__.py missing in: {d}"


def test_env_example_security_and_format():
  """Verify .env.example exists, contains necessary keys, and contains NO real credentials."""
  root = Path(__file__).resolve().parent.parent.parent
  env_example = root / ".env.example"

  assert env_example.is_file(), ".env.example must exist at root"
  content = env_example.read_text(encoding="utf-8")

  # Mandatory template keys
  assert "FALKORDB_HOST=" in content
  assert "FALKORDB_PORT=" in content
  assert "FALKORDB_USERNAME=" in content
  assert "FALKORDB_PASSWORD=" in content
  assert "FALKORDB_SSL=" in content
  assert "FALKORDB_BASELINE_GRAPH=" in content
  assert "APP_ENV=" in content

  # Security assertions: no real passwords or tokens embedded
  lines = [line.strip() for line in content.splitlines() if line.strip()]
  for line in lines:
    if line.startswith("#"):
      continue
    if "PASSWORD=" in line:
      val = line.split("=", 1)[1].strip()
      assert val == "", f"Password in .env.example must be empty, found: {val}"
    if "API_KEY=" in line:
      val = line.split("=", 1)[1].strip()
      assert val == "", f"API key in .env.example must be empty, found: {val}"


def test_gitignore_covers_critical_artifacts():
  """Verify .gitignore excludes virtualenv, secret .env files, and python caches."""
  root = Path(__file__).resolve().parent.parent.parent
  gitignore = root / ".gitignore"

  assert gitignore.is_file(), ".gitignore must exist at root"
  content = gitignore.read_text(encoding="utf-8")

  assert ".env" in content
  assert "!.env.example" in content
  assert "venv/" in content
  assert "__pycache__/" in content
  assert ".pytest_cache/" in content
