"""Shared pytest fixtures for chain-sec tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures"
_HOME = os.path.expanduser("~")
_PROJECT_ROOT = Path(__file__).parent.parent

# Candidate solc paths in priority order:
#   1. CHAIN_SEC_SOLC env var (set by scripts/env-vars.sh or CI)
#   2. ~/.solc-select (default solc-select location when home is writable)
#   3. .venv/.solc-select (fallback installed by setup-env.sh)
_SOLC_CANDIDATES = [
    os.environ.get("CHAIN_SEC_SOLC", ""),
    f"{_HOME}/.solc-select/artifacts/solc-0.8.20/solc-0.8.20",
    str(_PROJECT_ROOT / ".venv" / ".solc-select" / "artifacts" / "solc-0.8.20" / "solc-0.8.20"),
]
SOLC_BIN = next((p for p in _SOLC_CANDIDATES if p and os.path.isfile(p)), "")


@pytest.fixture(scope="session")
def solc_path() -> str | None:
    """Return the solc binary path if it exists, else None."""
    p = Path(SOLC_BIN)
    return str(p) if p.is_file() else None


@pytest.fixture(scope="session")
def slither_scanner(solc_path):
    """Return a SlitherScanner, skipping if slither is unavailable."""
    from src.scanners.slither_wrapper import SlitherScanner

    scanner = SlitherScanner(solc_path=solc_path)
    if not scanner.available:
        pytest.skip("slither not available in this environment")
    return scanner
