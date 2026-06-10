"""Shared pytest fixtures for chain-sec tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SOLC_BIN = os.environ.get(
    "CHAIN_SEC_SOLC",
    "/tmp/claude/venv/.solc-select/artifacts/solc-0.8.20/solc-0.8.20",
)


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
