#!/usr/bin/env bash
# setup-env.sh — Idempotent environment bootstrap for chain-sec.
#
# Creates a permanent Python venv at <project-root>/.venv and installs:
#   - slither-analyzer (static analysis framework)
#   - solc-select      (Solidity compiler version manager)
#   - solc 0.8.20      (pinned compiler)
#   - pytest + ruff    (test runner + linter)
#
# Idempotent: safe to rerun; skips steps already done.
#
# Usage (run from anywhere; resolves project root automatically):
#   bash scripts/setup-env.sh
#
# After running, activate the venv:
#   source .venv/bin/activate
#
# Or run non-interactively (e.g. in CI):
#   .venv/bin/python -m pytest
#   CHAIN_SEC_SOLC=<path> .venv/bin/python scan.py <target>

set -euo pipefail

# Resolve project root as the directory containing this script's parent.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

VENV_DIR="${PROJECT_ROOT}/.venv"
SOLC_VERSION="0.8.20"

echo "[chain-sec] Project root : ${PROJECT_ROOT}"
echo "[chain-sec] Venv location: ${VENV_DIR}"

# ---------------------------------------------------------------------------
# 1. Create venv (skip if already exists)
# ---------------------------------------------------------------------------
if [ ! -f "${VENV_DIR}/bin/activate" ]; then
    echo "[chain-sec] Creating Python venv ..."
    python3 -m venv "${VENV_DIR}"
else
    echo "[chain-sec] Venv already exists, skipping creation."
fi

# Activate for subsequent commands in this script.
# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"

# ---------------------------------------------------------------------------
# 2. Upgrade pip (quiet)
# ---------------------------------------------------------------------------
pip install --quiet --upgrade pip

# ---------------------------------------------------------------------------
# 3. Install slither-analyzer (skip if already installed)
# ---------------------------------------------------------------------------
if ! python -c "import slither" 2>/dev/null; then
    echo "[chain-sec] Installing slither-analyzer ..."
    pip install --quiet slither-analyzer
else
    echo "[chain-sec] slither-analyzer already installed."
fi

# ---------------------------------------------------------------------------
# 4. Install solc-select (skip if already available)
# ---------------------------------------------------------------------------
if ! command -v solc-select &>/dev/null; then
    echo "[chain-sec] Installing solc-select ..."
    pip install --quiet solc-select
else
    echo "[chain-sec] solc-select already installed."
fi

# ---------------------------------------------------------------------------
# 5. Install solc 0.8.20 via solc-select (skip if already present)
#    solc-select stores artifacts in ~/.solc-select by default.
#    We also mirror the binary into the venv dir so it survives on
#    machines where ~ is read-only (e.g. sandboxed CI).
# ---------------------------------------------------------------------------
SOLC_HOME_BIN="${HOME}/.solc-select/artifacts/solc-${SOLC_VERSION}/solc-${SOLC_VERSION}"
SOLC_VENV_BIN="${VENV_DIR}/.solc-select/artifacts/solc-${SOLC_VERSION}/solc-${SOLC_VERSION}"

if [ ! -f "${SOLC_HOME_BIN}" ] && [ ! -f "${SOLC_VENV_BIN}" ]; then
    echo "[chain-sec] Installing solc ${SOLC_VERSION} ..."
    # Try writing to ~/.solc-select; if home is read-only, mirror into venv.
    if solc-select install "${SOLC_VERSION}" 2>/dev/null; then
        echo "[chain-sec] solc ${SOLC_VERSION} installed to ~/.solc-select"
    else
        echo "[chain-sec] ~/.solc-select not writable; installing into venv ..."
        mkdir -p "$(dirname "${SOLC_VENV_BIN}")"
        # Download directly with pip-installed solc-select using SOLC_SELECT_DIR override.
        SOLC_SELECT_DIR="${VENV_DIR}/.solc-select" solc-select install "${SOLC_VERSION}"
    fi
else
    echo "[chain-sec] solc ${SOLC_VERSION} already installed."
fi

# Determine which solc binary we actually have.
if [ -f "${SOLC_HOME_BIN}" ]; then
    SOLC_BIN="${SOLC_HOME_BIN}"
else
    SOLC_BIN="${SOLC_VENV_BIN}"
fi

# ---------------------------------------------------------------------------
# 6. Set solc 0.8.20 as the active version (best-effort; may fail if
#    ~/.solc-select is read-only, but CHAIN_SEC_SOLC bypasses this)
# ---------------------------------------------------------------------------
solc-select use "${SOLC_VERSION}" 2>/dev/null || true

# ---------------------------------------------------------------------------
# 7. Install pytest + ruff if not present
# ---------------------------------------------------------------------------
if ! python -c "import pytest" 2>/dev/null; then
    echo "[chain-sec] Installing pytest ..."
    pip install --quiet pytest
fi

if ! "${VENV_DIR}/bin/ruff" --version &>/dev/null 2>&1; then
    echo "[chain-sec] Installing ruff ..."
    pip install --quiet ruff
fi

# ---------------------------------------------------------------------------
# Done — print activation instructions
# ---------------------------------------------------------------------------
echo ""
echo "[chain-sec] Environment ready."
echo "  Venv  : ${VENV_DIR}"
echo "  Python: $(python --version)"
echo "  Solc  : ${SOLC_BIN}"
echo ""
echo "Activate  : source ${VENV_DIR}/bin/activate"
echo "Run tests : PYTHONPATH=${PROJECT_ROOT} CHAIN_SEC_SOLC=${SOLC_BIN} \\"
echo "            ${VENV_DIR}/bin/python -m pytest"
echo "Scan      : CHAIN_SEC_SOLC=${SOLC_BIN} \\"
echo "            ${VENV_DIR}/bin/python ${PROJECT_ROOT}/scan.py <target>"
