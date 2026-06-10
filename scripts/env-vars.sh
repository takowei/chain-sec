#!/usr/bin/env bash
# env-vars.sh — Environment variables needed for tests and scan.py.
#
# Source this file after activating the venv:
#
#   source .venv/bin/activate
#   source scripts/env-vars.sh
#   python -m pytest
#   python scan.py tests/fixtures/UnguardedMint.sol
#
# scripts/setup-env.sh creates the venv and installs solc automatically.

# Resolve project root relative to this script.
_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_PROJECT_ROOT="$(cd "${_SCRIPT_DIR}/.." && pwd)"

# Absolute path to the permanent venv created by setup-env.sh.
export VIRTUAL_ENV="${_PROJECT_ROOT}/.venv"

# Add project root to PYTHONPATH so `src.*` imports resolve without install.
export PYTHONPATH="${_PROJECT_ROOT}"

# Explicit path to the solc binary installed by solc-select.
# setup-env.sh installs solc-0.8.20; two possible locations:
#   (a) ~/.solc-select  — default for solc-select when home is writable
#   (b) .venv/.solc-select — fallback when home is read-only
_SOLC_HOME="${HOME}/.solc-select/artifacts/solc-0.8.20/solc-0.8.20"
_SOLC_VENV="${_PROJECT_ROOT}/.venv/.solc-select/artifacts/solc-0.8.20/solc-0.8.20"

if [ -f "${_SOLC_HOME}" ]; then
    export CHAIN_SEC_SOLC="${_SOLC_HOME}"
elif [ -f "${_SOLC_VENV}" ]; then
    export CHAIN_SEC_SOLC="${_SOLC_VENV}"
fi

unset _SCRIPT_DIR _PROJECT_ROOT _SOLC_HOME _SOLC_VENV
