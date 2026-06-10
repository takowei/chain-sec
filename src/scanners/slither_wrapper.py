"""Slither-based scanner with custom mint-pattern detection rules."""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from .mint_patterns import SLITHER_BUILTIN_DETECTORS
from .models import Finding, Severity

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Environment variable that points to a writable solc-select artifacts dir.
# Set to a writable path when ~/.solc-select is read-only.
_VENV_OVERRIDE = os.environ.get("VIRTUAL_ENV", "")

# Solidity function names commonly associated with minting.
_MINT_FUNCTION_NAMES = frozenset(
    [
        "mint",
        "_mint",
        "__mint",
        "mintTo",
        "mintFor",
        "issue",
        "_issue",
        "create",
        "createTokens",
    ]
)

# Slither severity string → our Severity enum
_SLITHER_SEVERITY_MAP: dict[str, Severity] = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFO,
    "Optimization": Severity.INFO,
}


def _find_slither_bin() -> str | None:
    """Locate the slither executable, checking PATH and the pip --target dir."""
    if shutil.which("slither"):
        return shutil.which("slither")
    # Common pip --target layout: <target>/bin/slither
    pip_target = os.environ.get("PYTHONPATH", "")
    for segment in pip_target.split(os.pathsep):
        candidate = Path(segment) / "bin" / "slither"
        if candidate.is_file():
            return str(candidate)
    return None


class SlitherScanner:
    """
    Wraps Slither to perform static analysis focused on mint/supply vulnerabilities.

    Slither is invoked in two modes:
    1. JSON output mode (--json) for built-in detectors.
    2. Python API for custom mint-pattern rules.

    Parameters
    ----------
    solc_path:
        Explicit path to the solc binary. If omitted, 'solc' must be on PATH.
    pip_target:
        Directory where slither-analyzer was installed via pip --target.
        Added to PYTHONPATH so the subprocess can locate the package.
    """

    def __init__(
        self,
        solc_path: str | None = None,
        pip_target: str | None = None,
    ) -> None:
        self.solc_path = solc_path or shutil.which("solc")
        self.pip_target = pip_target
        self._slither_available = self._check_slither_available()

    def _check_slither_available(self) -> bool:
        try:
            env = self._build_env()
            result = subprocess.run(
                [sys.executable, "-c", "import slither; print('ok')"],
                capture_output=True,
                text=True,
                env=env,
                timeout=10,
            )
            return result.returncode == 0 and "ok" in result.stdout
        except Exception as exc:
            logger.warning("Slither availability check failed: %s", exc)
            return False

    def _build_env(self) -> dict[str, str]:
        env = os.environ.copy()
        if self.pip_target:
            existing = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = (
                f"{self.pip_target}{os.pathsep}{existing}" if existing else self.pip_target
            )
        if self.solc_path:
            solc_dir = str(Path(self.solc_path).parent)
            existing_path = env.get("PATH", "")
            env["PATH"] = f"{solc_dir}{os.pathsep}{existing_path}"
        return env

    @property
    def available(self) -> bool:
        return self._slither_available

    def scan(self, source_path: str | Path) -> list[Finding]:
        """
        Run full scan on a Solidity source file or directory.

        Returns list of Finding objects. Never raises; errors are logged and
        returned as INFO-level findings.
        """
        source_path = Path(source_path)
        if not source_path.exists():
            logger.error("Source path does not exist: %s", source_path)
            return []

        if not self._slither_available:
            logger.warning("Slither not available; skipping scan of %s", source_path)
            return [
                Finding(
                    rule_id="SCANNER-UNAVAILABLE",
                    severity=Severity.INFO,
                    contract="N/A",
                    function=None,
                    description=(
                        "Slither is not installed or not importable. Install slither-analyzer."
                    ),
                    source_file=str(source_path),
                )
            ]

        findings: list[Finding] = []
        findings.extend(self._run_builtin_detectors(source_path))
        findings.extend(self._run_custom_mint_rules(source_path))
        return findings

    # ------------------------------------------------------------------
    # Built-in detectors via slither CLI / JSON output
    # ------------------------------------------------------------------

    def _run_builtin_detectors(self, source_path: Path) -> list[Finding]:
        detector_args = ",".join(SLITHER_BUILTIN_DETECTORS)
        cmd = [
            sys.executable,
            "-m",
            "slither",
            str(source_path),
            "--json",
            "-",
            "--detect",
            detector_args,
            "--no-fail-pedantic",
        ]
        if self.solc_path:
            cmd += ["--solc", self.solc_path]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=self._build_env(),
                timeout=120,
            )
            if result.stdout.strip():
                return self._parse_slither_json(result.stdout, str(source_path))
            if result.returncode not in (0, 1):
                logger.warning("Slither exited %d: %s", result.returncode, result.stderr[:500])
        except subprocess.TimeoutExpired:
            logger.warning("Slither timed out on %s", source_path)
        except Exception as exc:
            logger.warning("Slither builtin run failed: %s", exc)
        return []

    def _parse_slither_json(self, raw_json: str, source_file: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError as exc:
            logger.warning("Failed to parse Slither JSON: %s", exc)
            return findings

        for result in data.get("results", {}).get("detectors", []):
            detector = result.get("check", "unknown")
            impact = result.get("impact", "Informational")
            description = result.get("description", "")
            severity = _SLITHER_SEVERITY_MAP.get(impact, Severity.INFO)

            # Extract contract/function from elements list
            contract_name = "Unknown"
            func_name: str | None = None
            line_start: int | None = None
            for elem in result.get("elements", []):
                etype = elem.get("type", "")
                if etype == "contract":
                    contract_name = elem.get("name", contract_name)
                elif etype == "function":
                    func_name = elem.get("name")
                src = elem.get("source_mapping", {})
                if src.get("lines"):
                    line_start = src["lines"][0]

            findings.append(
                Finding(
                    rule_id=f"SLITHER-{detector.upper().replace('-', '_')}",
                    severity=severity,
                    contract=contract_name,
                    function=func_name,
                    description=description.strip(),
                    source_file=source_file,
                    line_start=line_start,
                    extra={"slither_check": detector},
                )
            )
        return findings

    # ------------------------------------------------------------------
    # Custom mint-pattern rules via Slither Python API
    # ------------------------------------------------------------------

    def _run_custom_mint_rules(self, source_path: Path) -> list[Finding]:
        """
        Import Slither as a library and apply custom mint-pattern rules.
        Runs in-process so we can use the AST/CFG directly.
        """
        # Build sys.path augmentation script to avoid polluting this process.
        script = _build_custom_rule_script(str(source_path), self.solc_path)
        try:
            result = subprocess.run(
                [sys.executable, "-c", script],
                capture_output=True,
                text=True,
                env=self._build_env(),
                timeout=120,
            )
            if result.stdout.strip():
                raw = json.loads(result.stdout)
                return [Finding(**item) for item in raw]
            if result.returncode != 0:
                logger.warning("Custom rule script error: %s", result.stderr[:500])
        except subprocess.TimeoutExpired:
            logger.warning("Custom rule script timed out on %s", source_path)
        except Exception as exc:
            logger.warning("Custom rule script failed: %s", exc)
        return []


def _build_custom_rule_script(source_path: str, solc_path: str | None) -> str:
    """Return a self-contained Python script that runs custom mint rules and prints JSON."""
    mint_names = list(_MINT_FUNCTION_NAMES)
    solc_arg = f'"{solc_path}"' if solc_path else "None"
    return f"""
import json, sys

try:
    from slither import Slither
    from slither.core.declarations import Function
except ImportError as e:
    print(json.dumps([{{
        "rule_id": "IMPORT-ERROR",
        "severity": "INFO",
        "contract": "N/A",
        "function": None,
        "description": f"Cannot import slither: {{e}}",
        "source_file": {source_path!r},
    }}]))
    sys.exit(0)

MINT_NAMES = set({mint_names!r})

findings = []

solc_path = {solc_arg}
kwargs = {{"solc": solc_path}} if solc_path else {{}}

try:
    sl = Slither({source_path!r}, **kwargs)
except Exception as e:
    print(json.dumps([{{
        "rule_id": "COMPILE-ERROR",
        "severity": "INFO",
        "contract": "N/A",
        "function": None,
        "description": f"Slither/compilation error: {{e}}",
        "source_file": {source_path!r},
    }}]))
    sys.exit(0)

for contract in sl.contracts:
    for func in contract.functions_and_modifiers:
        func_name = func.name
        # MINT-001: mint function with no access control
        if func_name in MINT_NAMES or any(
            n in func_name.lower() for n in ["mint", "issue"]
        ):
            has_modifier = bool(func.modifiers)
            has_require_owner = any(
                "owner" in str(n).lower() or "role" in str(n).lower() or "only" in str(n).lower()
                for n in (list(func.modifiers) + list(func.nodes))
            )
            if not has_modifier and not has_require_owner:
                _lines = func.source_mapping.lines or []
                findings.append({{
                    "rule_id": "MINT-001",
                    "severity": "CRITICAL",
                    "contract": contract.name,
                    "function": func_name,
                    "description": (
                        f"Function '{{func_name}}' calls mint() without any "
                        "access control check. Any address can inflate token supply."
                    ),
                    "source_file": {source_path!r},
                    "line_start": _lines[0] if _lines else None,
                    "line_end": _lines[-1] if _lines else None,
                    "extra": {{}},
                }})

        # MINT-007: mint without supply cap
        if func_name in MINT_NAMES or "mint" in func_name.lower():
            written_vars = {{str(v) for v in func.state_variables_written}}
            read_vars = {{str(v) for v in func.state_variables_read}}
            has_cap = any(
                kw in v.lower() for v in (written_vars | read_vars)
                for kw in ["cap", "limit", "max", "maximum", "supply"]
            )
            if not has_cap:
                _lines = func.source_mapping.lines or []
                findings.append({{
                    "rule_id": "MINT-007",
                    "severity": "LOW",
                    "contract": contract.name,
                    "function": func_name,
                    "description": (
                        f"mint() in '{{func_name}}' lacks a supply cap check. "
                        "Unrestricted inflation is possible."
                    ),
                    "source_file": {source_path!r},
                    "line_start": _lines[0] if _lines else None,
                    "line_end": _lines[-1] if _lines else None,
                    "extra": {{}},
                }})

        # MINT-004: totalSupply written but inconsistently
        state_written = [str(v) for v in func.state_variables_written]
        if any("totalsupply" in v.lower() or "total_supply" in v.lower() for v in state_written):
            balance_written = any(
                "balance" in v.lower() for v in state_written
            )
            if not balance_written:
                _lines = func.source_mapping.lines or []
                findings.append({{
                    "rule_id": "MINT-004",
                    "severity": "MEDIUM",
                    "contract": contract.name,
                    "function": func_name,
                    "description": (
                        f"totalSupply accounting inconsistency in '{{func_name}}'. "
                        "totalSupply updated without corresponding balance update."
                    ),
                    "source_file": {source_path!r},
                    "line_start": _lines[0] if _lines else None,
                    "line_end": _lines[-1] if _lines else None,
                    "extra": {{}},
                }})

print(json.dumps(findings))
"""
