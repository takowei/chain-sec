"""Mythril-based scanner as a second-opinion tool.

Mythril performs symbolic execution to find vulnerabilities. It is optional;
if not installed the scanner degrades gracefully with an INFO finding.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from pathlib import Path

from .models import Finding, Severity

logger = logging.getLogger(__name__)

_MYTHRIL_SEVERITY_MAP: dict[str, Severity] = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
}


class MythrilScanner:
    """
    Wraps the Mythril CLI (myth) for symbolic-execution-based analysis.

    Mythril is treated as an optional second opinion. If unavailable the
    scan returns a single INFO finding documenting the gap.

    Parameters
    ----------
    pip_target:
        Directory where mythril was installed via pip --target.
    solc_path:
        Explicit path to the solc binary.
    timeout:
        Per-contract analysis timeout in seconds (default 60).
    """

    def __init__(
        self,
        pip_target: str | None = None,
        solc_path: str | None = None,
        timeout: int = 60,
    ) -> None:
        self.pip_target = pip_target
        self.solc_path = solc_path
        self.timeout = timeout
        self._available = self._check_available()

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

    def _check_available(self) -> bool:
        try:
            result = subprocess.run(
                [sys.executable, "-c", "import mythril; print('ok')"],
                capture_output=True,
                text=True,
                env=self._build_env(),
                timeout=10,
            )
            return result.returncode == 0 and "ok" in result.stdout
        except Exception as exc:
            logger.debug("Mythril availability check failed: %s", exc)
            return False

    @property
    def available(self) -> bool:
        return self._available

    def scan(self, source_path: str | Path) -> list[Finding]:
        """
        Run Mythril on a Solidity source file.

        Returns list of Finding objects. Errors are caught and returned as
        INFO-level findings so the caller always gets a usable result.
        """
        source_path = Path(source_path)

        if not self._available:
            return [
                Finding(
                    rule_id="MYTHRIL-UNAVAILABLE",
                    severity=Severity.INFO,
                    contract="N/A",
                    function=None,
                    description=("Mythril is not installed. Install with: pip install mythril"),
                    source_file=str(source_path),
                )
            ]

        if not source_path.exists():
            logger.error("Source path does not exist: %s", source_path)
            return []

        return self._run_myth_json(source_path)

    def _run_myth_json(self, source_path: Path) -> list[Finding]:
        """Invoke myth analyze --solv ... --output json and parse results."""
        cmd = [
            sys.executable,
            "-m",
            "mythril.interfaces.cli",
            "analyze",
            str(source_path),
            "--output",
            "json",
            "--execution-timeout",
            str(self.timeout),
        ]
        if self.solc_path:
            cmd += ["--solv", self.solc_path]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=self._build_env(),
                timeout=self.timeout + 30,
            )
            if result.stdout.strip():
                return self._parse_myth_json(result.stdout, str(source_path))
            if result.returncode not in (0, 1):
                logger.warning("Mythril exited %d: %s", result.returncode, result.stderr[:400])
        except subprocess.TimeoutExpired:
            logger.warning("Mythril timed out on %s", source_path)
        except Exception as exc:
            logger.warning("Mythril run failed: %s", exc)
        return []

    def _parse_myth_json(self, raw_json: str, source_file: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError as exc:
            logger.warning("Failed to parse Mythril JSON: %s", exc)
            return findings

        for issue in data.get("issues", []):
            severity = _MYTHRIL_SEVERITY_MAP.get(issue.get("severity", ""), Severity.INFO)
            findings.append(
                Finding(
                    rule_id=f"MYTHRIL-{issue.get('swc-id', 'UNKNOWN')}",
                    severity=severity,
                    contract=issue.get("contract", "Unknown"),
                    function=issue.get("function"),
                    description=issue.get("description", "").strip(),
                    source_file=source_file,
                    line_start=issue.get("lineno"),
                    extra={
                        "swc_id": issue.get("swc-id"),
                        "title": issue.get("title"),
                    },
                )
            )
        return findings
