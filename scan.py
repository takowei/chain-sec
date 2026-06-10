"""scan.py — End-to-end CLI for chain-sec static analysis.

Usage
-----
    python scan.py <solidity_file_or_directory> [options]
    python scan.py <project_directory> --project [options]

Examples
--------
    python scan.py contracts/Token.sol
    python scan.py path/to/cloned/repo/
    python scan.py tests/fixtures/UnguardedMint.sol --output findings/
    python scan.py tests/fixtures/multi_file_project/ --project --output findings/

The CLI:
  1. Discovers .sol files under the given path.
  2. Runs SlitherScanner (built-in detectors + custom mint-pattern rules).
  3. Writes one findings JSON per input file to the output directory.
  4. Prints a severity summary to stdout.
  5. Exits 0 when no critical/high findings, 1 otherwise.

Project mode (--project):
  Handles multi-file projects with imports and node_modules.  Automatically
  generates remappings, selects the correct solc version from pragma, and
  drives solc directly — no hardhat / foundry / npm scripts are executed.
  (RULES-OF-ENGAGEMENT.md §8 compliance.)

Red-line constraints (RULES-OF-ENGAGEMENT.md):
  - No network requests are made.
  - No mainnet/RPC interaction.
  - Analysis is read-only on local source files only.
  - Target build scripts are never executed.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

# Allow running from project root without installing the package.
sys.path.insert(0, str(Path(__file__).parent))

from src.scanners.models import Severity
from src.scanners.slither_wrapper import ScanProjectResult, SlitherScanner

logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)s  %(name)s: %(message)s",
)
logger = logging.getLogger("scan")

_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def _discover_sol_files(path: Path) -> list[Path]:
    """Return all .sol files under *path* (file or directory)."""
    if path.is_file():
        if path.suffix == ".sol":
            return [path]
        print(f"[scan] Warning: {path} is not a .sol file — skipping.", file=sys.stderr)
        return []
    return sorted(path.rglob("*.sol"))


def _build_scanner() -> SlitherScanner:
    """Construct SlitherScanner using env-var or PATH-discovered solc."""
    solc_env = os.environ.get("CHAIN_SEC_SOLC", "")
    solc_path: str | None = solc_env if solc_env and Path(solc_env).is_file() else None
    return SlitherScanner(solc_path=solc_path)


def _write_findings(findings: list, output_dir: Path, stem: str) -> Path:
    """Write findings list to JSON and return the output path."""
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / f"{stem}.json"
    payload = [f.to_dict() if hasattr(f, "to_dict") else f for f in findings]
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    return out_path


def _severity_counts(findings: list) -> dict[str, int]:
    counts: dict[str, int] = {s.value: 0 for s in Severity}
    for f in findings:
        sev = f.severity if isinstance(f.severity, str) else f.severity.value
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _print_summary(sol_file: Path, findings: list, out_path: Path) -> None:
    counts = _severity_counts(findings)
    total = sum(counts.values())
    parts = "  ".join(
        f"{sev}: {counts[sev]}"
        for sev in [s.value for s in _SEVERITY_ORDER]
        if counts.get(sev, 0) > 0
    )
    print(f"[{sol_file.name}] {total} finding(s)  {parts or 'none'}")
    print(f"  -> {out_path}")


def _has_critical_or_high(findings: list) -> bool:
    for f in findings:
        sev = f.severity if isinstance(f.severity, str) else f.severity.value
        if sev in (Severity.CRITICAL.value, Severity.HIGH.value):
            return True
    return False


# ---------------------------------------------------------------------------
# Project mode
# ---------------------------------------------------------------------------


def _run_project_mode(
    target_path: Path,
    output_dir: Path,
    scanner: SlitherScanner,
) -> int:
    """Run project-mode scan; return exit code (0/1/3)."""
    print(f"[scan] Project mode: {target_path}")

    # Build solc_bin_map from the scanner's configured solc binary.
    solc_bin_map: dict[str, str] | None = None
    if scanner.solc_path:
        from src.scanners.slither_wrapper import _solc_version_string

        ver = _solc_version_string(scanner.solc_path)
        if ver:
            solc_bin_map = {ver: scanner.solc_path}

    result: ScanProjectResult = scanner.scan_project(target_path, solc_bin_map=solc_bin_map)

    # Report compile failures.
    if result.failed_files:
        print(
            f"[scan] {len(result.failed_files)} file(s) failed to compile (skipped from findings):"
        )
        for fpath, reason in result.failed_files.items():
            print(f"  SKIP  {fpath.name}: {reason[:100]}")

    # Write combined findings JSON.
    project_name = target_path.name or "project"
    out_path = _write_findings(result.findings, output_dir, project_name)

    counts = _severity_counts(result.findings)
    total = sum(counts.values())
    parts = "  ".join(
        f"{sev}: {counts[sev]}"
        for sev in [s.value for s in _SEVERITY_ORDER]
        if counts.get(sev, 0) > 0
    )
    print(f"[scan] Project findings: {total}  {parts or 'none'}")
    print(f"[scan] Compiled: {len(result.compiled_files)} file(s)")
    if result.remappings_used:
        print(f"[scan] Remappings: {len(result.remappings_used)} active")
    print(f"[scan] solc version: {result.solc_version or '(unknown)'}")
    print(f"[scan] Output: {out_path}")

    return 1 if _has_critical_or_high(result.findings) else 0


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="scan.py",
        description="Run static analysis on Solidity source files.",
    )
    parser.add_argument(
        "target",
        help="Path to a .sol file or a directory containing .sol files.",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="findings",
        help="Directory where findings JSON files are written (default: findings/).",
    )
    parser.add_argument(
        "--project",
        "-p",
        action="store_true",
        help=(
            "Enable project mode: auto-detect remappings from node_modules/, "
            "select solc version from pragma, compile with explicit solc — "
            "never calls hardhat/foundry/npm scripts."
        ),
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging.",
    )
    args = parser.parse_args(argv)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    target_path = Path(args.target).resolve()
    if not target_path.exists():
        print(f"[scan] Error: path does not exist: {target_path}", file=sys.stderr)
        return 2

    output_dir = Path(args.output).resolve()
    scanner = _build_scanner()

    if not scanner.available:
        print(
            "[scan] Error: Slither is not available in the current environment.\n"
            "  Run: bash scripts/setup-env.sh && source ~/.chain-sec-venv/bin/activate",
            file=sys.stderr,
        )
        return 3

    # --project: delegate entirely to project mode.
    if args.project:
        if not target_path.is_dir():
            print(
                f"[scan] Error: --project requires a directory, got: {target_path}",
                file=sys.stderr,
            )
            return 2
        return _run_project_mode(target_path, output_dir, scanner)

    # Standard file/directory mode.
    sol_files = _discover_sol_files(target_path)
    if not sol_files:
        print(f"[scan] No .sol files found under {target_path}", file=sys.stderr)
        return 2

    found_critical_or_high = False
    total_findings = 0

    for sol_file in sol_files:
        findings = scanner.scan(sol_file)
        out_path = _write_findings(findings, output_dir, sol_file.stem)
        _print_summary(sol_file, findings, out_path)
        total_findings += len(findings)
        if _has_critical_or_high(findings):
            found_critical_or_high = True

    print(f"\n[scan] Scanned {len(sol_files)} file(s), {total_findings} finding(s) total.")
    print(f"[scan] Output dir: {output_dir}")

    return 1 if found_critical_or_high else 0


if __name__ == "__main__":
    sys.exit(main())
