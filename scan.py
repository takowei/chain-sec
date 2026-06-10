"""scan.py — End-to-end CLI for chain-sec static analysis.

Usage
-----
    python scan.py <solidity_file_or_directory> [options]

Examples
--------
    python scan.py contracts/Token.sol
    python scan.py path/to/cloned/repo/
    python scan.py tests/fixtures/UnguardedMint.sol --output findings/

The CLI:
  1. Discovers .sol files under the given path.
  2. Runs SlitherScanner (built-in detectors + custom mint-pattern rules).
  3. Writes one findings JSON per input file to the output directory.
  4. Prints a severity summary to stdout.
  5. Exits 0 when no critical/high findings, 1 otherwise.

Red-line constraints (RULES-OF-ENGAGEMENT.md):
  - No network requests are made.
  - No mainnet/RPC interaction.
  - Analysis is read-only on local source files only.
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
from src.scanners.slither_wrapper import SlitherScanner

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

    sol_files = _discover_sol_files(target_path)
    if not sol_files:
        print(f"[scan] No .sol files found under {target_path}", file=sys.stderr)
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
