"""Tests for scan.py CLI.

Strategy
--------
- Import scan.main() directly so pytest can call it without subprocess.
- Use the existing tests/fixtures/*.sol as input (same files the scanner
  tests use), so we rely on the same known-vulnerable contracts.
- Tests that require slither are gated behind the `slither_scanner` fixture
  (which calls pytest.skip when slither is unavailable).
- Tests for argument parsing and path validation run regardless of slither.
"""

from __future__ import annotations

import json
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def run_scan(argv: list[str]) -> int:
    """Call scan.main() and return its exit code."""
    import scan

    return scan.main(argv)


# ---------------------------------------------------------------------------
# Argument / path validation (no slither needed)
# ---------------------------------------------------------------------------


class TestCliArgValidation:
    def test_missing_path_exits_2(self, tmp_path):
        """Non-existent target path must exit with code 2."""
        code = run_scan([str(tmp_path / "nonexistent.sol")])
        assert code == 2

    def test_no_sol_files_exits_2(self, tmp_path):
        """Directory with no .sol files must exit with code 2."""
        code = run_scan([str(tmp_path)])
        assert code == 2

    def test_non_sol_file_exits_2(self, tmp_path):
        """A file that is not .sol must exit with code 2."""
        f = tmp_path / "readme.txt"
        f.write_text("hello")
        code = run_scan([str(f)])
        assert code == 2


# ---------------------------------------------------------------------------
# End-to-end scan (requires slither)
# ---------------------------------------------------------------------------


class TestCliEndToEnd:
    def test_unguarded_mint_exits_1(self, slither_scanner, tmp_path):
        """Scanning UnguardedMint.sol must find CRITICAL and exit 1."""
        # slither_scanner fixture ensures slither is available; use it
        # as a gate only — scan.py builds its own scanner internally.
        del slither_scanner  # used as availability gate

        code = run_scan(
            [
                str(FIXTURES_DIR / "UnguardedMint.sol"),
                "--output",
                str(tmp_path / "findings"),
            ]
        )
        assert code == 1, "Expected exit 1 (critical/high found)"

        out_file = tmp_path / "findings" / "UnguardedMint.json"
        assert out_file.exists(), f"findings JSON not created at {out_file}"

        data = json.loads(out_file.read_text())
        rule_ids = [f["rule_id"] for f in data]
        assert "MINT-001" in rule_ids, f"MINT-001 missing from {rule_ids}"

        critical = [f for f in data if f["rule_id"] == "MINT-001"]
        assert critical[0]["severity"] == "CRITICAL"
        assert critical[0]["contract"] == "UnguardedMint"

    def test_no_cap_exits_0_or_1(self, slither_scanner, tmp_path):
        """NoCap.sol has LOW finding only — CLI must write the JSON and NOT exit 2."""
        del slither_scanner

        code = run_scan(
            [
                str(FIXTURES_DIR / "NoCap.sol"),
                "--output",
                str(tmp_path / "findings"),
            ]
        )
        # Exit 0 = no critical/high; exit 1 = some critical/high.
        # Either is acceptable here — what we verify is the JSON is written.
        assert code in (0, 1), f"Unexpected exit code {code}"

        out_file = tmp_path / "findings" / "NoCap.json"
        assert out_file.exists(), "findings JSON for NoCap.sol not created"
        data = json.loads(out_file.read_text())
        rule_ids = [f["rule_id"] for f in data]
        assert "MINT-007" in rule_ids, f"MINT-007 missing from {rule_ids}"

    def test_directory_scan(self, slither_scanner, tmp_path):
        """Scanning a directory must produce one JSON per .sol file."""
        del slither_scanner

        code = run_scan(
            [
                str(FIXTURES_DIR),
                "--output",
                str(tmp_path / "findings"),
            ]
        )
        assert code in (0, 1, 2), f"Unexpected exit code {code}"

        out_dir = tmp_path / "findings"
        # All three fixtures should have produced output files.
        expected = {"UnguardedMint.json", "NoCap.json", "SupplyMismatch.json"}
        produced = {f.name for f in out_dir.glob("*.json")}
        assert expected.issubset(produced), f"Missing output files: {expected - produced}"

    def test_supply_mismatch_produces_mint004(self, slither_scanner, tmp_path):
        """SupplyMismatch.sol must produce MINT-004 (MEDIUM) finding."""
        del slither_scanner

        run_scan(
            [
                str(FIXTURES_DIR / "SupplyMismatch.sol"),
                "--output",
                str(tmp_path / "findings"),
            ]
        )
        out_file = tmp_path / "findings" / "SupplyMismatch.json"
        assert out_file.exists()
        data = json.loads(out_file.read_text())
        rule_ids = [f["rule_id"] for f in data]
        assert "MINT-004" in rule_ids, f"MINT-004 missing from {rule_ids}"


class TestCompileFailureIsNotClean:
    def test_compile_error_exits_4(self, tmp_path, monkeypatch):
        """A file that fails to compile must not exit 0 (clean)."""
        import scan
        from src.scanners.models import Finding, Severity

        class FailingScanner:
            available = True

            def scan(self, path):
                return [
                    Finding(
                        rule_id="COMPILE-ERROR",
                        severity=Severity.INFO,
                        contract="",
                        function=None,
                        description="solc not found",
                        source_file=str(path),
                    )
                ]

        monkeypatch.setattr(scan, "_build_scanner", FailingScanner)
        code = run_scan([str(FIXTURES_DIR / "UnguardedMint.sol"), "--output", str(tmp_path / "f")])
        assert code == 4
