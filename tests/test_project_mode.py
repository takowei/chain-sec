"""Tests for project-mode compilation and scanning.

Fixture: tests/fixtures/multi_file_project/
  contracts/
    MathLib.sol       — internal library (no findings expected)
    ProjectMint.sol   — imports MathLib + @fakelib node_modules dep;
                        has unguarded mint() -> MINT-001 CRITICAL
  node_modules/
    @fakelib/tokens/contracts/IERC20Mintable.sol  — fake pkg dependency

All tests use solc 0.8.20 (the only version available in this environment).
No hardhat / foundry / npm scripts are executed at any point.
"""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURE_PROJECT = Path(__file__).parent / "fixtures" / "multi_file_project"
FIXTURE_MAIN = FIXTURE_PROJECT / "contracts" / "ProjectMint.sol"


# ---------------------------------------------------------------------------
# project_compiler unit tests
# ---------------------------------------------------------------------------


class TestProjectCompiler:
    def test_version_detection(self, solc_path):
        """pragma solidity ^0.8.20 must resolve to version '0.8.20'."""
        from src.scanners.project_compiler import build_project_context

        if not solc_path:
            pytest.skip("solc not available")

        ctx = build_project_context(FIXTURE_PROJECT, {"0.8.20": solc_path})
        assert ctx.solc_version == "0.8.20"

    def test_node_modules_excluded_from_targets(self, solc_path):
        """Files under node_modules/ must not appear in ctx.sol_files."""
        from src.scanners.project_compiler import build_project_context

        if not solc_path:
            pytest.skip("solc not available")

        ctx = build_project_context(FIXTURE_PROJECT, {"0.8.20": solc_path})
        for f in ctx.sol_files:
            assert "node_modules" not in f.parts, f"node_modules file leaked into scan targets: {f}"

    def test_auto_remapping_generated(self, solc_path):
        """@fakelib/ prefix must appear in auto-generated remappings."""
        from src.scanners.project_compiler import build_project_context

        if not solc_path:
            pytest.skip("solc not available")

        ctx = build_project_context(FIXTURE_PROJECT, {"0.8.20": solc_path})
        assert ctx.remappings, "Expected at least one remapping"
        prefixes = [r.split("=")[0] for r in ctx.remappings]
        assert any("@fakelib" in p for p in prefixes), (
            f"@fakelib not found in remapping prefixes: {prefixes}"
        )

    def test_missing_version_raises(self, solc_path):
        """Requesting a version not in solc_bin_map must raise ValueError."""
        from src.scanners.project_compiler import build_project_context

        if not solc_path:
            pytest.skip("solc not available")

        with pytest.raises(ValueError, match="solc-select install"):
            build_project_context(FIXTURE_PROJECT, {"0.9.99": "/nonexistent/solc"})

    def test_remappings_txt_takes_priority(self, solc_path, tmp_path):
        """If remappings.txt exists it must be used instead of auto-detection."""
        from src.scanners.project_compiler import build_project_context

        if not solc_path:
            pytest.skip("solc not available")

        # Build a minimal project copy with a remappings.txt.
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "remappings.txt").write_text("@custom/=lib/custom/\n")
        # Copy one .sol file so version detection works.
        import shutil

        shutil.copy(FIXTURE_MAIN, proj / "ProjectMint.sol")

        ctx = build_project_context(proj, {"0.8.20": solc_path})
        assert ctx.remappings == ["@custom/=lib/custom/"]


# ---------------------------------------------------------------------------
# End-to-end project scan (requires slither)
# ---------------------------------------------------------------------------


class TestScanProject:
    def test_mint001_detected_in_project(self, slither_scanner):
        """scan_project on the fixture must detect MINT-001 CRITICAL in ProjectMint."""
        result = slither_scanner.scan_project(FIXTURE_PROJECT)

        rule_ids = [f.rule_id for f in result.findings]
        assert "MINT-001" in rule_ids, f"Expected MINT-001 in project findings, got: {rule_ids}"
        mint001 = [f for f in result.findings if f.rule_id == "MINT-001"]
        sev = mint001[0].severity
        assert (sev.value if hasattr(sev, "value") else sev) == "CRITICAL"
        assert mint001[0].contract == "ProjectMint"

    def test_compiled_files_reported(self, slither_scanner):
        """At least one file must appear in compiled_files (not all failed)."""
        result = slither_scanner.scan_project(FIXTURE_PROJECT)
        assert result.compiled_files, f"No files compiled. failed_files: {result.failed_files}"

    def test_node_modules_not_in_compiled_files(self, slither_scanner):
        """node_modules files must never appear as compiled targets."""
        result = slither_scanner.scan_project(FIXTURE_PROJECT)
        for f in result.compiled_files:
            assert "node_modules" not in f.parts, f"node_modules file in compiled_files: {f}"

    def test_remappings_recorded(self, slither_scanner):
        """ScanProjectResult must record the remappings that were applied."""
        result = slither_scanner.scan_project(FIXTURE_PROJECT)
        assert result.remappings_used, "Expected remappings_used to be non-empty"

    def test_solc_version_recorded(self, slither_scanner):
        """ScanProjectResult must record the solc version used."""
        result = slither_scanner.scan_project(FIXTURE_PROJECT)
        assert result.solc_version == "0.8.20"

    def test_missing_solc_version_surfaces_as_info_finding(self, slither_scanner):
        """When the required version is absent, a PROJECT-SOLC-VERSION INFO finding is returned."""
        result = slither_scanner.scan_project(
            FIXTURE_PROJECT,
            solc_bin_map={"0.9.99": "/nonexistent/solc"},
        )
        rule_ids = [f.rule_id for f in result.findings]
        assert "PROJECT-SOLC-VERSION" in rule_ids, (
            f"Expected PROJECT-SOLC-VERSION finding, got: {rule_ids}"
        )


# ---------------------------------------------------------------------------
# CLI --project flag integration
# ---------------------------------------------------------------------------


class TestCliProjectFlag:
    def test_project_flag_exits_1_on_critical(self, slither_scanner, tmp_path):
        """scan.py --project on fixture must exit 1 (CRITICAL found)."""
        import scan

        del slither_scanner  # availability gate only

        code = scan.main(
            [str(FIXTURE_PROJECT), "--project", "--output", str(tmp_path / "findings")]
        )
        assert code == 1, f"Expected exit 1 (critical finding), got {code}"

    def test_project_flag_writes_json(self, slither_scanner, tmp_path):
        """scan.py --project must write a findings JSON named after the project dir."""
        import scan

        del slither_scanner

        out_dir = tmp_path / "findings"
        scan.main([str(FIXTURE_PROJECT), "--project", "--output", str(out_dir)])

        expected = out_dir / "multi_file_project.json"
        assert expected.exists(), f"Expected output file {expected}"

        import json

        data = json.loads(expected.read_text())
        rule_ids = [f["rule_id"] for f in data]
        assert "MINT-001" in rule_ids, f"MINT-001 missing from project JSON: {rule_ids}"

    def test_project_flag_requires_directory(self, slither_scanner, tmp_path):
        """--project with a file path (not directory) must exit 2."""
        import scan

        del slither_scanner

        code = scan.main([str(FIXTURE_MAIN), "--project", "--output", str(tmp_path / "findings")])
        assert code == 2
