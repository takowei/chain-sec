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


# ---------------------------------------------------------------------------
# Constraint-parsing unit tests
# ---------------------------------------------------------------------------


class TestConstraintParsing:
    """Unit tests for semver constraint parsing helpers in project_compiler."""

    def test_parse_caret(self):
        from src.scanners.project_compiler import _parse_pragma_constraints

        assert _parse_pragma_constraints("^0.8.20") == [("^", "0.8.20")]

    def test_parse_gte_lt_range(self):
        from src.scanners.project_compiler import _parse_pragma_constraints

        result = _parse_pragma_constraints(">=0.8.0 <0.9.0")
        assert result == [(">=", "0.8.0"), ("<", "0.9.0")]

    def test_parse_bare_version(self):
        from src.scanners.project_compiler import _parse_pragma_constraints

        assert _parse_pragma_constraints("0.8.20") == [("", "0.8.20")]

    def test_parse_exact(self):
        from src.scanners.project_compiler import _parse_pragma_constraints

        assert _parse_pragma_constraints("=0.8.17") == [("=", "0.8.17")]

    def test_caret_upper_nonzero_major(self):
        from src.scanners.project_compiler import _version_satisfies

        # ^1.2.3 → >=1.2.3 <2.0.0
        assert _version_satisfies("1.9.9", "^", "1.2.3") is True
        assert _version_satisfies("2.0.0", "^", "1.2.3") is False

    def test_caret_upper_zero_major(self):
        from src.scanners.project_compiler import _version_satisfies

        # ^0.8.20 → >=0.8.20 <0.9.0 (npm/Solidity semantics)
        assert _version_satisfies("0.8.20", "^", "0.8.20") is True
        assert _version_satisfies("0.8.30", "^", "0.8.20") is True
        assert _version_satisfies("0.9.0", "^", "0.8.20") is False
        assert _version_satisfies("0.8.19", "^", "0.8.20") is False

    def test_caret_upper_zero_minor(self):
        from src.scanners.project_compiler import _version_satisfies

        # ^0.0.5 → >=0.0.5 <0.0.6
        assert _version_satisfies("0.0.5", "^", "0.0.5") is True
        assert _version_satisfies("0.0.6", "^", "0.0.5") is False

    def test_gte_operator(self):
        from src.scanners.project_compiler import _version_satisfies

        assert _version_satisfies("0.8.23", ">=", "0.8.0") is True
        assert _version_satisfies("0.7.9", ">=", "0.8.0") is False

    def test_lt_operator(self):
        from src.scanners.project_compiler import _version_satisfies

        assert _version_satisfies("0.8.29", "<", "0.9.0") is True
        assert _version_satisfies("0.9.0", "<", "0.9.0") is False


# ---------------------------------------------------------------------------
# Version selection unit tests
# ---------------------------------------------------------------------------


class TestVersionSelection:
    """Unit tests for _pick_best_version and _constraints_lower_bound."""

    def test_pick_highest_satisfying(self):
        from src.scanners.project_compiler import _pick_best_version

        constraints = [("^", "0.8.0")]
        # 0.8.30 > 0.8.20, both satisfy ^0.8.0; highest wins
        result = _pick_best_version(constraints, ["0.8.30", "0.8.20"])
        assert result == "0.8.30"

    def test_pick_none_when_all_fail(self):
        from src.scanners.project_compiler import _pick_best_version

        constraints = [("^", "0.8.0")]
        assert _pick_best_version(constraints, ["0.9.0", "0.7.6"]) == ""

    def test_pick_satisfies_combined_constraints(self):
        from src.scanners.project_compiler import _pick_best_version

        # >=0.8.17 <0.9.0 — 0.8.20 satisfies, 0.8.16 does not
        constraints = [(">=", "0.8.17"), ("<", "0.9.0")]
        assert _pick_best_version(constraints, ["0.8.20", "0.8.16"]) == "0.8.20"
        assert _pick_best_version(constraints, ["0.8.16"]) == ""

    def test_lower_bound_from_caret(self):
        from src.scanners.project_compiler import _constraints_lower_bound

        assert _constraints_lower_bound([("^", "0.8.23")]) == "0.8.23"

    def test_lower_bound_from_gte(self):
        from src.scanners.project_compiler import _constraints_lower_bound

        assert _constraints_lower_bound([(">=", "0.8.17")]) == "0.8.17"

    def test_lower_bound_tightest_wins(self):
        from src.scanners.project_compiler import _constraints_lower_bound

        # Mix of ^0.8.0 and >=0.8.17; tightest lower bound is 0.8.17
        result = _constraints_lower_bound([("^", "0.8.0"), (">=", "0.8.17")])
        assert result == "0.8.17"


# ---------------------------------------------------------------------------
# Artifacts discovery unit tests
# ---------------------------------------------------------------------------


class TestArtifactsDiscovery:
    """Unit tests for _discover_solc_bin_map in scan.py."""

    def test_discovers_venv_artifacts(self, tmp_path):
        """Binaries under $VIRTUAL_ENV/.solc-select/artifacts/ are found."""
        import os
        import stat
        from unittest.mock import patch

        import scan

        # Create a fake solc binary tree
        art_dir = tmp_path / ".solc-select" / "artifacts" / "solc-0.8.99" / "solc-0.8.99"
        art_dir.parent.mkdir(parents=True)
        art_dir.write_text("#!/bin/sh\necho 'solc, the solidity compiler version 0.8.99'\n")
        art_dir.chmod(art_dir.stat().st_mode | stat.S_IEXEC)

        with patch.dict(os.environ, {"VIRTUAL_ENV": str(tmp_path)}):
            bin_map = scan._discover_solc_bin_map()

        assert "0.8.99" in bin_map, f"Expected 0.8.99 in {bin_map}"
        assert bin_map["0.8.99"] == str(art_dir)

    def test_non_executable_ignored(self, tmp_path):
        """Non-executable files inside artifact dirs are not included."""
        import os
        from unittest.mock import patch

        import scan

        art_dir = tmp_path / ".solc-select" / "artifacts" / "solc-0.8.99" / "solc-0.8.99"
        art_dir.parent.mkdir(parents=True)
        art_dir.write_text("not a real binary")
        # Do NOT set executable bit

        with patch.dict(os.environ, {"VIRTUAL_ENV": str(tmp_path)}):
            bin_map = scan._discover_solc_bin_map()

        assert "0.8.99" not in bin_map

    def test_real_venv_artifacts_found(self):
        """The actual installed solc-0.8.20 and solc-0.8.30 are discovered."""
        import scan

        bin_map = scan._discover_solc_bin_map()
        assert bin_map, "Expected at least one solc binary discovered from venv artifacts"
        # Both installed versions should be present
        for expected_ver in ("0.8.20", "0.8.30"):
            assert expected_ver in bin_map, (
                f"Expected solc {expected_ver} in discovered map {bin_map}"
            )
