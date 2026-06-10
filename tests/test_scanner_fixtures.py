"""Tests verifying scanner detection against known-vulnerable Solidity fixtures.

Each fixture file is crafted to trigger exactly one MINT-* rule.
Tests assert:
  - The expected rule_id is present in findings.
  - The reported severity matches the rule definition.
"""

from __future__ import annotations

from pathlib import Path

from src.scanners.models import Severity

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestMintRuleDetection:
    """Custom mint-pattern rules against deliberate fixture contracts."""

    def test_mint001_unguarded_mint(self, slither_scanner):
        """MINT-001 CRITICAL: mint() with no access control must be detected."""
        findings = slither_scanner._run_custom_mint_rules(FIXTURES_DIR / "UnguardedMint.sol")
        rule_ids = [f.rule_id for f in findings]
        assert "MINT-001" in rule_ids, f"Expected MINT-001 in {rule_ids}"

        critical = [f for f in findings if f.rule_id == "MINT-001"]
        assert critical[0].severity == Severity.CRITICAL
        assert critical[0].contract == "UnguardedMint"
        assert critical[0].function == "mint"

    def test_mint007_no_supply_cap(self, slither_scanner):
        """MINT-007 LOW: mint() without any cap/limit variable must be detected."""
        findings = slither_scanner._run_custom_mint_rules(FIXTURES_DIR / "NoCap.sol")
        rule_ids = [f.rule_id for f in findings]
        assert "MINT-007" in rule_ids, f"Expected MINT-007 in {rule_ids}"

        low = [f for f in findings if f.rule_id == "MINT-007"]
        assert low[0].severity == Severity.LOW
        assert low[0].contract == "NoCap"

    def test_mint004_supply_mismatch(self, slither_scanner):
        """MINT-004 MEDIUM: totalSupply updated without balance update must be detected."""
        findings = slither_scanner._run_custom_mint_rules(FIXTURES_DIR / "SupplyMismatch.sol")
        rule_ids = [f.rule_id for f in findings]
        assert "MINT-004" in rule_ids, f"Expected MINT-004 in {rule_ids}"

        medium = [f for f in findings if f.rule_id == "MINT-004"]
        assert medium[0].severity == Severity.MEDIUM
        assert medium[0].contract == "SupplyMismatch"

    def test_guarded_mint_no_mint001(self, slither_scanner):
        """NoCap.sol has onlyOwner — MINT-001 must NOT fire (false-positive guard)."""
        findings = slither_scanner._run_custom_mint_rules(FIXTURES_DIR / "NoCap.sol")
        rule_ids = [f.rule_id for f in findings]
        assert "MINT-001" not in rule_ids, (
            f"MINT-001 should not fire on owner-gated mint, but got {rule_ids}"
        )

    def test_interface_mint_no_mint001(self, slither_scanner):
        """Interface declaration has no body — MINT-001 must NOT fire."""
        findings = slither_scanner._run_custom_mint_rules(FIXTURES_DIR / "InterfaceMint.sol")
        mint001 = [f for f in findings if f.rule_id == "MINT-001"]
        assert mint001 == [], (
            f"MINT-001 must not fire on interface declarations, but fired on: "
            f"{[(f.contract, f.function) for f in mint001]}"
        )

    def test_view_pure_mint_no_mint001(self, slither_scanner):
        """view/pure functions cannot mutate state — MINT-001 must NOT fire."""
        findings = slither_scanner._run_custom_mint_rules(FIXTURES_DIR / "ViewMint.sol")
        mint001 = [f for f in findings if f.rule_id == "MINT-001"]
        assert mint001 == [], (
            f"MINT-001 must not fire on view/pure functions, but fired on: "
            f"{[(f.contract, f.function) for f in mint001]}"
        )

    def test_abstract_mint_no_mint001(self, slither_scanner):
        """Abstract (unimplemented) function declaration — MINT-001 must NOT fire."""
        findings = slither_scanner._run_custom_mint_rules(FIXTURES_DIR / "AbstractMint.sol")
        mint001 = [f for f in findings if f.rule_id == "MINT-001"]
        assert mint001 == [], (
            f"MINT-001 must not fire on abstract declarations, but fired on: "
            f"{[(f.contract, f.function) for f in mint001]}"
        )

    def test_internal_mint_no_mint001(self, slither_scanner):
        """Internal/private mint helpers — MINT-001 must NOT fire (not externally callable)."""
        findings = slither_scanner._run_custom_mint_rules(FIXTURES_DIR / "InternalMint.sol")
        mint001 = [f for f in findings if f.rule_id == "MINT-001"]
        assert mint001 == [], (
            f"MINT-001 must not fire on internal/private mint functions, but fired on: "
            f"{[(f.contract, f.function) for f in mint001]}"
        )
