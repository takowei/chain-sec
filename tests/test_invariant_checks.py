"""Tests for supply-accounting invariant checks (INV-001/002/003).

Each rule has a positive fixture (should fire) and a negative fixture
(should NOT fire).  All tests require Slither and solc to be available;
they are skipped automatically if not.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.scanners.models import Severity

FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_slither(fixture_name: str, solc_path: str | None):
    """Compile a fixture file with Slither; return the Slither instance."""
    from slither import Slither

    path = str(FIXTURES_DIR / fixture_name)
    kwargs = {}
    if solc_path:
        kwargs["solc"] = solc_path
    return Slither(path, **kwargs)


def _run(fixture_name: str, solc_path: str | None):
    """Return all invariant findings for a fixture file."""
    from src.scanners.invariant_checks import run_invariant_checks

    sl = _load_slither(fixture_name, solc_path)
    return run_invariant_checks(sl)


# ---------------------------------------------------------------------------
# INV-001 — Asymmetric paired-token mint/burn
# ---------------------------------------------------------------------------


class TestInv001AsymmetricPairedMint:
    """INV-001 detects single-sided mint or burn without matching partner."""

    def test_positive_asymmetric_mint_fires(self, solc_path):
        """A function that mints PT but never YT must trigger INV-001."""
        findings = _run("inv001_asymmetric_mint_pos.sol", solc_path)
        inv001 = [f for f in findings if f.rule_id == "INV-001"]
        assert inv001, f"Expected INV-001 but got: {[f.rule_id for f in findings]}"
        hit = inv001[0]
        assert hit.severity == Severity.MEDIUM
        assert hit.contract == "AsymmetricMintPos"
        assert hit.function == "mintPT"
        assert "mint" in hit.description.lower()

    def test_negative_symmetric_mint_does_not_fire(self, solc_path):
        """A function minting both PT and YT must NOT trigger INV-001."""
        findings = _run("inv001_symmetric_mint_neg.sol", solc_path)
        inv001 = [f for f in findings if f.rule_id == "INV-001"]
        assert inv001 == [], (
            f"INV-001 must not fire on symmetric PT+YT mint, but fired on: "
            f"{[(f.contract, f.function) for f in inv001]}"
        )

    def test_inv001_rule_id_prefix(self, solc_path):
        """INV-001 findings must use the INV-* rule_id prefix."""
        findings = _run("inv001_asymmetric_mint_pos.sol", solc_path)
        for f in findings:
            assert f.rule_id.startswith("INV-") or not f.rule_id.startswith("MINT-"), (
                f"Invariant findings must use INV-* prefix, got: {f.rule_id}"
            )

    def test_inv001_can_be_disabled(self, solc_path):
        """INV-001 can be suppressed via enable_inv001=False."""
        from src.scanners.invariant_checks import run_invariant_checks

        sl = _load_slither("inv001_asymmetric_mint_pos.sol", solc_path)
        findings = run_invariant_checks(sl, enable_inv001=False)
        inv001 = [f for f in findings if f.rule_id == "INV-001"]
        assert inv001 == [], "INV-001 should produce no findings when disabled"


# ---------------------------------------------------------------------------
# INV-002 — Rounding direction favours user
# ---------------------------------------------------------------------------


class TestInv002RoundingFavoursUser:
    """INV-002 detects ceil-in-mint or floor-in-redeem wrong-direction rounding."""

    def test_positive_ceil_in_mint_fires(self, solc_path):
        """A mint function using divUp (ceil) for amountOut must trigger INV-002."""
        findings = _run("inv002_ceil_to_user_pos.sol", solc_path)
        inv002 = [f for f in findings if f.rule_id == "INV-002"]
        assert inv002, f"Expected INV-002 but got: {[f.rule_id for f in findings]}"
        hit = inv002[0]
        assert hit.severity == Severity.MEDIUM
        assert hit.contract == "CeilToUserPos"
        assert hit.function == "mint"
        assert "ceil" in hit.description.lower() or "divup" in hit.description.lower()

    def test_negative_floor_in_mint_does_not_fire(self, solc_path):
        """A mint function using divDown (floor) must NOT trigger INV-002."""
        findings = _run("inv002_floor_to_user_neg.sol", solc_path)
        inv002 = [f for f in findings if f.rule_id == "INV-002"]
        assert inv002 == [], (
            f"INV-002 must not fire on floor-in-mint path, but fired on: "
            f"{[(f.contract, f.function) for f in inv002]}"
        )

    def test_inv002_extra_contains_rounding_info(self, solc_path):
        """INV-002 finding's extra dict must include 'rounding' and 'call' keys."""
        findings = _run("inv002_ceil_to_user_pos.sol", solc_path)
        inv002 = [f for f in findings if f.rule_id == "INV-002"]
        assert inv002
        extra = inv002[0].extra
        assert "rounding" in extra, f"Missing 'rounding' in extra: {extra}"
        assert "call" in extra, f"Missing 'call' in extra: {extra}"
        assert extra["rounding"] == "ceil"

    def test_inv002_can_be_disabled(self, solc_path):
        """INV-002 can be suppressed via enable_inv002=False."""
        from src.scanners.invariant_checks import run_invariant_checks

        sl = _load_slither("inv002_ceil_to_user_pos.sol", solc_path)
        findings = run_invariant_checks(sl, enable_inv002=False)
        inv002 = [f for f in findings if f.rule_id == "INV-002"]
        assert inv002 == [], "INV-002 should produce no findings when disabled"


# ---------------------------------------------------------------------------
# INV-003 — Mint amount depends on spot rate
# ---------------------------------------------------------------------------


class TestInv003SpotRateDependency:
    """INV-003 detects mint functions that compute amounts from manipulable sources."""

    def test_positive_chainlink_spot_fires(self, solc_path):
        """A mint function calling latestRoundData must trigger INV-003."""
        findings = _run("inv003_spot_rate_pos.sol", solc_path)
        inv003 = [f for f in findings if f.rule_id == "INV-003"]
        assert inv003, f"Expected INV-003 but got: {[f.rule_id for f in findings]}"
        hit = inv003[0]
        assert hit.severity == Severity.MEDIUM
        assert hit.contract == "SpotRateMintPos"
        assert hit.function == "mint"
        assert "latestrounddata" in hit.description.lower()

    def test_negative_stored_index_does_not_fire(self, solc_path):
        """A mint function using a stored index state var must NOT trigger INV-003."""
        findings = _run("inv003_stored_index_neg.sol", solc_path)
        inv003 = [f for f in findings if f.rule_id == "INV-003"]
        assert inv003 == [], (
            f"INV-003 must not fire on stored-index mint path, but fired on: "
            f"{[(f.contract, f.function) for f in inv003]}"
        )

    def test_inv003_extra_contains_spot_call(self, solc_path):
        """INV-003 finding's extra dict must include 'spot_call'."""
        findings = _run("inv003_spot_rate_pos.sol", solc_path)
        inv003 = [f for f in findings if f.rule_id == "INV-003"]
        assert inv003
        extra = inv003[0].extra
        assert "spot_call" in extra, f"Missing 'spot_call' in extra: {extra}"

    def test_inv003_can_be_disabled(self, solc_path):
        """INV-003 can be suppressed via enable_inv003=False."""
        from src.scanners.invariant_checks import run_invariant_checks

        sl = _load_slither("inv003_spot_rate_pos.sol", solc_path)
        findings = run_invariant_checks(sl, enable_inv003=False)
        inv003 = [f for f in findings if f.rule_id == "INV-003"]
        assert inv003 == [], "INV-003 should produce no findings when disabled"


# ---------------------------------------------------------------------------
# Cross-rule: existing MINT-* tests must not be broken
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fixture,expected_absent",
    [
        ("UnguardedMint.sol", ["INV-001", "INV-002", "INV-003"]),
        ("NoCap.sol", ["INV-002", "INV-003"]),
    ],
)
def test_invariant_rules_do_not_pollute_existing_fixtures(fixture, expected_absent, solc_path):
    """INV-* rules must not fire on the original MINT-* test fixtures."""
    findings = _run(fixture, solc_path)
    for rule in expected_absent:
        hits = [f for f in findings if f.rule_id == rule]
        assert hits == [], (
            f"{rule} should not fire on {fixture}, but fired: "
            f"{[(f.contract, f.function) for f in hits]}"
        )
