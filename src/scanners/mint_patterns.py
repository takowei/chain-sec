"""Mint/supply vulnerability pattern rules for Slither-based detection."""

from dataclasses import dataclass

from .models import Severity


@dataclass(frozen=True)
class MintRule:
    """Definition of a single mint-pattern detection rule."""

    rule_id: str
    severity: Severity
    description_template: str
    slither_detector: str | None = None  # maps to Slither built-in detector name


# Rules ordered from highest to lowest severity.
MINT_RULES: list[MintRule] = [
    MintRule(
        rule_id="MINT-001",
        severity=Severity.CRITICAL,
        description_template=(
            "Function '{func}' calls mint() without any access control check. "
            "Any address can inflate token supply."
        ),
        slither_detector=None,  # custom logic in SlitherScanner
    ),
    MintRule(
        rule_id="MINT-002",
        severity=Severity.HIGH,
        description_template=(
            "Function '{func}' mints tokens inside a reentrancy-unsafe pattern. "
            "Reentrant calls may produce duplicate mint."
        ),
        slither_detector="reentrancy-eth",
    ),
    MintRule(
        rule_id="MINT-003",
        severity=Severity.HIGH,
        description_template=(
            "Integer overflow/underflow detected near mint operation in '{func}'. "
            "Unchecked arithmetic may allow supply to wrap around."
        ),
        slither_detector="tautology",
    ),
    MintRule(
        rule_id="MINT-004",
        severity=Severity.MEDIUM,
        description_template=(
            "totalSupply accounting inconsistency detected in '{func}'. "
            "Minted amount may diverge from recorded totalSupply."
        ),
        slither_detector=None,
    ),
    MintRule(
        rule_id="MINT-005",
        severity=Severity.MEDIUM,
        description_template=(
            "onlyOwner/role modifier present but bypassable via '{func}'. "
            "Access control may be circumvented."
        ),
        slither_detector="suicidal",
    ),
    MintRule(
        rule_id="MINT-006",
        severity=Severity.HIGH,
        description_template=(
            "Proxy/upgradeable pattern detected; mint logic in '{func}' could be "
            "overwritten by a malicious upgrade."
        ),
        slither_detector="uninitialized-local",
    ),
    MintRule(
        rule_id="MINT-007",
        severity=Severity.LOW,
        description_template=(
            "mint() in '{func}' lacks a supply cap check. Unrestricted inflation is possible."
        ),
        slither_detector=None,
    ),
]

# Lookup by rule_id for fast access.
RULES_BY_ID: dict[str, MintRule] = {r.rule_id: r for r in MINT_RULES}

# Slither built-in detectors we always run alongside custom rules.
SLITHER_BUILTIN_DETECTORS: list[str] = [
    "arbitrary-send-eth",
    "controlled-delegatecall",
    "reentrancy-eth",
    "reentrancy-no-eth",
    "uninitialized-state",
    "tx-origin",
    "suicidal",
    "backdoor",
]
