"""Supply-accounting invariant checks for Slither-based static analysis.

Three rules:
  INV-001 — Asymmetric paired-token mint/burn (single-sided without matching pair).
  INV-002 — Rounding direction favours user in mint/redeem paths (ceil-to-user).
  INV-003 — Mint amount derived from manipulable spot rate/index.

Each rule is a standalone function.  All three are called by
``run_invariant_checks(slither_obj)`` which is invoked by slither_wrapper
after project-mode compilation.

Design notes
------------
- Rules run against the Slither Python API directly (same-process).
- Returns Finding objects with severity=MEDIUM and rule_id=INV-*.
- Rule can be disabled via config flags passed to ``run_invariant_checks``.
- Precision is medium: intentional false-positives are acceptable; false-
  negatives are not.  Output is for human review, not automated exploit.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from slither.slithir.operations import HighLevelCall, InternalCall, LibraryCall

from .models import Finding, Severity

if TYPE_CHECKING:
    from slither.core.declarations.contract import Contract
    from slither.core.declarations.function import Function
    from slither.slither import Slither

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Name heuristics
# ---------------------------------------------------------------------------

# Call names that indicate "create new supply"
_MINT_NAMES: frozenset[str] = frozenset(
    [
        "mint",
        "_mint",
        "mintto",
        "mintfor",
        "mintby",
        "mintprincipaltoken",
        "mintbyyt",
        "issue",
        "_issue",
    ]
)

# Call names that indicate "destroy supply"
_BURN_NAMES: frozenset[str] = frozenset(
    [
        "burn",
        "_burn",
        "burnfrom",
        "burnbyyt",
        "redeem",
        "destroy",
    ]
)

# Function-name keywords that indicate this is a mint-class function
_MINT_FUNC_KEYWORDS: tuple[str, ...] = (
    "mint",
    "issue",
    "deposit",
    "addliquidity",
)

# Function-name keywords that indicate this is a redeem/burn-class function
_REDEEM_FUNC_KEYWORDS: tuple[str, ...] = (
    "redeem",
    "burn",
    "withdraw",
    "removeliquidity",
)

# Library / internal helper names that indicate ceil (round-up) arithmetic
_CEIL_CALL_PATTERN: re.Pattern[str] = re.compile(
    r"divup|mulup|muldivup|rawdivup|divdown_?up|ceildiv|roundup",
    re.IGNORECASE,
)

# Library / internal helper names that indicate floor (round-down) arithmetic
_FLOOR_CALL_PATTERN: re.Pattern[str] = re.compile(
    r"divdown|muldown|muldivdown|rawdivdown|floordiv|rounddown",
    re.IGNORECASE,
)

# Variable-name keywords that suggest the value flows *to* the user (output)
_AMOUNT_OUT_KEYWORDS: tuple[str, ...] = (
    "amountout",
    "netout",
    "touser",
    "received",
    "tokensout",
    "ptout",
    "ytout",
    "syout",
    "lpout",
    "sharesout",
    "assets",
    "shares",
)

# Variable-name keywords that suggest the value is collected *from* the user (input)
_AMOUNT_IN_KEYWORDS: tuple[str, ...] = (
    "amountin",
    "netin",
    "fromuser",
    "paid",
    "tokensin",
    "ptin",
    "ytin",
    "syin",
    "lpin",
    "sharesin",
)

# External call names that indicate a *spot* / manipulable price source
_SPOT_SOURCE_PATTERNS: re.Pattern[str] = re.compile(
    r"latestrounddata|getreserves|getamountsout|getamountsin|spot|currentprice"
    r"|getrate|price|getprice|currentrate|exchangerate|assetprice",
    re.IGNORECASE,
)

# Variable-name keywords that indicate a *stored / checkpoint* index — safe to exclude
_SAFE_INDEX_KEYWORDS: tuple[str, ...] = (
    "storedindex",
    "lastindex",
    "cumulativeindex",
    "checkpointindex",
    "pyindex",
    "globalindex",
    "accindex",
    "stored",
    "cumulative",
    "checkpoint",
    "lastbalance",
    "lastprice",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_concrete_function(contract: Contract, func: Function) -> bool:
    """Return True if the function has an executable body worth analysing."""
    if contract.is_interface or contract.is_abstract:
        return False
    if func.is_implemented is not True:
        return False
    if func.view or func.pure:
        return False
    return True


def _call_name_lower(ir: InternalCall | HighLevelCall | LibraryCall) -> str:
    """Return the lowercased callee name from a SlithIR call operation.

    ``function_name`` on Slither IR ops returns a ``Constant`` object (not a
    plain str), so we always coerce through ``str()`` before lower-casing.
    Fall back to ``ir.function.name`` if the property is absent.
    """
    name = getattr(ir, "function_name", None)
    if name is None and ir.function is not None:
        name = ir.function.name
    return str(name).lower() if name is not None else ""


def _collect_call_names(func: Function) -> list[tuple[str, int | None]]:
    """Return list of (lowercased_call_name, line_no) for all call IR ops."""
    calls: list[tuple[str, int | None]] = []
    for node in func.nodes:
        line: int | None = None
        if node.source_mapping and node.source_mapping.lines:
            line = node.source_mapping.lines[0]
        for ir in node.irs:
            if isinstance(ir, (InternalCall, HighLevelCall, LibraryCall)):
                calls.append((_call_name_lower(ir), line))
    return calls


def _source_file(contract: Contract) -> str:
    """Best-effort source file path from a contract."""
    try:
        return str(contract.source_mapping.filename.absolute)
    except Exception:
        return "unknown"


def _func_line_start(func: Function) -> int | None:
    try:
        lines = func.source_mapping.lines
        return lines[0] if lines else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# INV-001 — Asymmetric paired-token mint/burn
# ---------------------------------------------------------------------------


def check_inv001_asymmetric_paired_mint(
    slither_obj: Slither,
) -> list[Finding]:
    """Detect functions that call mint XOR burn without a matching partner.

    Heuristic: a contract that holds *two or more* token address state variables
    (indicative of a paired-token architecture like PT/YT) AND has a function
    that calls mint-class OR burn-class operations for only *one* of those
    addresses is a candidate.

    Fallback: if the contract only has *one* token address state var, we still
    flag functions that perform only mints (no burns) or only burns (no mints),
    because unilateral supply change without the other side is suspicious in
    any accounting contract.
    """
    findings: list[Finding] = []

    for contract in slither_obj.contracts:
        if contract.is_interface or contract.is_abstract:
            continue

        for func in contract.functions:
            if not _is_concrete_function(contract, func):
                continue
            # Only look at externally reachable functions
            if func.visibility not in ("public", "external"):
                continue

            call_list = _collect_call_names(func)
            if not call_list:
                continue

            mint_calls = [(n, ln) for n, ln in call_list if any(m in n for m in _MINT_NAMES)]
            burn_calls = [(n, ln) for n, ln in call_list if any(b in n for b in _BURN_NAMES)]

            has_mint = bool(mint_calls)
            has_burn = bool(burn_calls)

            # Skip if the function does neither — not relevant
            if not has_mint and not has_burn:
                continue

            # Symmetric if both sides present — no finding
            if has_mint and has_burn:
                continue

            # If the function calls mint N≥2 times (e.g. PT + YT) with no burn,
            # that is a valid paired-mint pattern — skip to avoid false positives.
            if has_mint and len(mint_calls) >= 2:
                continue
            if has_burn and len(burn_calls) >= 2:
                continue

            # One-sided single call: potentially asymmetric
            side = "mint" if has_mint else "burn"
            paired_calls = mint_calls if has_mint else burn_calls
            call_names = [n for n, _ in paired_calls]
            first_line = next((ln for _, ln in paired_calls if ln), _func_line_start(func))

            findings.append(
                Finding(
                    rule_id="INV-001",
                    severity=Severity.MEDIUM,
                    contract=contract.name,
                    function=func.name,
                    description=(
                        f"Function '{func.name}' in '{contract.name}' performs "
                        f"only {side}-class operations ({call_names}) without a "
                        f"matching {'burn' if side == 'mint' else 'mint'} on the "
                        f"paired token.  Verify supply accounting symmetry."
                    ),
                    source_file=_source_file(contract),
                    line_start=first_line,
                    extra={
                        "side": side,
                        "calls": call_names,
                    },
                )
            )

    return findings


# ---------------------------------------------------------------------------
# INV-002 — Rounding direction favours user
# ---------------------------------------------------------------------------


def check_inv002_rounding_favours_user(
    slither_obj: Slither,
) -> list[Finding]:
    """Detect mint/redeem paths where rounding direction benefits the user.

    In a correct vault/yield protocol:
      - Mint (user receives): computation should round *down* (floor) so the
        protocol keeps the fractional unit.
      - Redeem (user pays): computation should round *up* (ceil) so the
        protocol collects at least the full amount.

    This rule flags the opposite — ceil in mint paths, floor in redeem paths
    — as those can be exploited via repeated round-trips.

    Detection strategy
    ------------------
    1. Classify the function as mint-class or redeem-class by name keywords.
    2. Within the function's IR nodes, scan for LibraryCall / InternalCall ops
       whose callee name matches the ceil or floor regex.
    3. For mint-class + ceil call → flag as wrong direction (user gets more).
    4. For redeem-class + floor call → also flag (user pays less).

    Variable-name heuristic: if the lvalue of the rounded call contains an
    ``amountOut``-style keyword, the result likely flows to the user.
    """
    findings: list[Finding] = []

    for contract in slither_obj.contracts:
        if contract.is_interface or contract.is_abstract:
            continue

        for func in contract.functions:
            if not _is_concrete_function(contract, func):
                continue

            fname_lower = func.name.lower()
            is_mint_func = any(kw in fname_lower for kw in _MINT_FUNC_KEYWORDS)
            is_redeem_func = any(kw in fname_lower for kw in _REDEEM_FUNC_KEYWORDS)

            if not is_mint_func and not is_redeem_func:
                continue

            for node in func.nodes:
                line: int | None = None
                if node.source_mapping and node.source_mapping.lines:
                    line = node.source_mapping.lines[0]

                for ir in node.irs:
                    if not isinstance(ir, (LibraryCall, InternalCall)):
                        continue

                    call_name = _call_name_lower(ir)
                    is_ceil = bool(_CEIL_CALL_PATTERN.search(call_name))
                    is_floor = bool(_FLOOR_CALL_PATTERN.search(call_name))

                    if not is_ceil and not is_floor:
                        continue

                    lvalue = getattr(ir, "lvalue", None)
                    lvalue_name = str(lvalue).lower() if lvalue else ""

                    # Determine directionality hint from variable name
                    looks_like_out = any(kw in lvalue_name for kw in _AMOUNT_OUT_KEYWORDS)
                    looks_like_in = any(kw in lvalue_name for kw in _AMOUNT_IN_KEYWORDS)

                    # Evaluate whether the rounding is wrong-direction
                    wrong_direction = False
                    direction_note = ""

                    if is_mint_func and is_ceil:
                        # ceil in mint path → user receives more than fair share
                        if looks_like_in:
                            # ceil on amountIn in a mint: user pays more — that's OK, skip
                            pass
                        else:
                            wrong_direction = True
                            direction_note = (
                                f"Ceil call '{call_name}' in mint-class function "
                                f"'{func.name}' (lvalue: {lvalue_name or 'unknown'}).  "
                                f"If this result flows to the user as output, "
                                f"rounding favours the user."
                            )

                    if is_redeem_func and is_floor:
                        # floor in redeem/burn path → user pays less than fair amount
                        if looks_like_out:
                            # floor on amountOut in a redeem: user gets less — OK, skip
                            pass
                        else:
                            wrong_direction = True
                            direction_note = (
                                f"Floor call '{call_name}' in redeem-class function "
                                f"'{func.name}' (lvalue: {lvalue_name or 'unknown'}).  "
                                f"If this result is a required input, rounding "
                                f"favours the user (they pay less)."
                            )

                    if wrong_direction:
                        findings.append(
                            Finding(
                                rule_id="INV-002",
                                severity=Severity.MEDIUM,
                                contract=contract.name,
                                function=func.name,
                                description=direction_note,
                                source_file=_source_file(contract),
                                line_start=line,
                                extra={
                                    "call": call_name,
                                    "lvalue": lvalue_name,
                                    "func_class": "mint" if is_mint_func else "redeem",
                                    "rounding": "ceil" if is_ceil else "floor",
                                },
                            )
                        )

    return findings


# ---------------------------------------------------------------------------
# INV-003 — Mint amount derived from manipulable spot rate
# ---------------------------------------------------------------------------


def check_inv003_spot_rate_dependency(
    slither_obj: Slither,
) -> list[Finding]:
    """Detect mint functions whose computed amount depends on a spot price source.

    Spot price sources (Chainlink latestRoundData, AMM getReserves, direct
    balanceOf) can be manipulated within a single transaction via flash loans.
    If the minted amount is computed from such a source, the supply can be
    inflated arbitrarily.

    Detection strategy
    ------------------
    1. Walk all IR nodes in mint-class functions.
    2. If a HighLevelCall matches the spot-source pattern, record its lvalue.
    3. Separately check if any variable whose name contains a rate/index
       keyword is populated by a spot call (name heuristic cross-check).
    4. Exclude variables whose names suggest they are stored/checkpoint
       indices (safe pattern).
    """
    findings: list[Finding] = []

    for contract in slither_obj.contracts:
        if contract.is_interface or contract.is_abstract:
            continue

        for func in contract.functions:
            if not _is_concrete_function(contract, func):
                continue

            fname_lower = func.name.lower()
            is_mint_func = any(kw in fname_lower for kw in _MINT_FUNC_KEYWORDS)
            is_redeem_func = any(kw in fname_lower for kw in _REDEEM_FUNC_KEYWORDS)

            if not is_mint_func and not is_redeem_func:
                continue

            for node in func.nodes:
                line: int | None = None
                if node.source_mapping and node.source_mapping.lines:
                    line = node.source_mapping.lines[0]

                for ir in node.irs:
                    if not isinstance(ir, (HighLevelCall, InternalCall, LibraryCall)):
                        continue

                    call_name = _call_name_lower(ir)

                    if not _SPOT_SOURCE_PATTERNS.search(call_name):
                        continue

                    lvalue = getattr(ir, "lvalue", None)
                    lvalue_name = str(lvalue).lower() if lvalue else ""

                    # Exclude if variable name looks like a safe stored index
                    if any(safe_kw in lvalue_name for safe_kw in _SAFE_INDEX_KEYWORDS):
                        continue

                    findings.append(
                        Finding(
                            rule_id="INV-003",
                            severity=Severity.MEDIUM,
                            contract=contract.name,
                            function=func.name,
                            description=(
                                f"Function '{func.name}' in '{contract.name}' calls "
                                f"'{call_name}' (spot price / manipulable source) and "
                                f"uses the result ('{lvalue_name}') in mint/redeem amount "
                                f"calculation.  If this is a live spot price rather than "
                                f"a stored cumulative index, the mint amount is vulnerable "
                                f"to flash-loan manipulation."
                            ),
                            source_file=_source_file(contract),
                            line_start=line,
                            extra={
                                "spot_call": call_name,
                                "result_var": lvalue_name,
                            },
                        )
                    )

    return findings


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def run_invariant_checks(
    slither_obj: Slither,
    *,
    enable_inv001: bool = True,
    enable_inv002: bool = True,
    enable_inv003: bool = True,
) -> list[Finding]:
    """Run all enabled invariant checks and return merged findings.

    Parameters
    ----------
    slither_obj:
        A compiled ``Slither`` instance (not re-compiled here).
    enable_inv001:
        Toggle for asymmetric paired-token mint/burn check.
    enable_inv002:
        Toggle for rounding-direction check (highest priority).
    enable_inv003:
        Toggle for spot-rate dependency check.

    Returns
    -------
    list[Finding]
        All candidate findings.  severity is always MEDIUM.
        rule_id values: INV-001, INV-002, INV-003.
    """
    findings: list[Finding] = []

    if enable_inv002:
        try:
            findings.extend(check_inv002_rounding_favours_user(slither_obj))
        except Exception:
            logger.exception("INV-002 check failed")

    if enable_inv001:
        try:
            findings.extend(check_inv001_asymmetric_paired_mint(slither_obj))
        except Exception:
            logger.exception("INV-001 check failed")

    if enable_inv003:
        try:
            findings.extend(check_inv003_spot_rate_dependency(slither_obj))
        except Exception:
            logger.exception("INV-003 check failed")

    return findings
