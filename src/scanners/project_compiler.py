"""Project-mode compiler for multi-file Solidity projects.

Handles automatic remapping generation, pragma-based solc version selection,
and per-file fallback compilation. Never executes target project scripts
(no hardhat / foundry / npm lifecycle hooks).

Red-line compliance (RULES-OF-ENGAGEMENT.md §8):
  - Only reads source files and remappings.txt (data, not executable).
  - solc is invoked directly by us; no target build scripts are run.
  - npm install must be run by the user with --ignore-scripts before scanning.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pragma / semver helpers
# ---------------------------------------------------------------------------

# Matches a full pragma solidity statement, capturing the constraint expression.
_PRAGMA_STMT_RE = re.compile(
    r"pragma\s+solidity\s+([^;]+);",
    re.MULTILINE,
)

# Matches individual version constraints within a pragma expression.
# Groups: (operator, major, minor, patch)
_CONSTRAINT_RE = re.compile(r"(\^|>=|<=|>|<|=)?\s*(\d+)\.(\d+)\.(\d+)")

# Well-known package prefixes that appear in import paths.
_KNOWN_PACKAGE_PREFIXES: dict[str, str] = {
    "@openzeppelin": "@openzeppelin",
    "@uniswap": "@uniswap",
    "@chainlink": "@chainlink",
    "@aave": "@aave",
    "@pendle": "@pendle",
    "@layerzerolabs": "@layerzerolabs",
    "@balancer-labs": "@balancer-labs",
    "@gnosis": "@gnosis",
    "@mean-finance": "@mean-finance",
}


@dataclass
class ProjectContext:
    """Describes a compilable Solidity project.

    Attributes
    ----------
    root:
        Absolute path to the project root (where node_modules/ may live).
    sol_files:
        All .sol files discovered under the project root.
    remappings:
        List of solc remapping strings, e.g. "@openzeppelin/=node_modules/@openzeppelin/".
    solc_version:
        The solc version string selected to satisfy all pragma constraints (e.g. "0.8.20").
    solc_bin:
        Absolute path to the selected solc binary. Empty string if not resolved.
    """

    root: Path
    sol_files: list[Path] = field(default_factory=list)
    remappings: list[str] = field(default_factory=list)
    solc_version: str = ""
    solc_bin: str = ""


def build_project_context(
    project_root: Path,
    solc_bin_map: dict[str, str],
) -> ProjectContext:
    """Analyse a project directory and return a ready-to-use ProjectContext.

    Parameters
    ----------
    project_root:
        Root directory of the target project.
    solc_bin_map:
        Mapping from version string to absolute solc binary path,
        e.g. {"0.8.20": "/path/to/solc-0.8.20"}.
        The highest installed version satisfying all pragma constraints is
        selected.  If none satisfies, a descriptive ValueError is raised.

    Raises
    ------
    ValueError
        If no installed version satisfies the pragma constraints.
    """
    project_root = project_root.resolve()

    sol_files = sorted(project_root.rglob("*.sol"))
    # Exclude files inside node_modules — those are dependencies, not targets.
    sol_files = [f for f in sol_files if "node_modules" not in f.parts]

    remappings = _build_remappings(project_root)
    constraints = _collect_constraints(sol_files)

    available_versions = sorted(solc_bin_map.keys(), key=_version_tuple, reverse=True)

    if not constraints:
        logger.warning("No pragma solidity found; using first available solc version")
        solc_version = available_versions[0] if available_versions else ""
    else:
        solc_version = _pick_best_version(constraints, available_versions)

    if not solc_version or solc_version not in solc_bin_map:
        available = ", ".join(sorted(solc_bin_map.keys())) or "(none)"
        min_required = _constraints_lower_bound(constraints)
        if min_required:
            fix_hint = f"solc-select install {min_required}"
        else:
            fix_hint = "solc-select install <version>"
        summary = _constraints_summary(constraints)
        raise ValueError(
            f"No installed solc version satisfies pragma constraints {summary!r}.\n"
            f"  Available: {available}\n"
            f"  Suggested: {fix_hint}"
        )

    return ProjectContext(
        root=project_root,
        sol_files=sol_files,
        remappings=remappings,
        solc_version=solc_version,
        solc_bin=solc_bin_map[solc_version],
    )


# ---------------------------------------------------------------------------
# Remapping helpers
# ---------------------------------------------------------------------------


def _build_remappings(project_root: Path) -> list[str]:
    """Produce solc remapping strings for the given project root.

    Priority:
    1. Read ``remappings.txt`` in the project root (plain data, not executable).
    2. Auto-detect from node_modules top-level packages using known prefixes.
    3. Auto-detect bare package names (folders whose names start with ``@``).
    """
    remappings: list[str] = []

    # 1. Explicit remappings.txt — it's data, safe to read per red-line §8.
    remap_file = project_root / "remappings.txt"
    if remap_file.is_file():
        lines = remap_file.read_text(encoding="utf-8").splitlines()
        for line in lines:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                remappings.append(line)
        logger.debug("Loaded %d remapping(s) from remappings.txt", len(remappings))
        return remappings

    # 2 & 3. Auto-detect from node_modules.
    node_modules = project_root / "node_modules"
    if not node_modules.is_dir():
        return remappings

    for child in sorted(node_modules.iterdir()):
        if not child.is_dir():
            continue
        pkg_name = child.name

        if pkg_name.startswith("@"):
            # Scoped package: look one level deeper, e.g. @openzeppelin/contracts
            for subpkg in sorted(child.iterdir()):
                if subpkg.is_dir():
                    prefix = f"{pkg_name}/{subpkg.name}/"
                    target = f"node_modules/{pkg_name}/{subpkg.name}/"
                    remappings.append(f"{prefix}={target}")
            # Also add the top-level scope remap for bare @scope/ imports.
            prefix = f"{pkg_name}/"
            target = f"node_modules/{pkg_name}/"
            remappings.append(f"{prefix}={target}")
        else:
            prefix = f"{pkg_name}/"
            target = f"node_modules/{pkg_name}/"
            remappings.append(f"{prefix}={target}")

    logger.debug("Auto-generated %d remapping(s) from node_modules", len(remappings))
    return remappings


# ---------------------------------------------------------------------------
# Solc version constraint parsing and selection
# ---------------------------------------------------------------------------


def _version_tuple(ver: str) -> tuple[int, int, int]:
    """Convert a "X.Y.Z" string to a sortable integer tuple."""
    parts = ver.split(".")
    try:
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    except (IndexError, ValueError):
        return (0, 0, 0)


def _caret_upper(bt: tuple[int, int, int]) -> tuple[int, int, int]:
    """Return the exclusive upper bound for a caret (^) constraint.

    Solidity follows npm semver caret rules:
    - ``^X.Y.Z`` where X > 0  → ``<(X+1).0.0``
    - ``^0.Y.Z`` where Y > 0  → ``<0.(Y+1).0``
    - ``^0.0.Z``               → ``<0.0.(Z+1)``
    """
    major, minor, patch = bt
    if major > 0:
        return (major + 1, 0, 0)
    if minor > 0:
        return (0, minor + 1, 0)
    return (0, 0, patch + 1)


def _version_satisfies(ver: str, op: str, bound: str) -> bool:
    """Return True when *ver* satisfies the constraint ``op bound``.

    Supported operators: ``^``, ``>=``, ``<=``, ``>``, ``<``, ``=`` (or bare).
    ``^0.Y.Z`` means ``>=0.Y.Z <0.(Y+1).0`` (npm/Solidity caret semantics).
    """
    vt = _version_tuple(ver)
    bt = _version_tuple(bound)

    if op == "^":
        return bt <= vt < _caret_upper(bt)
    if op in (">=", ""):
        return vt >= bt
    if op == "<=":
        return vt <= bt
    if op == ">":
        return vt > bt
    if op == "<":
        return vt < bt
    if op == "=":
        return vt == bt
    return vt >= bt


def _parse_pragma_constraints(pragma_expr: str) -> list[tuple[str, str]]:
    """Parse a pragma solidity expression into a list of (operator, version) pairs.

    Examples
    --------
    "^0.8.0"          -> [("^", "0.8.0")]
    ">=0.8.0 <0.9.0"  -> [(">=", "0.8.0"), ("<", "0.9.0")]
    "0.8.20"          -> [("", "0.8.20")]
    """
    result: list[tuple[str, str]] = []
    for m in _CONSTRAINT_RE.finditer(pragma_expr):
        op = m.group(1) or ""
        ver = f"{m.group(2)}.{m.group(3)}.{m.group(4)}"
        result.append((op, ver))
    return result


def _collect_constraints(sol_files: list[Path]) -> list[tuple[str, str]]:
    """Gather the union of all version constraints across all .sol files.

    Reads only the first 40 lines of each file (pragma is nearly always there).
    Returns a flat list of (operator, version) pairs — the intersection of all
    constraints is what the selected solc must satisfy.
    """
    all_constraints: list[tuple[str, str]] = []
    for f in sol_files:
        try:
            header = _read_head(f, lines=40)
        except OSError:
            continue
        for m in _PRAGMA_STMT_RE.finditer(header):
            expr = m.group(1).strip()
            pairs = _parse_pragma_constraints(expr)
            all_constraints.extend(pairs)
    return all_constraints


def _pick_best_version(
    constraints: list[tuple[str, str]],
    available: list[str],
) -> str:
    """Return the highest available version satisfying all constraints, or ''.

    ``available`` is assumed to be sorted descending (highest first).
    """
    for ver in available:
        if all(_version_satisfies(ver, op, bound) for op, bound in constraints):
            return ver
    return ""


def _constraints_lower_bound(constraints: list[tuple[str, str]]) -> str:
    """Return the tightest lower-bound version implied by constraints.

    Used to produce a helpful ``solc-select install X.Y.Z`` hint when no
    installed version satisfies the constraints.
    """
    lower: tuple[int, int, int] = (0, 0, 0)
    for op, ver in constraints:
        vt = _version_tuple(ver)
        if op in ("^", ">=", "=", ""):
            if vt > lower:
                lower = vt
        elif op == ">":
            # Strictly greater — bump patch as minimum approximation.
            candidate = (vt[0], vt[1], vt[2] + 1)
            if candidate > lower:
                lower = candidate
    if lower == (0, 0, 0):
        return ""
    return f"{lower[0]}.{lower[1]}.{lower[2]}"


def _constraints_summary(constraints: list[tuple[str, str]]) -> str:
    """Return a compact human-readable string of all constraints."""
    return " ".join(f"{op}{ver}" for op, ver in constraints) or "(none)"


def _read_head(path: Path, lines: int = 40) -> str:
    """Read the first *lines* lines of a file as a string."""
    result: list[str] = []
    with path.open(encoding="utf-8", errors="ignore") as fh:
        for i, line in enumerate(fh):
            if i >= lines:
                break
            result.append(line)
    return "".join(result)
