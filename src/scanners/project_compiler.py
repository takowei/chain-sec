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

# Regex to extract the first version constraint from a pragma statement.
# Matches: pragma solidity ^0.8.20; / >=0.8.0 <0.9.0; / =0.8.20; etc.
_PRAGMA_RE = re.compile(
    r"pragma\s+solidity\s+"
    r"[^;]*?"
    r"(\d+\.\d+\.\d+)",
    re.MULTILINE,
)

# Well-known package prefixes that appear in import paths.
# Key = prefix used in import, Value = typical node_modules subdirectory name.
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
        The dominant solc version string inferred from pragma statements (e.g. "0.8.20").
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
        Versions not present in this map will raise a descriptive error.

    Raises
    ------
    ValueError
        If the required solc version is not available in solc_bin_map.
    """
    project_root = project_root.resolve()

    sol_files = sorted(project_root.rglob("*.sol"))
    # Exclude files inside node_modules — those are dependencies, not targets.
    sol_files = [f for f in sol_files if "node_modules" not in f.parts]

    remappings = _build_remappings(project_root)
    solc_version = _detect_solc_version(sol_files)

    if not solc_version:
        logger.warning("No pragma solidity found; using first available solc version")
        solc_version = next(iter(solc_bin_map), "")

    solc_bin = solc_bin_map.get(solc_version, "")
    if not solc_bin:
        available = ", ".join(sorted(solc_bin_map.keys())) or "(none)"
        raise ValueError(
            f"Required solc version {solc_version!r} is not installed.\n"
            f"  Available: {available}\n"
            f"  Fix: solc-select install {solc_version}"
        )

    return ProjectContext(
        root=project_root,
        sol_files=sol_files,
        remappings=remappings,
        solc_version=solc_version,
        solc_bin=solc_bin,
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
# Solc version detection
# ---------------------------------------------------------------------------


def _detect_solc_version(sol_files: list[Path]) -> str:
    """Return the most common concrete solc version found in pragma statements.

    Reads the first 40 lines of each .sol file (where pragma is almost always
    placed) to keep it fast on large repos.
    """
    version_counts: dict[str, int] = {}
    for f in sol_files:
        try:
            header = _read_head(f, lines=40)
        except OSError:
            continue
        m = _PRAGMA_RE.search(header)
        if m:
            ver = m.group(1)
            version_counts[ver] = version_counts.get(ver, 0) + 1

    if not version_counts:
        return ""

    # Return the most frequently seen version.
    return max(version_counts, key=lambda v: version_counts[v])


def _read_head(path: Path, lines: int = 40) -> str:
    """Read the first *lines* lines of a file as a string."""
    result: list[str] = []
    with path.open(encoding="utf-8", errors="ignore") as fh:
        for i, line in enumerate(fh):
            if i >= lines:
                break
            result.append(line)
    return "".join(result)
