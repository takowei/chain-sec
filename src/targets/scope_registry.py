"""Authorized target scope registry.

Before any scan, the target must be registered here with:
- A public bug-bounty scope URL (Immunefi / Code4rena / HackenProof / Cantina).
- An authorization date.
- At least one in-scope contract address or repository URL.

Scanning an unregistered target raises UnauthorizedTargetError.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date


class UnauthorizedTargetError(RuntimeError):
    """Raised when a scan is attempted on an unregistered target."""


@dataclass
class Target:
    """A single authorized bug-bounty target."""

    name: str
    scope_url: str
    authorized_date: date
    in_scope_contracts: list[str] = field(default_factory=list)
    in_scope_repos: list[str] = field(default_factory=list)
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.scope_url.startswith("https://"):
            raise ValueError(f"scope_url must be an https:// URL, got: {self.scope_url!r}")
        if not self.in_scope_contracts and not self.in_scope_repos:
            raise ValueError("At least one in_scope_contracts or in_scope_repos entry is required.")


class ScopeRegistry:
    """Registry of authorized analysis targets.

    Usage
    -----
        registry = ScopeRegistry()
        registry.register(Target(
            name="ExampleProtocol",
            scope_url="https://immunefi.com/bounty/example/",
            authorized_date=date(2026, 6, 10),
            in_scope_repos=["https://github.com/example/protocol"],
        ))
        registry.assert_authorized("ExampleProtocol")
    """

    def __init__(self) -> None:
        self._targets: dict[str, Target] = {}

    def register(self, target: Target) -> None:
        """Add a target to the authorized list."""
        self._targets[target.name] = target

    def get(self, name: str) -> Target | None:
        return self._targets.get(name)

    def assert_authorized(self, name: str) -> Target:
        """Return the target or raise UnauthorizedTargetError if not registered."""
        target = self._targets.get(name)
        if target is None:
            raise UnauthorizedTargetError(
                f"Target {name!r} is not in the authorized scope registry. "
                "Register it with a valid public bug-bounty scope URL before scanning. "
                "See RULES-OF-ENGAGEMENT.md §1."
            )
        return target

    def list_targets(self) -> list[Target]:
        return list(self._targets.values())
