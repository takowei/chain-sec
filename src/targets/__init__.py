"""Authorized target scope registry.

Only targets recorded here (with a valid public bug-bounty scope URL
and authorization date) may be analyzed. This enforces Rule #1 of
RULES-OF-ENGAGEMENT.md.
"""

from .scope_registry import ScopeRegistry, Target

__all__ = ["ScopeRegistry", "Target"]
