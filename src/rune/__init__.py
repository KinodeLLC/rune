"""
Rune: the governance policy language.

A policy compiles to capability grants for the broker and an authorisation for
the promotion gate - the two objects that already decide what an agent may do
and what it may ship. A policy is therefore enforced by construction rather
than consulted by convention.

Kept a separate language from the code it governs, so a policy change is its
own artifact with its own review path.
"""

__version__ = "0.1.0"

from .lang import (  # noqa: E402
    APPROVAL_TRIGGERS,
    LANGUAGE_VERSION,
    LIMIT_NAMES,
    PROMOTE_CONDITIONS,
    GrantDecl,
    Lowering,
    PolicyDecl,
    RuneParser,
    evaluate,
    parse_rune,
)

__all__ = [
    "__version__", "LANGUAGE_VERSION",
    "parse_rune", "RuneParser", "Lowering", "evaluate",
    "PolicyDecl", "GrantDecl",
    "APPROVAL_TRIGGERS", "PROMOTE_CONDITIONS", "LIMIT_NAMES",
]
