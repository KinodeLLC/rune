"""
rune, the policy language.

a policy compiles into capability grants for the broker and an authorisation
for the gate, which are the two objects already deciding what an agent can do
and what it can ship, so it gets enforced by construction rather than consulted
by convention.

kept out of the code it governs so a policy change is its own thing with its
own review.
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
