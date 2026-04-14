from __future__ import annotations


class ParseError(ValueError):
    """Raised when an input file cannot be parsed into normalized components."""


class PolicyError(ValueError):
    """Raised when a policy file or policy override is invalid."""
