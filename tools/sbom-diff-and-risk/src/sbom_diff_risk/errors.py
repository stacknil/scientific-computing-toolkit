from __future__ import annotations


class ParseError(ValueError):
    """Raised when an input file cannot be parsed into normalized components."""


class MalformedInputError(ParseError):
    """Raised when an input is syntactically malformed."""


class UnsupportedInputError(ParseError):
    """Raised when deterministic mode rejects otherwise valid input syntax."""


class InputSelectionError(ParseError):
    """Raised when an explicit parser selection cannot be satisfied."""


class PolicyError(ValueError):
    """Raised when policy parsing or evaluation inputs are invalid."""
