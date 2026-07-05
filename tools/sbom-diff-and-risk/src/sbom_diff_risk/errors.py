from __future__ import annotations

from enum import StrEnum


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


class ComponentIdentityDiagnosticCode(StrEnum):
    DUPLICATE_COMPONENT = "duplicate_component"
    CONFLICTING_METADATA = "conflicting_metadata"


class ComponentIdentityError(ValueError):
    """Raised when one input cannot produce an unambiguous component index."""

    def __init__(
        self,
        code: ComponentIdentityDiagnosticCode,
        message: str,
        *,
        side: str | None = None,
        component_key: str | None = None,
    ) -> None:
        self.code = code
        self.detail = message
        self.side = side
        self.component_key = component_key
        super().__init__(f"{code.value}: {message}")
