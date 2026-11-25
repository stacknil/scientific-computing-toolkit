# sbom-diff-and-risk v1.2.0

Version-risk classification uses canonical package versions and strictly validates SemVer evidence. Policy qualification covers equivalent inputs, malformed Scorecard evidence and canonical release identities for optional PyPI lookups. See the [decision-stability reproduction guide](docs/validation/decision-stability/REPRODUCTION.md).

The compare command, report schema identifiers, risk taxonomy and offline defaults are preserved. Corrected evidence can change a risk classification or policy result. SARIF reports identify the producing tool as version 1.2.0. For an upgrade, replay the same inputs and policy and review changed decisions before adopting the new output as a baseline.
