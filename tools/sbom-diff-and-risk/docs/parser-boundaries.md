# Parser boundaries

`sbom-diff-and-risk` intentionally supports a conservative parser subset so local runs remain deterministic, auditable, and CI-friendly.

The project does not try to emulate a package installer. When syntax would require resolver behavior, implicit includes, index lookups, or environment-specific side effects, the parser fails closed with an explicit error.

## requirements.txt

`requirements.txt` is treated as a narrow manifest format, not as "everything pip can do in a file".

| Syntax | Status | Notes |
| --- | --- | --- |
| Plain PEP 508 names and version specifiers | Supported | Example: `requests==2.31.0` |
| Extras and markers | Supported | Example: `pytest[testing]>=8.0 ; python_version >= "3.11"` |
| Comments and blank lines | Supported | Stripped before parsing |
| Line continuations | Supported | Continued lines are joined deterministically |
| `-r`, `--requirement` | Unsupported | Include chains are rejected |
| `-c`, `--constraint` | Unsupported | Constraint files are rejected |
| `-e`, `--editable` | Unsupported | Editable installs are rejected |
| Direct URL, VCS, or local path references | Unsupported | Includes `pkg @ https://...`, `git+...`, `file://...`, wheels, and local archives |
| Index and source options | Unsupported | Includes `--index-url`, `--extra-index-url`, `--find-links`, `--trusted-host`, `--no-index` |
| Other pip-only install flags | Unsupported | Includes hash flags, binary toggles, prerelease flags, and related installer controls |

When unsupported syntax appears, the parser raises `UnsupportedInputError` and the CLI returns exit code `2`.

## pyproject.toml

`pyproject.toml` support is also intentionally narrow:

| Section | Status | Notes |
| --- | --- | --- |
| `[project.dependencies]` | Supported | Parsed by default |
| `[project.optional-dependencies]` | Supported | Parsed by default and kept distinct from dependency groups |
| `[dependency-groups]` | Supported | Requires explicit `--pyproject-group <name>` selection |
| `{ include-group = "name" }` inside dependency groups | Supported | Includes are resolved locally and deterministically |
| Missing requested dependency group | Explicit error | Reported as `InputSelectionError` |
| Poetry, Hatch, PDM, or other tool-specific dependency sections | Unsupported | Not parsed in v0.2 |

Dependency groups are not merged automatically with `[project.optional-dependencies]`. They solve different problems and are kept separate on purpose.

## Error taxonomy

The parser uses explicit error classes so CI logs are understandable:

- `MalformedInputError`: the file is syntactically malformed.
- `UnsupportedInputError`: the file is valid enough to read, but deterministic mode intentionally does not support the construct.
- `InputSelectionError`: the user asked for a parser selection the input cannot satisfy, such as a missing dependency group.

The CLI maps these parser failures to exit code `2`.
