# Sanitization Report

This report summarizes the conversion of a local student analysis folder into a public-safe climate diagnostics mini-lab.

## Files Inspected

- Top-level project files and folders.
- Python analysis scripts from the previous exercise-style folders.
- Generated figures, CSV tables, NetCDF outputs, archives, and text outputs.
- Office/PDF artifacts, slide decks, and temporary office files.
- File names and text content for course, institution, personal, local-path, and credential-like patterns.

## Identifiers Removed or Generalized

- Personal names were replaced by the public pseudonymous identity `stacknil`.
- Institution, class, course, group, and submission wording was removed from public documentation and code.
- Course-style file and directory names were replaced by neutral analysis names.
- Local absolute paths were replaced with placeholders in `configs/example.yaml`.

## Raw Files Excluded

- Raw or provider-controlled NetCDF climate datasets.
- Generated NetCDF outputs from local runs.
- Course reports, PDFs, slide decks, Word documents, and office temp files.
- Archive files containing generated outputs.

## Remaining Assumptions

- Users will obtain climate datasets from original providers and keep them outside Git by default. Public official datasets do not need privacy sanitization, but redistribution should still follow provider terms and repository size constraints.
- The included scripts are exploratory scientific-computing workflows, not operational forecasting tools.
- Any future generated figure or notebook should be inspected for metadata before public release.

## Unresolved Risks

- Historical Git history was not rewritten because this folder was not a Git repository at cleanup time.
- If these files are later imported into a repository with older commits, that repository history should be audited separately.
