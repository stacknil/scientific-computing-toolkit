# Sanitization Report

This working-tree report records how the public-safe export was prepared.

## Files Inspected

- root-level source materials;
- generated figures;
- generated reports;
- compressed data and analysis artifacts;
- public export tree.

## Identifiers Removed or Excluded

- personal names and student identifiers;
- institution, college, course, and classroom context;
- team-member and instructor references;
- local Windows and cloud-sync paths;
- course templates, slides, and word-processing reports;
- raw compressed data archives and large climate datasets.

## Public Assets Kept

- reusable Python source modules;
- neutral documentation;
- placeholder configuration;
- small derived CSV summary;
- derived demonstration figures with neutral filenames.

## Raw Files Excluded

- raw or packaged climate datasets;
- original course PDFs;
- original presentation decks;
- original word-processing reports;
- compressed working archives.

## Remaining Assumptions

- Included figures are derived scientific outputs and do not contain personal or institutional branding.
- The public repository should be created from this sanitized export directory, not from the original working folder.
- Git history should be clean because the export directory is separate from the original materials.

## Recommended Review Path

Publish or review this project from the sanitized subproject directory only. Do not publish the original working directory or raw source materials.
