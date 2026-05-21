# Reviewer path

This reviewer path is a lightweight guide for reading the compact precipitation diagnostics mini-lab as a public scientific-computing workflow. It is intended to make the project easy to evaluate without presenting it as the repository's flagship release surface.

## 30-second orientation

Read the project README first. Confirm this is a sanitized scientific-computing mini-lab, not a course archive and not an operational forecast system.

Check the first screen for the project role:

- compact reviewer-facing precipitation diagnostics mini-lab
- supporting scientific-data project inside `scientific-computing-toolkit`
- not part of the `sbom-diff-and-risk` release surface
- not a separate meteorology portfolio

## 5-minute workflow review

Inspect:

- [`docs/methodology.md`](methodology.md)
- [`docs/inference-framework.md`](inference-framework.md)
- [`reports/example-report.md`](../reports/example-report.md)
- [`examples/sample_metadata.json`](../examples/sample_metadata.json)

This pass should answer whether the workflow is reproducible, scientifically bounded, and clear enough for a reviewer to follow from input assumptions to derived outputs.

## 15-minute reproducibility review

Run:

```bash
python -m pip install -e .[dev]
python -m pytest
python scripts/run_preprocessing.py --help
python scripts/run_eof_analysis.py --help
python scripts/run_composite_analysis.py --help
```

This review does not require raw climate datasets. The help commands verify that the public scripts expose their configuration surface without relying on local machine paths or restricted data files.

## Boundaries

Read:

- [`docs/data-policy.md`](data-policy.md)
- [`PUBLICATION_BOUNDARIES.md`](../PUBLICATION_BOUNDARIES.md)

The project should be read as a reproducible spatiotemporal diagnostics module: it demonstrates data-policy discipline, analysis structure, and reviewer-friendly interpretation while keeping raw datasets, institutional course artifacts, personal identifiers, and local machine details out of the public repository.