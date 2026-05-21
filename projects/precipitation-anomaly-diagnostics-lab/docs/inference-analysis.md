# Inference Analysis

This document explains how to reason from the generated diagnostics without overstating the evidence. The mini-lab is designed for exploratory climate diagnostics, not operational forecasting or attribution.

## Inference Goal

The core question is:

```text
How unusual is the configured precipitation state, and what statistical or circulation patterns co-occur with it?
```

The workflow answers that question through a chain of reproducible diagnostics:

```text
climatology
-> anomaly and standardized anomaly
-> regional ranking and representative years
-> EOF/PC decomposition
-> correlation, trend, and regression checks
-> circulation composites
-> coupled-field MCA diagnostics
-> cautious physical interpretation
```

Each step is evidence-generating, not proof-generating. The final interpretation should be phrased as a diagnostic hypothesis unless it is supported by external physical analysis.

## Evidence Chain

The synthetic chart set in [`examples/synthetic-inference-report.md`](../examples/synthetic-inference-report.md) provides a concrete example of this chain. Those figures are generated from deterministic artificial data and are included only to demonstrate chart style and inference discipline.

### 1. Establish the Baseline

The climatology defines the reference state. An anomaly only has meaning relative to the chosen baseline period, variable definition, and preprocessing choices.

Review questions:

- Is the baseline period long enough for the question?
- Does the baseline overlap with the target event?
- Is the input field seasonal, monthly, or already aggregated?
- Are the coordinates and units consistent with the expected dataset?

Interpretation:

Large absolute anomalies indicate departures in the original units. Large percentage anomalies can be unstable where climatology is small, so maps should be read together with climatology and standard-deviation fields.

### 2. Separate Magnitude From Standardized Rarity

Absolute anomaly answers:

```text
How many units above or below the baseline is this cell or region?
```

Standardized anomaly answers:

```text
How large is the departure relative to local historical variability?
```

This distinction matters because wet regions and dry regions can have different climatological variance. A large absolute anomaly in a high-variance region may be less statistically unusual than a smaller anomaly in a low-variance region.

### 3. Rank Representative Years

Representative years are selected from regional standardized anomalies. They are useful for composite diagnostics because they provide transparent, reproducible year groups.

Interpretation rules:

- Use high and low years as diagnostic samples, not as labels with intrinsic physical meaning.
- Inspect whether selected years cluster by decade; clustering may indicate a trend or low-frequency variability.
- Keep group sizes documented because composite p-values depend strongly on sample count.
- Do not infer causality from year selection alone.

### 4. Read EOF Modes as Coordinates

EOF analysis decomposes variance into orthogonal spatial patterns and time coefficients. It is excellent for summarizing dominant covariance structures, but it does not know atmospheric physics.

Interpretation rules:

- EOF maps show statistically efficient patterns, not necessarily separate physical modes.
- PC time series show when each pattern is active.
- Mode sign is arbitrary; a flipped EOF/PC pair has the same mathematical meaning.
- North error bars help screen whether adjacent eigenvalues are clearly separated.
- A physically meaningful interpretation should also be consistent with representative years, composites, or external circulation knowledge.

### 5. Use Correlation and Regression as Association Checks

Correlation maps and regional regressions test whether configured climate indices align with the precipitation field or regional mean.

Interpretation rules:

- Correlation is symmetric association, not causation.
- Regression coefficients depend on index scaling and region definition.
- High `R^2` on a small sample should be treated cautiously.
- Lagged correlation can suggest lead/lag structure, but serial correlation reduces effective sample size.
- Pointwise map p-values do not establish field significance.

### 6. Use Trends as Context, Not Event Explanation

Trend maps estimate monotonic linear change over the configured period. They are useful for context, but a linear trend does not explain individual event anomalies by itself.

Interpretation rules:

- Compare target-year anomalies with trend diagnostics to separate event-scale departures from background change.
- Inspect whether representative years are concentrated at the beginning or end of the analysis period.
- Avoid extrapolating beyond the analysis period.

### 7. Use Composites to Connect Anomaly Patterns With Circulation

Composite analysis compares circulation fields between configured high/low or positive/negative groups. It can reveal co-occurring circulation structures such as ridges, troughs, or vertical-motion anomalies when the input variables support that interpretation.

Interpretation rules:

- Composite differences are conditional averages over selected years.
- Welch p-values are pointwise and sample-size sensitive.
- A circulation pattern is more credible when it is spatially coherent and consistent across variables.
- Composite interpretation should mention the selected years and group sizes.
- Do not describe composites as mechanisms unless supported by physical reasoning and independent evidence.

### 8. Use MCA to Screen Coupled Variability

Maximum covariance analysis finds paired precipitation and SST patterns with large shared covariance. It is useful for coupled-field exploration.

Interpretation rules:

- MCA score correlation indicates how tightly the paired mode varies in time.
- Squared covariance fraction measures contribution to cross-covariance, not precipitation variance alone.
- Heterogeneous correlation maps show how each field relates to the opposite-field score.
- MCA does not establish whether SST forces precipitation or precipitation responds to atmospheric circulation.

## Suggested Interpretation Template

Use this structure when writing a public report:

```text
1. Baseline and data context:
   The analysis uses [variable] over [period] with [baseline].

2. Anomaly statement:
   The target period shows [positive/negative/mixed] precipitation anomalies,
   strongest over [region], relative to [baseline].

3. Standardized context:
   Standardized anomalies indicate whether the departure is unusual relative
   to local variability.

4. Mode structure:
   EOF mode [n] summarizes [spatial pattern], with PC behavior suggesting
   [temporal behavior].

5. Representative-year evidence:
   High/low representative years provide transparent samples for composites.

6. Circulation association:
   Composite circulation differences are consistent with [diagnostic pattern],
   but are interpreted as association unless independently supported.

7. Limitations:
   Note dataset choice, region-box approximation, pointwise p-values,
   sample size, and absence of causal attribution.
```

## What Counts as Stronger Evidence

Evidence becomes more persuasive when independent diagnostics agree:

- anomaly maps and regional series show the same sign and timing;
- standardized anomaly confirms the departure is unusual, not only large;
- EOF/PC behavior aligns with representative years;
- composites are spatially coherent and physically plausible;
- correlation/regression diagnostics are consistent with known climate-index behavior;
- MCA patterns align with the precipitation anomaly structure and not only with isolated grid cells.

## What Should Not Be Claimed

Avoid these claims unless backed by additional analysis:

- "The index caused the precipitation anomaly."
- "This EOF mode is a physical mode."
- "The trend explains the target event."
- "Pointwise p < 0.05 means the map is field-significant."
- "The workflow is operationally validated."
- "The included example configuration reproduces a canonical scientific result."

## Reviewer Checklist

Before accepting an interpretation, check:

- Were all data paths local placeholders or provider-sourced paths?
- Were the analysis period and climatology period explicitly stated?
- Were region definitions documented?
- Were representative years selected by a reproducible rule?
- Were p-values described as pointwise where applicable?
- Were conclusions phrased as diagnostic evidence rather than causal proof?
- Were raw datasets kept outside Git unless explicitly redistributable?
