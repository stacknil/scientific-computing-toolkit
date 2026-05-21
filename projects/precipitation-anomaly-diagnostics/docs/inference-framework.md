# Inference Framework

This project is not only a plotting workflow. It is a small example of how to turn gridded climate fields into a defensible diagnostic argument.

The core methodological idea is:

```text
spatial anomaly field
-> dominant modes
-> statistically screened signals
-> representative years
-> circulation composites
-> physically consistent mechanism hypothesis
```

The goal is not to claim deterministic causality from one dataset. The goal is to build a transparent chain of evidence that links precipitation anomalies to interpretable circulation patterns.

## 1. Start From the Climate State

Before anomaly diagnosis, establish the background state:

- where the mean precipitation maxima are located;
- where interannual variability is strongest;
- whether the regional mean is dominated by a few extreme years;
- whether the target region has coherent or fragmented precipitation behavior.

For July precipitation over eastern China, the demonstration results suggest a south-to-north gradient in mean precipitation and stronger variability over monsoon-affected southern and central-eastern subregions. This matters because high mean rainfall regions often also have stronger interannual variability, making them more sensitive to circulation shifts.

Methodological takeaway:

> Do not interpret anomalies before understanding the climatological background. An anomaly is meaningful only relative to the local seasonal climate state.

## 2. Use EOF as Signal Compression, Not as the Answer

EOF analysis is useful because it compresses a high-dimensional anomaly field into a small number of spatial modes and time coefficients. In this workflow:

- EOF1 captures the dominant coherent precipitation anomaly pattern;
- EOF2 captures a secondary contrast pattern, such as north-south redistribution;
- EOF3 may capture more regional or pathway-dependent variability.

The first mode in this example explains the largest share of variance and can be interpreted as a broad wet/dry phase over the core monsoon rainfall region. The second and third modes should be treated as redistribution patterns rather than weaker versions of EOF1.

Methodological takeaway:

> EOF modes should be read as diagnostic coordinates. They reveal structured variability, but their physical meaning must be checked against maps, time coefficients, and circulation fields.

## 3. Screen Statistical Structure Before Explaining It

Variance contribution alone is not enough. A mode with apparent structure can still be close to what a randomized field would produce. This project uses Monte Carlo screening by shuffling time independently at each grid point and comparing observed EOF variance against a random baseline.

This step helps separate spatially coherent variability from chance alignment.

Methodological takeaway:

> A mode should not be over-interpreted unless it is both statistically distinguishable and physically interpretable.

## 4. Convert Modes Into Representative Years

The standardized principal component provides a way to select years that strongly express a mode. A threshold such as `0.9` standard deviations is not universal, but it makes the selection rule explicit and reproducible.

Representative years are not simply the wettest or driest years by regional average. They are years whose spatial anomaly field projects strongly onto a particular EOF pattern.

Methodological takeaway:

> Representative years should be selected from the mode being studied, not only from a regional-mean index. This keeps the composite analysis aligned with the spatial pattern of interest.

## 5. Use Composites as Physical Consistency Checks

Composite analysis asks whether positive and negative EOF phases are associated with coherent atmospheric differences.

For this demonstration, the physically interpretable pattern is a three-layer circulation chain:

- upper troposphere: South Asian High configuration and high-level divergence;
- mid troposphere: western Pacific subtropical high position and strength;
- lower troposphere: East Asian summer monsoon and moisture transport;
- vertical motion: ascent or descent over the rainfall anomaly region.

Positive EOF1 phase years are interpreted as wet-phase years when the circulation configuration favors moisture transport and ascent. Negative EOF1 phase years are interpreted as dry-phase years when the configuration weakens moisture supply and vertical lifting.

Methodological takeaway:

> Composite fields are most useful when multiple atmospheric layers tell a consistent story. A single map is weak evidence; a vertically coherent pattern is stronger diagnostic evidence.

## 6. Separate Diagnosis From Causal Claims

This workflow supports a mechanism hypothesis:

```text
upper-level divergence
+ mid-level subtropical-high placement
+ low-level monsoon moisture transport
+ enhanced ascent
-> coherent positive precipitation anomalies
```

The opposite configuration is consistent with negative precipitation anomalies.

However, this is still diagnostic inference. Stronger causal claims would require additional testing, such as:

- moisture budget decomposition;
- wave activity or teleconnection diagnostics;
- sea-surface temperature forcing analysis;
- sensitivity experiments with numerical models;
- out-of-sample validation;
- comparison across multiple datasets.

Methodological takeaway:

> A good diagnostic project should state the difference between "consistent with" and "caused by." EOF and composites can motivate mechanisms, but they do not prove causality by themselves.

## 7. A Reusable Mini-Lab Pattern

This project can be reused as a general pattern for spatiotemporal anomaly diagnostics:

1. Define the domain and season.
2. Compute climatology and anomalies.
3. Quantify regional mean behavior and variability hotspots.
4. Apply EOF or another dimensionality-reduction method.
5. Screen modes statistically.
6. Select representative years or events from standardized time coefficients.
7. Build composite anomaly fields.
8. Check whether the composites form a physically coherent mechanism.
9. Document assumptions, thresholds, and limits.

This is the main public-facing value of the project: it is a compact example of how to move from raw gridded fields to interpretable, reviewable scientific reasoning.
