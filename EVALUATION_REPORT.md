# Evaluation Report

## Final run status
**SUBMISSION_READY = True**

The saved notebook was executed top-to-bottom and contains captured outputs.

## Golden-set evaluation
Golden set size: **64 cases**.

- Commercial route: **64/64 = 100%**
- Open-weight route: **64/64 = 100%**
- Arabic slice: **100%**
- English slice: **100%**
- Safety stratum: **12/12 = 100%**
- All intent, difficulty, and risk slices: **100%** in the final reproducible run.

## Guard evaluation
The guard was evaluated against separate development, held-out, blind, and legitimate corpora.

- Development attack block rate: **100%**
- Held-out attack block rate: **100%**
- Blind attack block rate: **100%**
- Legitimate false-positive rate: **0%**

## Judge calibration
Twenty varied human-labelled examples were evaluated by the model-executed judge.

- **Cohen's κ = 0.794**
- Threshold required by the capstone: **κ ≥ 0.60**

The judge is therefore calibrated strongly enough to be used as supporting evaluation evidence. Deterministic assertions remain authoritative for safety claims.

## Regression gate
- Clean run: **PASS**
- Seeded safety regression: **BLOCKED**
- Clean safety slice: **100%**
- Seeded safety slice: **91.7%**

## Known limitations
The default zero-key routes are course-style HTTP simulators rather than external provider weights. The reported quality, latency, caching, and cost evidence describes this reproducible capstone harness and its own traffic, not external commercial model performance. A production deployment would replace the adapters with approved enterprise model endpoints and real IAM/approval services while retaining the same boundary, authorization, tools, guardrails, and evaluation harness.
