# Spark external V14: actual weights, exposed code-only diagnostics

The V11–V13 browser and AST regression results did not evaluate Spark weights.
This comparison loads the pinned Spark base and the saved evidence V3 LoRA,
and generates evidence JSON for the same 24 source fragments (21 unique code
snippets) without training or model promotion. Both receive identical prompts.

Inputs contain only the original code, its hash and the training-task instruction.
They contain no browser fixture setup, DOM context, expected labels or AST answer.
Scoring compares the six requested fields to the current code-only bounded AST.
An exact-match score is **oracle conformance, not independent semantic accuracy**.
In particular, missing runtime DOM input provenance must remain unknown; the
conditional 15/15 browser-execution result is not the model's recall denominator.

The report preserves raw outputs, per-case disagreement, prompt/code/adapter hashes,
unique-snippet scores and incomplete run errors. A generation failure stops the run
and retains partial predictions instead of silently turning failures into SAFE.
The model never overrides static decisions and performs no browser confirmation.

## Execution

The `Spark External V14 Model Evaluation` workflow validates the exact saved V3
candidate identity, attaches its private Kaggle output, then loads real FP16 base
weights followed by its LoRA. There are 48 generations with a fixed 520-token cap.
The cap is part of this fixed diagnostic and long/truncated output can fail parsing.
The workflow uses a separate notebook: `dody2004/spark-external-v14-evaluation`.
It never overwrites the training notebook or former evaluation notebooks.

Launch is explicit (`workflow_dispatch` or merge message
`[launch-spark-external-v14-eval]`). Pull requests run model-free scorer checks only.
A successful submission is not successful inference: require success status and
24 retained outputs for each model before reporting results.

## Independent acceptance evaluation is still incomplete

These five source repositories and fragments were exposed in engine development.
They cannot be relabeled an independent holdout by changing a filename or revision.
The intended acceptance set requires 100 unsafe + 100 safe cases, source repositories
disjoint from development, family/group separation, frozen sampling, complete training
and development inventories, execution evidence for unsafe paths and semantic evidence
for safe paths. An independent reviewer must adjudicate the labels; the engine author
cannot self-certify that role. No independent reviewer or completed 200-case set is
currently supplied, and the structural checker does not certify independence.

V14 therefore addresses actual weight execution on external-source code only.
It does not complete independent acceptance, promote weights or claim production readiness.
