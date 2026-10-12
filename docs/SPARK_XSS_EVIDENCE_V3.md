# Spark XSS V3 — evidence-first specialist

## Why change

The 48-case independent synthetic regression showed that the original model
was better overall than either binary LoRA:
- Spark base: accuracy 79.17%, recall 87.50%, FPR 29.17%.
- Binary V1: accuracy 64.58%, recall 100%, FPR 70.83%.
- Balanced binary V2: accuracy 70.83%, recall 41.67%, FPR 0%.

The V2 model solved false alerts by dismissing 14 of 24 potential XSS paths.
No binary threshold can guarantee reliable code execution evidence.

## New design

1. **Source:** The bounded JavaScript AST analyzer identifies observed untrusted
   sources, such as location.hash or req.query. String occurrences in comments
   or constant strings are not evidence.
2. **Flow:** Record the precise local assignment/alias trace from source to
   each output operation. The relation is CONNECTED, DISCONNECTED or UNKNOWN.
3. **Sink:** Classify the actual output behavior as HTML_PARSER,
   SCRIPT_EXECUTION, TEXT_ONLY or UNKNOWN. Text-only APIs are safe for their
   *local sink*, even if the input is untrusted.
4. **Defense:** Verify an imported, explicitly trusted sanitizer in the
   appropriate HTML context, or a safe output API. Unknown calls, unknown
   sanitizer names and unsupported control flow do not prove safety.
5. **Decision gate:** A deterministic gate returns CANDIDATE, SAFE (bounded
   local path only) or INCONCLUSIVE. This gate ignores model suggestions that
   disagree with the observed evidence.
6. **Confirmation:** Browser evidence on an explicitly authorized target
   remains the only way to mark an XSS finding CONFIRMED.

The structured output includes snippet SHA256, source/flow/sink/defense paths,
the reason for the decision, limitations, and confirmed=false.

The model is an **advisory evidence extractor**; it cannot change a
deterministic verdict, sign off an unknown sanitizer, or confirm execution.

## Running locally

From the MyModel repository with dependencies installed:

    uv run python -m xss_specialist.evidence_pipeline my-snippet.js

An externally provided advisory report can be checked without executing it:

    uv run python -m xss_specialist.evidence_pipeline my-snippet.js --advisory-json proposal.json

The proposal must match the exact snippet SHA256 and every grounded field.
When it does not match, it is rejected without changing the gate's verdict.

## Synthetic SFT v3

The new SFT uses the pinned base XHToken/Spark-X2.5-4B, not the previous
biased adapters. A deterministic builder creates 340 JavaScript examples:
- 220 training examples from 11 template families.
- 120 group-disjoint internal dev examples from 6 unseen template families.
- CANDIDATE, SAFE and INCONCLUSIVE reasoning situations in both splits.
- The output target contains ONLY six evidence fields:
  snippet_sha256, source, flow, sink, defense, limitations.
- The target **never** contains Classification, a final vulnerability
  verdict, or a claim that a payload executed in the browser.

Builder:

    uv run python -m training.spark_xss_evidence_v3 --output-dir models/spark-evidence-v3

Training is opt-in through the GitHub Actions workflow
"Spark Evidence V3 GPU Candidate". It submits a **separate private**
Kaggle notebook:

https://www.kaggle.com/code/dody2004/spark-xss-evidence-v3

The Kaggle metadata requests GPU T4 x2 with internet enabled; it does
not prove Kaggle actually allocated a GPU. Verify the notebook GPU log
and the candidate's run_status.json before claiming training success.

The model is trained for one epoch using one T4 card with NF4 QLoRA,
FP16, LoRA rank 8 and learning rate 1e-5. The original V1 and V2
checkpoints are never overwritten.

## Evaluation and non-promotion rules

The source-label generator never consumes frozen benchmarks or any previous
Kaggle model output. Tests also reject exact snippet overlap with the previous
exposed 48-code suite and SFT v3. This does NOT guarantee semantic or
templating independence; the internal dev split is not a field benchmark.

Before considering production:
- verify output-JSON validity, per-field precision and unsupported evidence
  rejection on entirely new reviewed real-world code;
- measure the **deterministic final gate**, including INCONCLUSIVE coverage,
  separately from the model's advisory field accuracy;
- require scope-constrained browser execution evidence for confirmed reports;
- benchmark diverse frameworks, reflected/stored XSS, encoding contexts,
  JS/URL/CSS attribute sinks, DOM mutations, and unknown sanitizers;
- never calibrate thresholds on the already exposed 48-case regression suite.

No automatic promotion, credential usage, target scanning or MyHunt/PentesterFlow
deployment is performed by this pipeline. A successfully trained LoRA is a
candidate for evaluation only.


## GPU evidence extraction smoke test

Workflow: Spark Evidence V3 Field Evaluation.

The GPU run is conditional on Kaggle training status COMPLETE and a validated
run_status.json from the **separate private V3 adapter**. Its source SHA,
candidate identity, 220/120 SFT/dev split, Spark base revision, and
model_promoted=false are all verified before a new GPU job can be submitted.

The field evaluator loads Spark base and V3 adapter with the same FP16 weights
(not direct 4-bit inference, which previously broke Spark attention with Byte
weight dtype), and generates JSON on 12 stratified group-held-out synthetic
dev examples. It reports:

- strict JSON validity rate (exact six-key object, no binary verdict fields);
- per-field exact match for source, flow, sink, defense and limitations;
- total rate of evidence proposals grounded in the local deterministic AST;
- separate baseline Spark versus trained evidence V3 scores;
- zero browser confirmations and DO_NOT_PROMOTE.

This is a **small synthetic dev smoke test**, not a substitute for independent
real-code evaluation or proof of XSS vulnerabilities. Both versions are scored
on the same inputs and evaluated without giving either model final authority.


## Completed candidate checkpoint and scheduled field comparison

The isolated Kaggle training workflow run
https://github.com/mostaraxcite/MyModel/actions/runs/38300184934
completed successfully. Its final monitor output reports Kaggle
KernelWorkerStatus.COMPLETE and verifies candidate_saved_not_evaluated,
220 training / 120 dev records, model_has_final_authority=false and
model_promoted=false. This confirms checkpoint creation, **not** field
prediction quality or independent real-world generalization.

The separate v3 field-evaluation workflow uses the already-saved adapter
and checks exact JSON output plus source/flow/sink/defense/limitation fields
against AST-grounded evidence on 12 held-out synthetic dev cases. Its
merge trigger is [launch-spark-evidence-v3-eval]. It does NOT retrain the
model, approve a security finding or deploy it to production.
