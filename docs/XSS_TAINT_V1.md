# XSS Taint Specialist v1: offline foundation

The whole-snippet SAFE/POSSIBLE_XSS/XSS training series is retired. All historical
v0.x workflow jobs are disabled and both supported encoder trainer main functions
refuse new training. Historical weights, reports and corpora are retained.
No replacement model has been trained or promoted.

## Run

```
uv run xss-taint path/to/local.js
uv run python security-models/xss/inference/hybrid_predict.py 'const x=location.hash; box.innerHTML=x;'
```

The hybrid CLI defaults to AST analysis without loading weights or launching a
browser. An explicit `--adapter` attaches advisory routing scores only. The
historical `predict.py` remains an explicitly documented research-only classifier.
No route to the new final decision bypasses sink review on a model SAFE prediction.

## Implemented

- Pinned tree-sitter JavaScript AST parser; parse errors abstain.
- Source patterns for browser URL/document data and Express request properties.
- Local variable assignment, aliases, reassignment and conservative if/else joins.
- HTML sinks: innerHTML, outerHTML, srcdoc, document.write/writeln, res.send,
  insertAdjacentHTML. JavaScript evaluation/timer sinks are reviewed separately.
- textContent/innerText are text sinks; their values cannot establish HTML execution.
- Sanitizer identity requires an exact default import from an explicitly audited
  dompurify dependency. Global names and near-miss names are untrusted.
- `--trusted-module dompurify` is a caller-supplied trust assertion about the installed
  dependency, default configuration and hooks. This analyzer does not verify package
  bytes, dependency versions or vulnerabilities. It is OFF by default. Additional
  sanitize configuration arguments and unknown calls abstain. Rebinding/mutation
  invalidates identity; concatenation removes the HTML sanitizer guarantee.
- Sanitized HTML never establishes safety for a JavaScript execution context.
- Every sink result includes source, flow, context, sanitizer and location evidence.
- Unknown calls and unsupported side effects invalidate tracked guarantees.

## Meaning of results

SAFE means the supported reviewed sink expressions are constant, text-only, or
protected under the explicit sanitizer trust policy. It is not a whole-program
proof. Source identification assumes unshadowed browser builtins and Express
request conventions; these are patterns, not authenticated object identities.
CANDIDATE is a statically identified source-to-sink path without a compatible
protection. It does not prove reachability, browser execution or exploitability.
INCONCLUSIVE means syntax, effects, flow or coverage cannot be resolved. A file
with no reviewed sink is also inconclusive. All outputs set `confirmed=false`.

## Deliberate coverage boundaries

JavaScript only. HTML, JSX, TypeScript, event handlers, function bodies/calls,
closures, cross-file flow, loops, destructuring, dynamic properties, framework
rendering, object aliases and dependency implementations are not resolved.
Unsupported constructs abstain; this initial release is not a full-program taint
analyzer or a substitute for code review. Unknown constructs may hide sinks, so
candidate evidence never claims exhaustive coverage. Conservative invalidation
can create many abstentions; this is measured rather than disguised as safety.

The existing browser oracle is not invoked by this offline path. Local isolated
browser confirmation and a reviewed trust/evidence boundary remain a separate
integration milestone. `requires_oracle` is a review requirement, not a claim that
an oracle ran. No automatic third-party probing or code execution is added.

## Independent evaluation

`xss-taint-eval --train TRAIN.jsonl --dev DEV.jsonl --external LOCKED.jsonl`
requires caller-curated binary SAFE/XSS labels and provenance with repository,
framework, template and generator identities. Missing identities, overlapping
identities or exact stripped-code duplicates across splits fail closed. Metadata
checks do not prove semantic independence; corpus provenance needs human review.

External evaluation is an explicit invocation, not part of development or tests.
The existing external corpus has not been opened to implement this release.
No external FPR/FNR claim is made. New group-disjoint corpora must be curated
before a meaningful evaluation; existing synthetic data is not relabelled to
manufacture disjointness.

The initial metric thresholds are SAFE FPR <15%, strict XSS FNR <8%, decision
coverage >=90%, and SAFE review rate <15%. Strict FNR counts XSS abstentions as
misses; SAFE review rate includes abstentions to prevent gaming FPR by refusing
to decide. Missing classes fail the threshold check. Meeting these numbers alone
does not promote anything: `promotion_allowed=false` until independently curated
locked evaluation is reviewed. The later <8% SAFE FPR goal remains a target.

## Next work

Collect independently sourced, auditable group-disjoint cases; quantify coverage
and error categories. Extend flow only for measured gaps. Then consider a small
model for unresolved relations and a local isolated browser evidence bridge.
Do not train five specialist models before proving which relations need learning.

## Flow-relation training path

A separate `training.train_flow_relations` entry point now trains a compact
TF-IDF/logistic-regression baseline on bounded source/sink/flow spans. This is an
advisory statistical baseline, not a new SLM and not a replacement whole-snippet
XSS classifier. It outputs CONNECTED, DISCONNECTED or UNKNOWN probabilities.
No predicted relation can override static safety, confirmation or oracle requirements.

Each training/development JSONL row must contain:

| Field | Required content |
|---|---|
| `id` | Unique relation identity |
| `task` | `FLOW_RELATION` |
| `source_expression` | Reviewed source expression, 1–4096 characters |
| `sink_expression` | Reviewed sink expression, 1–4096 characters |
| `flow_excerpt` | Reviewed bounded flow, 1–4096 characters |
| `label` | `CONNECTED`, `DISCONNECTED` or `UNKNOWN` |
| `verification.status` | `REVIEWED` |
| `verification.reviewer` | Independent reviewer identity |
| `verification.rationale` | Why the relation label is supported |
| `verification.reference` | Review/evidence reference |
| `provenance` | Actual repository, framework, template and generator identities |

Group identities and exact relation inputs must be disjoint across training and
development. Independent labels must come from audited code-flow review, not from
the new analyzer's own output or rewritten v0.x labels. Minimum counts are 20 per
class in training and 10 per class in development, as initial operational floors,
not a statistically established sample-size guarantee. The external test is not
accepted by this trainer and remains untouched. Model weights are inert JSON,
not pickle. No candidate is auto-promoted.

```
uv run python -m training.train_flow_relations \
  --train reviewed_relations_train.jsonl \
  --dev reviewed_relations_dev.jsonl \
  --output security-models/xss/adapters/flow-relation-v1
```

To attach an advisor to local review after a candidate exists:

```
uv run xss-taint local.js \
  --relation-model security-models/xss/adapters/flow-relation-v1/model.json \
  --relation-record reviewed_relation.json
```

The inference record also needs `snippet_sha256`, matching the UTF-8 code passed
to the analyzer. Advice changes review priority only. A disconnected prediction
never suppresses a candidate, resolves an abstention, or skips browser requirements.
Probabilities are uncalibrated research scores and are not correctness guarantees.

The attempted run on the repository's current `train.jsonl` and `validation.jsonl`
was blocked before fitting: they contain whole-snippet classifier records, not
independently reviewed relation records. See
[`training_readiness.json`](../reports/taint-v1/training_readiness.json). No research
checkpoint was created. The numerical serialization test uses artificial unit-test
fixtures in a temporary directory and is not a training release or evaluation result.

## Native-data training attempt completed

The initial missing-data blocker has now been addressed with
[`data/flow-relations-v1`](../data/flow-relations-v1/README.md): 60 selected original
Express assignment relations for training and 30 Fastify relations for development.
Inputs are pinned and byte-verified; complete MIT notices accompany copied source.
They were reviewed by the same implementer, not an independent expert. Annotation
rules define explicit local value dependency with opaque call returns. These are
relation labels, not vulnerability labels.

For these verified native-code records, code-template/code-generator fields are
explicitly not applicable. Repository/framework independence is checked; structural
template independence is not claimed. The audit continues to require actual
independent template/generator identities when code is generated. This applicability
rule avoids fabricated split identifiers and is tested against spoofed provenance.

The training command completed locally, producing inert JSON weights of 96,710
bytes, without a cloud training job or downloading an LLM. This statistical baseline
is not an SLM. On independent-repository development queries: 50% accuracy, macro
F1 0.4374, per-class recall CONNECTED 40%, DISCONNECTED 100%, UNKNOWN 10%.
The poor recall makes it unsuitable even as a trusted flow resolver; it is recorded
as a rejected research candidate and is never loaded automatically. All static
verdicts and browser requirements remain independent of model advice.

The artifact, per-query predictions, training report and rejection metadata are in
`security-models/xss/adapters/flow-relation-v1-native-001/` and
`registry/releases/flow-relation-v1-native-001.json`. The earlier preflight failure
is preserved in `reports/taint-v1/training_readiness.json` alongside the completed
attempt. No external XSS FPR/FNR is claimed, and the external test was not opened.
