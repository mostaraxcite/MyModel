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
