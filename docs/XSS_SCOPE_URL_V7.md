# XSS scope, URL and encoding repairs (V7)

An exposed 40-case browser evaluation found one dangerous path reported as
SAFE and six false candidate alerts. Block lexical declarations were replacing
outer bindings; URL attributes were classified without element identity;
fixed navigation prefixes and percent-encoded HTML text composition lost
their contextual protection.

This change scopes lexical declarations from block entry, restores only
block-local names, preserves outer assignments, and separates callback-local
var declarations/parameters from asynchronous writes to surrounding state.
Unknown effects invalidate trusted function identities. Literal message
capture booleans, simple `{data}` patterns and `window.onmessage` are reviewed.
Getter/spread/prototype object behavior, arbitrary callbacks and unreviewed
functions still abstain.

Local object properties and aliases are tracked. Direct local helpers with
at most four identifier parameters, twelve straight-line statements and a
final side-effect-free return may propagate values. Recursive/nested helper
calls, unknown getter access and effects are not claimed safe.

Navigation URL prefixes are contextual: root/dot-relative or fixed HTTP(S)
prefixes prevent a javascript scheme at an anchor/location sink, but do not
prove remote script loads, server-side processing, redirects or whole-site
safety. Unknown DOM element identity stays inconclusive. Proven inert HTML
elements are distinguished from anchor/area/script destinations. Escaped
prefix spellings are not assumed to have their raw-source meaning.

Percent-encoding is preserved only in plain HTML text and a narrow skeleton
of fixed, inert, attribute-free wrapper tags. Attributes, raw-text/script
bodies, decoded values, sanitized-fragment composition and remote-script
contexts are not generalized into this protection.

## Validation and remaining limits

- 255 focused local tests pass, including the previously exposed 40 cases
  and semantic-boundary regressions. Existing URL regression expectations
  were updated for the browser's fixed root-relative navigation scheme;
  this explicitly excludes later server-side query re-rendering.
- Exposed browser regression: 20/20 dangerous candidates, 18/20 bounded-safe
  examples, two safe examples inconclusive, zero false candidates, zero
  dangerous examples reported safe. All twenty dangerous fixture markers
  executed in Chromium; no safe fixture marker executed.
- Fresh frozen synthetic evaluation: 9/12 dangerous candidates, three
  dangerous inconclusive examples; 10/12 bounded-safe, two safe inconclusive
  examples; zero false candidates and zero dangerous examples reported safe.
  All twelve dangerous fixtures executed in Chromium, no safe marker did.
- New audit candidate recall is **75%**, below the predeclared 90% gate.
  `DO_NOT_PROMOTE` remains the recorded outcome. The remaining dangerous
  abstentions are a body-mutated loop counter, named message handler and
  nested helper calls. No engine changes were made after viewing this audit.

The new cases were hashed before the first score. The first browser attempt
aborted when a javascript URL replaced the document before DOM capture; only
the harness was changed to capture the synchronous nonce assignment and
allow a missing output element, then the unchanged engine/cases were rerun.
The manifest records that retry. The author knows prior development patterns:
this is a fresh synthetic evaluation, **not an external blind benchmark**.
The cases are now exposed and must not be reported as unseen in later work.

Reports are in `docs/evaluations/xss_v7_regression_report.json` and
`docs/evaluations/xss_v7_fresh_report.json`; cases and source hashes are in
`evaluation/fixtures/xss_scope_url_v7_*`. They evaluate deterministic source
analysis, not learned weights or real-world exploitability. Every browser
request is intercepted locally or aborted, and each case has a new isolated
context and nonce. Safe no-execution evidence applies to the tested inputs
and bounded fixture semantics only.

## Reproduce

```sh
python -m pip install tree-sitter==0.25.2 tree-sitter-javascript==0.25.0 playwright==1.55.0
python -m playwright install chromium
python -m evaluation.xss_scope_url_v7_evaluate \
  --cases evaluation/fixtures/xss_scope_url_v7_regression.jsonl \
  --output results/v7_regression.json --regression-gate
python -m evaluation.xss_scope_url_v7_evaluate \
  --cases evaluation/fixtures/xss_scope_url_v7_fresh.jsonl \
  --manifest evaluation/fixtures/xss_scope_url_v7_fresh_manifest.json \
  --output results/v7_fresh.json
```

CI gates on the exposed regression, not a claim of independent accuracy or
production promotion. No model training, live target scanning or model
promotion is performed by this change.
