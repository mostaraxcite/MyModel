# Source-based conditional XSS diagnostics V11

This stage reviews the V10 intake instead of manufacturing a 200-case
benchmark. Twenty-four original source fragments were frozen with author
semantic review: 15 unsafe **under declared fixture input-control conditions**
and 9 bounded-safe output fixtures. The other 33 intake locations retain
explicit review/dependency reasons; some are additional writes covered by the
selected complete SVG callback, not extra independent examples.

The unchanged engine is PR32, revision
`e45e0ccaa811bdcb16e78306c591e991d976b6ba`. CI restores and verifies that package
inside this diagnostic job before scoring, so future engine PRs are not blocked
by a requirement to leave the production package unchanged. Original fragments, source/context hashes,
case hash and real jQuery 4.0.0 bytes are frozen before any scores are observed.
The vendor is MIT-licensed with its upstream copyright/license header retained;
the original Git blob hash also verifies it was not replaced by a fixture stub.

## Runtime conditions and labels

The harness supplies attacker-controlled text, form values and attributes via
safe DOM APIs. Original statements turn them into HTML. Their executable
markup is only a per-case random marker, captured by the browser. For callbacks,
the original complete callback is retained and called with explicit typed DOM
receivers or editor fixture objects; additional application callbacks are not
claimed safe. Fixed markup, numeric SVG geometry and existing DOM-node moves
have semantic safe reasons independent of a payload's nonexecution.

All browser requests are fulfilled from local strings/vendor bytes or aborted.
The browser never accesses original application targets. DOM setup is excluded
from static input; the evaluator does not insert a synthetic `window.name` or
other recognized source to make the analyzer succeed. Anonymous callback
fragments are bound to a name for parseable static input; this wrapper does
not supply a caller source or silently upgrade a function body into a whole
application assessment.

These fixtures establish conditional output behavior, not attacker access in
original applications. Actual callers, trust boundaries and original library
versions still require application-specific review. jQuery 4.0.0 is the tested
dependency, not an assertion about the historical application's installed version.

## Independence and sampling

The reviewer is explicitly `assistant-engine-author`, not a fabricated
independent reviewer. The complete development/training inventory remains
unverified. Selected source fragments are correlated: CodeQL DOM-input cases
share a lineage, and copied Prism/MyBB examples are grouped with their
application origins. Nine safe fixtures do not mean nine independent pattern
families. This corpus cannot establish production recall, false-positive rate
or learned-weight performance; the 100+100 independent protocol is not met.

All outcomes remain visible. Browser/label mismatch fails verification rather
than silently relabeling examples. Static abstentions count as recall misses.
Metrics are descriptive on this conditional corpus; printed Wilson intervals
are nominal and do not account for these lineage correlations. After any use
to modify the engine, these cases must remain exposed regression fixtures.

## Reproduce

```
python -m evaluation.external_conditional_v11 \
  --output results/xss-external-conditional-v11.json
```

The output retains exact inputs, browser marker/error/network evidence, static
statuses and separate rates. CI uploads the complete report and prints it as
`V11_EXTERNAL_CONDITIONAL_EVIDENCE`. No training, adapter inference or model
promotion occurs.

## Recorded first-run evidence

GitHub run [38372645071](https://github.com/mostaraxcite/MyModel/actions/runs/38372645071)
verified head `be4e393643d2dda5ae755967d1d43d84aff4eb3b` with Chromium 140.0.7339.16.
All 24 fixtures completed without JavaScript errors or browser/label mismatches.
The report is retained in `docs/evaluations/xss_external_conditional_v11_report.json`.

| Conditional-corpus observation | Count |
|---|---:|
| Unsafe fixtures executing marker in browser | 15 / 15 |
| Unsafe fixtures statically reaching candidate | 0 / 15 |
| Unsafe fixtures statically reported safe | 0 / 15 |
| Unsafe fixtures statically inconclusive | 15 / 15 |
| Safe fixtures producing static alerts | 0 / 9 |
| Safe fixtures statically bounded-safe | 4 / 9 |
| Safe fixtures statically inconclusive | 5 / 9 |
| Decisive static judgments | 4 / 24 |

The observed candidate recall is zero **on these selected conditional DOM-input
fixtures**, not a universal model accuracy score. Static snippets omit harness
trust assumptions, and neither a DOM value nor a function named `html` proves
attacker control or authentic jQuery identity by itself. Current unresolved
DOM getters/library methods show an unsupported practical source/sink family;
abstention avoids a false safety claim but does not provide detection coverage.

Next engine work needs verified DOM identity and caller/input trust provenance,
plus an explicitly supported library model for HTML-vs-text and getter-vs-setter
operations. It must not trust arbitrary function names or blanket-mark all DOM
values attacker-controlled. These 24 cases are now exposed diagnostics; any
future repair result on them is regression performance. A new independently
reviewed corpus is still required, and no learned model was tested here.
