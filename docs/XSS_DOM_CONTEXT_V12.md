# Explicit DOM identity/input context V12

V11 exposed fifteen runtime-executing DOM-input fixtures that the snippet-only
engine left inconclusive. This change adds an **opt-in conditional context**,
not blanket tainting of DOM text or recognition of any function named html.
The old snippet-only behavior remains available and unchanged.

`analyze`, `review_evidence`, and `grounded_review` accept `dom_context` with:

- An evidence reference for externally reviewed runtime assertions.
- Authentic jQuery global identities and exact known receiver selectors.
- Exact selectors and reviewed input-read fields (value, text, properties or
  specific attributes). Unlisted fields are not inferred untrusted or safe.
- Optional typed external DOM/jQuery bindings. Node movement is safe only
  when that binding is explicitly reviewed as inert.

The engine checks metadata structure, not the truth of the assertions. Reports
retain a context hash, `verified_by_engine: false`, conditional source status
and conditional explanations. A caller or model must not fabricate this
context from names, source keywords or a desired classification.

## Supported bounded operations

Literal reviewed document selections and authentic jQuery selections support
first-element `.get(0)`/`[0]`, exact nested `.find` selectors, native DOM reads,
native getAttribute reads, and jQuery value/text/HTML/property/attribute reads.
Getter and setter arity is distinguished. Authentic html(value) is an HTML
sink; text/value/inert-attribute setters are non-HTML output. Existing nodes
are movable only under the explicit inert-node assertion. Aliases preserve
typed identity when the base analyzer preserves their binding.

Shadowed roots/globals, unresolved effects, arbitrary attribute names,
unlisted/missing receivers and nonzero indices abstain. Writes invalidate
entry-time DOM assumptions instead of retaining stale input taint after a
fixed overwrite. Asynchronous callbacks do not inherit entry-time DOM
assertions; their later identities and values need a separate runtime review.
Unknown or effectful helpers retain existing conservative behavior.

The fixture profile is only for the isolated V11 runtime: genuine jQuery 4.0.0,
known existing ordinary DOM receivers, and inputs supplied through safe DOM
APIs. It is not an application-wide production policy. The scanner does not
automatically activate it on unrelated sites. Broader binding models,
selector cardinalities, callback scheduling and external mutation remain
unsupported. Additional native/library side effects remain inconclusive.

## Use

```
python -m xss_specialist.grounded_advisor snippet.js \
  --dom-context-json reviewed-context.json
```

The option is also available on the taint analyzer CLI. It does not run
JavaScript or contact a target. Model advisory fields still cannot add trust,
override paths or assert browser confirmation.

## Validation and interpretation

Local checkout: 419 tests passed. Forty-six contextual tests cover the exposed
24 fixtures plus shadowing, unknown effects, writes, getter/setter arity,
native reads, alias tracking, same-named fake methods, unreviewed selectors,
nonzero indices, inert-node assumptions and invalid context metadata.

The new browser regression reuses unchanged original fragments and the real
V11 dependency; all requests are locally fulfilled or aborted. It records
both snippet-only and contextual judgments and the complete runtime evidence.
Default and contextual scoring have **different input assumptions**, so they
are not an independent accuracy gain or an unchanged-input population
comparison. These examples are exposed regressions. Independent 100+100
adjudication and learned-weight evaluation remain incomplete. No promotion.

## Retained GitHub evidence

Run [38378668474](https://github.com/mostaraxcite/MyModel/actions/runs/38378668474)
verified head `e57bd40d7c58d1f5eb3a37739cc6d271ca651eb0`.
Core CI run 38378668117 passed 502 tests; the DOM job passed all 46 new
contextual tests and verified every original browser fixture without errors.
The complete retained result is `docs/evaluations/xss_dom_context_v12_report.json`.

| Supplied-context regression result | Count |
|---|---:|
| Unsafe candidates with explicit fixture context | 15 / 15 |
| Unsafe reported SAFE | 0 / 15 |
| False alerts on safe fixtures | 0 / 9 |
| Safe fixtures with a decisive verdict | 6 / 9 |
| Safe abstentions | 3 / 9 |
| Total decision coverage | 21 / 24 (87.5%) |

Without context, those same fifteen unsafe snippets still abstain. This is a
new conditional analysis capability, not automatic trust inference. The three
safe abstentions are complete SVG numeric/editor callbacks whose invocation
and side effects remain outside this bounded static support. Runtime execution
was separately checked using the original fixture. Independent corpus and
learned-model accuracy remain unestablished.
