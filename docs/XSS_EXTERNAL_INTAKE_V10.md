# External source intake V10

The engine remains frozen at `e45e0ccaa811bdcb16e78306c591e991d976b6ba`
(merged PR #32). This stage does not change the engine or rescore the 88
exposed cases as independent evidence.

Six complete files from five repositories were retrieved at immutable
revisions. The inventory retains original content hashes and URLs. AST-based
intake found 57 potential output locations and retains exact statement text
and enclosing function/program byte ranges. These are **review locations**,
not 57 vulnerabilities or 57 independent labelled samples.

| Source repository | Revision | File(s) |
|---|---|---|
| semgrep/semgrep-rules | 9bbf021d0acffa3095fcffd17b2bc7787eb4796d | dom-based-xss.js; raw-html-concat.js |
| github/codeql | 4af6ba60e60683f482a583f9d444f1286abafd1f | XssThroughDom/xss-through-dom.js |
| mybb/mybb | 897593d36d2db00ac09dd0c0379595354538b85a | jscripts/bbcodes_sceditor.js |
| mbraak/jqTree | d6b8d11c4ebd7aa4a60498786bc94724b6f6ffda | lib/dragAndDropHandler.js |
| PrismJS/prism | 8403e4537b2fdc23435b7235ad082df1f6e6c6e4 | plugins/previewers/prism-previewers.js |

## Label review blockers found during sourcing

Upstream `ok`, `Alert` and `ruleid` comments describe the upstream query's
expectations. They are not ground-truth XSS labels:

- The CodeQL source deliberately substitutes an identity function named
  `DOMPurify.sanitize` to test query modeling. Treating its name as proof of
  real sanitization would create an incorrect safety label.
- A Semgrep test declares `newContent` inside each branch and returns it
  outside those blocks. That exact example requires runtime/reachability
  review; its annotation cannot prove exploitable execution.
- Original application files require caller, library and input context.
  Merely finding a jQuery call or SVG attribute is not proof of XSS.
- The selected benchmark files are related to the application files via
  upstream references. Five repository names do not establish five
  independent pattern groups. Source lineage must be retained when splitting.

Every intake candidate stays `needs_review`, `NOT_TESTED`, with browser status
`not_tested`. No unsafe/safe accuracy denominator is manufactured. Scanning
public files and reading their annotations does not prove independence from
the complete training inventory, which remains unverified.

## Reproduce preparation

```
python -m evaluation.external_source_intake \
  --sources evaluation/fixtures/xss_external_sources_v10.json \
  --engine-revision e45e0ccaa811bdcb16e78306c591e991d976b6ba \
  --output results/xss-external-intake-v10.json
pytest tests/test_external_source_intake.py tests/test_decision_metrics.py tests/test_holdout_protocol.py
```

Preparation performs no static scoring, JavaScript execution or live target
scan. Source hashes and offsets are reproducible. The extractor is intentionally
not exhaustive: dynamic APIs, constructor-based jQuery HTML and non-DOM sinks
can need manual intake. Original files are source evidence, not a runtime fixture.

## Next acceptance requirements

Produce at least 100 reviewed unsafe and 100 reviewed safe cases, retaining
original contexts, source lineage and independent semantic review. Verify the
full development/training inventory, group-disjoint sampling plan, and browser
execution for unsafe labels. Freeze the corpus before scoring, report all
abstentions, and use group-aware uncertainty. No independent reviewer identity
or runtime evidence was fabricated here. The 57 pending locations do not meet
this gate. No learned weights were available or evaluated in this stage;
production accuracy and model promotion remain unestablished.
