# New XSS static review benchmark — 2026-10-13

This is a **new manually authored, synthetic** test suite with 42 source
snippets, not scraped or replayed live targets. It is disjoint from the
earlier frozen 48-case suite and the V3 generated training examples at
the **exact-snippet** level. Similar XSS concepts still occur in both.
It is not a browser-confirmed real-world XSS exploitability benchmark
and is not suitable for claiming 100% real-world security performance.

## Dataset design and frozen partitions

- 15 potentially unsafe static source-to-sink flows.
- 15 locally safe paths (text APIs, trusted sanitization, inert attributes,
  non-executable outputs).
- 12 snippets that cannot be classified defensibly without additional
  provenance, context or policy.
- 26 **diagnostic** examples used to identify and correct bounded
  analyzer gaps.
- 16 **reserved audit** examples, scored only after the code was finalized.

Static predictions have three values: CANDIDATE, SAFE (bounded local path)
and INCONCLUSIVE (abstention). Browser-confirmed cases: **zero**.
A candidate is not proof of exploitability; an inconclusive verdict is
neither a false negative nor a correct positive.

Metrics include unsafe candidate recall, unsafe false-safe rate,
unsafe abstentions, safe false-positive rate, safe abstentions,
needs-review overclaim rate, and overall decision coverage.

## Diagnostic baseline observed on GitHub

Initial CI workflow: https://github.com/mostaraxcite/MyModel/actions/runs/38310909318

- Potentially unsafe flows: 10 / 10 CANDIDATE.
- Locally safe: 6 / 9 SAFE, 1 / 9 false positive, 2 / 9 abstentions.
- Needs-review: 7 / 7 INCONCLUSIVE.
- Coverage: 17 / 26.

An explicit misclassification involved the result of
encodeURIComponent reaching an HTML markup parser. Percent-encoding
the entire untrusted value prevents forming literal HTML delimiters
in this specific context. It is not a universal JavaScript or URL
sanitization strategy.

The two safe-path abstentions involved an inert data attribute and
document.createTextNode followed by appendChild. The new bounded
analyzer rules recognize those patterns without treating arbitrary
dynamic attributes or appended nodes as safe.

## Current diagnostic result

After the narrow context-specific fixes:

- 10/10 unsafe flows marked CANDIDATE.
- 9/9 locally safe paths marked SAFE (0 false positives).
- 7/7 needs-review paths left INCONCLUSIVE.
- Coverage: 19/26 = 73.08%.

The corrected diagnostic CI run:
https://github.com/mostaraxcite/MyModel/actions/runs/38311268929
completed with **260 passing Python tests**.

This result **must not** be treated as independent generalization
performance: we deliberately adjusted code using the diagnostic split.

## Audit and reproducibility

After merging, GitHub Actions workflow
"Audit New XSS Static Suite (One-Time)" runs the 16 reserved audit
cases on the merged revision, prints a compact metric report and saves
all per-case diagnostics as an Actions artifact. It runs locally
without a browser, payload execution, live scanning or GPU usage.

Manually run only diagnostic cases while modifying logic:

    uv run python -m evaluation.fresh_static_xss_suite --partition diagnostic

Score audit after freezing the code:

    uv run python -m evaluation.fresh_static_xss_suite --partition audit

All model checkpoints V1, V2, V3 are preserved. This change evaluates
**the deterministic oracle**, not Spark fine-tuning or browser detection.
It never promotes an adapter to MyHunt/PentesterFlow.


## Locked audit outcomes — first and only audit scoring

The reserved audit was run once **after merging the context-specific fixes**.
The job did not train a model, test browser exploitation, or call any remote
target. This report is the definitive pre-next-development audit snapshot.

- GitHub Actions run: https://github.com/mostaraxcite/MyModel/actions/runs/38311578941
- Raw case-by-case artifact: https://github.com/mostaraxcite/MyModel/actions/runs/38311578941/artifacts/11775221270
- Audited source revision: 44998e30d0ee7be83287c5978cd3d492b73f15a6

| Metric | Diagnostic (tuned) | Audit (never tuned) |
|---|---:|---:|
| Potentially unsafe CANDIDATE | 10/10 | **0/5** |
| Potentially unsafe SAFE | 0/10 | 0/5 |
| Potentially unsafe INCONCLUSIVE | 0/10 | **5/5** |
| Safe CANDIDATE (false alerts) | 0/9 | **0/6** |
| Safe correctly classified | 9/9 | **2/6** |
| Safe INCONCLUSIVE | 0/9 | **4/6** |
| Needs-review INCONCLUSIVE | 7/7 | **5/5** |
| Decision coverage | 73.08% | **12.5%** |

The audit result does NOT mean 100% real-world XSS false negatives;
these examples are static and all five potentially unsafe paths
abstained instead of being mislabeled SAFE. But **0/5 candidate recall**
is a serious capability/coverage failure. The apparently perfect
diagnostic score was not predictive of new pattern families.

Observed next coverage work includes callback/cross-window flow,
loop effects, URL attributes/schemes, dynamic script destinations,
safe Node.append/replaceChildren, and side-effect-free logging.
These are **suggestions for future rule development, not validated fixes**.
Further engineering must use a newly authored diagnostic set and a
new held-out audit, rather than reusing this now-exposed audit for
model selection or reporting it as independent accuracy.

The production/promotion decision remains DO_NOT_PROMOTE.
