# Frozen XSS V5 static audit results — 2026-10-13

This record preserves the **first and only run** of the newly authored
24-case static flow suite, under the exact analyzer revision that includes
bounded callback, numeric for-loop, URL link and external-script sinks.

## Provenance

- V5 implementation: https://github.com/mostaraxcite/MyModel/pull/26
- Frozen synthetic audit suite: https://github.com/mostaraxcite/MyModel/pull/27
- Evaluated analyzer revision: 683356c6acf974b7ae0c72e39121cc06052cb69a
- GitHub Actions audit: https://github.com/mostaraxcite/MyModel/actions/runs/38315457687
- Original 24-case JSON report:
  https://github.com/mostaraxcite/MyModel/actions/runs/38315457687/artifacts/11776457702

This suite was authored after the previous audit; it is still a
synthetic, manually labeled code review test, **not** real-world XSS
exploitability or browser execution confirmation.

## Observed confusion matrix

| Reviewed static class | CANDIDATE | Bounded SAFE | INCONCLUSIVE | Total |
|---|---:|---:|---:|---:|
| Potentially unsafe source-to-execution path | 6 | 0 | 2 | 8 |
| Locally safe path | 0 | 6 | 2 | 8 |
| Insufficient information | 0 | 0 | 8 | 8 |

- Candidate recall on potentially unsafe patterns: **75%** (6/8).
- False-safe on potentially unsafe patterns: **0%** (0/8).
- False-positive candidate alerts on reviewed safe examples: **0%** (0/8).
- Safe-example abstention: **25%** (2/8).
- Correct abstention on underspecified examples: **100%** (8/8).
- Three-way decision coverage: **50%** (12/24).
- Browser-confirmed executions: **zero**.
- Production promotion: **DO_NOT_PROMOTE**.

The previous 16-case static audit scored **0/5 candidate recall**
and 12.5% coverage, but the two suites use different code examples,
review categories and feature combinations. This is encouraging
coverage evidence, not a statistically controlled before-and-after
improvement or a general 75% detection rate on live web applications.

## Next steps

The successful V5 internal regression suite consisted of 293 passing
Python tests, and the separate frozen 24-case suite yielded two
potentially unsafe examples that still abstained. Keep these cases
as historical evidence rather than using them repeatedly as unseen
acceptance tests. Obtain exact case IDs and diagnostic limitations from
the **already archived** report using the read-only workflow
"Inspect Frozen XSS V5 Audit Artifact".

Work on new development examples for additional asynchronous
scheduling, Promise/callback propagation, inert text-node replacement,
and same-origin URL builder semantics; then use a *new* audit for
independent validation. Never promote a speculative static candidate
to browser-confirmed XSS without controlled execution evidence.

Original V1/V2/V3 model checkpoints are preserved. V5 evaluated only
deterministic local AST rules and used neither GPU training nor scans
of external targets.
