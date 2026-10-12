# XSS AST Specialist V5 — bounded browser message, loop and URL flows

This engineering iteration follows the **first untouched 16-case synthetic
static audit** (2026-10-13). That audit had 0/5 unsafe candidates, 0/6
false positive alerts, and 12.5% decision coverage: the analyzer abstained
on all five dangerous examples. It should **never** be retuned and re-reported
as an independent test after seeing the case-level errors.

## New bounded capabilities

- A literal window.addEventListener('message', handler) or global
  addEventListener('message', handler) with exactly one function parameter
  is examined as a potential asynchronous source. The parameter is
  tainted with canonical message-event.data provenance; only AST-observed
  sinks in the callback yield a candidate. Unrecognized event kinds and
  callbacks remain inconclusive. No browser code is executed.
- Literal increasing for(let i=N;i<M;i++) loops with at most eight
  iterations are walked statically. All other loop constructs, unbounded
  loops and unknown effects abstain, rather than assuming safety.
- A URL assigned to a proven anchor's href, setAttribute('href',...)
  or window.location.href is treated as a potential script URL context.
- A URL assigned to an element proven to be a script element by a literal
  document.createElement('script') or querySelector('script') is a
  potential remote-script execution context. Arbitrary .src on an
  untyped element is not automatically a script sink.
- A literal root-relative path prefix immediately followed by a single
  encodeURIComponent(untrustedValue) is a narrowly verified safe
  URL construction. javascript: prefixes, protocol-relative URLs,
  raw attacker inputs or later decoding are NOT treated as protected.
- Known browser console logging does not invalidate an otherwise static
  constant sink, unless console was shadowed.
- Unreviewed calls and branches can invalidate previously known DOM tag
  identity. An unknown mutation never establishes a safe sink.

The oracle still emits CANDIDATE / bounded SAFE / INCONCLUSIVE, not
browser-confirmed XSS. Spark's advisory cannot rewrite the oracle evidence,
conceal candidates or declare confirmation.

## Test boundaries

The V5 PR runs new development tests and the existing regression suite.
It does NOT reuse the exposed 16-case audit to tune the logic.
A new, deliberately frozen synthetic audit should be executed only
after implementation and tests pass, and still cannot establish actual
exploitability in deployed sites. Framework-specific DOM mutation,
cross-function aliasing, complex loops, dynamically constructed
callbacks, user-controlled eval identity and browser security policies
remain beyond this bounded static AST review.

No Kaggle model training, live web requests, production deployment, or
MyHunt/PentesterFlow model promotion is performed.
