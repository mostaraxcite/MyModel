# Bounded named handlers, helper chains and counter strides (V8)

V7's frozen synthetic audit left three dangerous paths inconclusive: a named
message handler, a nested pure helper call and a literal loop-counter update
in the body. Those examples are now exposed development regressions.

The known function-declaration registry can resolve a named message handler,
`window.onmessage` assignment or resolved-Promise callback. Assignments,
unknown effects or lost identity prevent resolution. Captured surrounding
constants, DOM identities and helper identities are not trusted as safe
asynchronous snapshots; parameters and callback-local declarations remain
separate. Plain already-observed outer taint may still yield a candidate.
Later outer writes and caller shadowing cannot certify a captured HTML path
as safe.

Direct straight-line helpers can call other known helpers, with at most
three active calls and 64 total helper invocations. Recursion, unknown calls,
effects, excess depth and unresolved free variables abstain. All local
bindings are initialized at function entry to avoid accidentally using a
same-named caller variable in a declaration's temporal dead zone.

A literal increasing `for` loop can include top-level `counter++`,
`++counter` or `counter += positiveInteger` body updates. Their fixed stride
is combined with the header increment. Conditional/dynamic counter writes,
counter shadowing, arbitrary calls in the body of a counter-updating loop,
more than eight body executions or more than 64 total nested loop executions
abstain. These are AST proofs of a small numeric bound, not JS execution.

## Verification protocol

- 307 focused local tests passed, including the original 40 exposed cases,
  V7's now-exposed 24 cases, recursion/scope/identity and counter boundaries.
- Static regression on V7's exposed audit now yields all 12 dangerous cases
  as candidates; ten safe cases are bounded-safe, two remain inconclusive.
  Runtime verification is performed by GitHub's intercepted Chromium job.
- 24 new synthetic cases (12 unsafe, 12 safe) and the three engine files
  were hashed before any score. The author knows development patterns;
  this is a fresh synthetic audit, not an external blind benchmark.
- The fresh partition is scored only on the initial PR `opened` event.
  CI's later runs use exposed regressions. No engine tuning follows this
  fresh audit; future fixes require a new partition.
- Model weights, production exploitability and live external targets are
  not evaluated. `DO_NOT_PROMOTE` remains the recorded model outcome.

CI retains JSON proof artifacts with fresh nonces and locally fulfilled or
aborted browser requests. The initial fresh report and final CI results are
recorded after the GitHub job completes. The captured-variable and helper
depth boundaries may legitimately leave additional dangerous examples
inconclusive; they must not be relabeled safe or dropped from the score.

## Recorded first audit outcome

GitHub run `38358941957` completed successfully: **444 core tests passed**,
and intercepted Chromium verified the original 40 and exposed V7 24 cases.
All 32 dangerous regression fixtures were candidates and executed; zero safe
regression fixtures executed and zero false candidate alerts occurred.

The fresh V8 24-case audit produced 10/12 dangerous candidates (**83.33%**),
two dangerous inconclusive cases, ten bounded-safe cases and two safe
inconclusive cases. Chromium executed all twelve dangerous fixtures, none of
the safe ones; zero dangerous examples were reported SAFE and zero false
candidate alerts occurred. The fresh audit still fails its predeclared 90%
recall gate. CI success verifies tests and evidence generation, not this
accuracy gate or learned-weight production eligibility.

The two dangerous abstentions are a captured variable changed after callback
registration and a four-helper chain beyond the three-active-call bound.
These limitations are retained; no engine tuning followed the fresh score.
The corresponding constant-text capture and four-helper fixed-return safe
cases were also inconclusive. The first outcome is preserved in
`docs/evaluations/xss_v8_fresh_report.json`. The full per-path packet artifact
is attached to the initial workflow run.

Initial evaluated engine commit: `b1ffc7166cced10778cc435cd277eaa0bbab038d`.
This follow-up records results only; the engine source hashes remain exactly
those in the frozen manifest. This partition is now exposed.

