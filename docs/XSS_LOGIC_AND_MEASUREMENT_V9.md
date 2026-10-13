# Correct local XSS logic and honest measurement (V9)

The specialist must establish an untrusted input, a connected value path, an
interpreting output sink and the absence of a context-compatible protection.
Unsupported flow stays inconclusive. A static candidate is not browser
confirmation; bounded-safe output is not whole-application safety.

## Logic repaired

Program-level message/Promise registrations whose callbacks read captured
globals are revisited after synchronous program statements. Only a direct
top-level registration and a globally declared or inline callback qualify.
Provisional captured paths are replaced, not duplicated. A later connected
source can create a candidate; a later fixed overwrite does not retain a
registration-time false alert. Cross-scope closures, captured object identity
or sanitization assumptions, unknown effects and more than 32 deferred
registrations do not establish safety. Deferral is one bounded pass, not a
browser event-loop simulator or arbitrary inter-callback scheduling proof.
An unsupported effect after registration blocks deferred capture upgrading:
a later source assignment cannot prove that a removed or altered listener
still runs. Such paths remain inconclusive.

Acyclic pure helpers now use known identity, active-stack cycle detection
and a 64-invocation work budget rather than an arbitrary three-call cutoff.
Unknown/free caller bindings, effects, getters, recursion and exhausted work
still abstain. No untrusted JavaScript is executed by the AST reviewer.

## What each percentage means

| Measure | Denominator / interpretation |
|---|---|
| Dangerous-candidate recall | Dangerous candidates / all reviewed dangerous cases, including abstentions and untested cases |
| Candidate precision | Dangerous / all adjudicated candidate alerts; undefined for zero alerts or alerts lacking adjudicated labels |
| False-positive rate | Safe cases alerted / all reviewed safe cases |
| Dangerous reported SAFE | Explicit unsafe-to-SAFE errors; separate from abstention |
| Decision coverage | Candidate or bounded-safe decisions / all supplied cases |
| Test coverage | Tested cases / all supplied cases |
| Abstention | Report separately for unsafe and safe classes |

There is no single production-accuracy scalar. Invalid labels/IDs are rejected,
not dropped. Percentages from different partitions cannot be presented as a
before/after gain: `compare_same_cases` verifies the case hash, IDs, source and
labels. Browser non-execution is negative evidence for the tested input, not
a safe ground-truth label by itself.

Wilson 95% intervals show **nominal binomial sampling uncertainty**. They do
not establish external validity for selected synthetic or correlated cases.
For the prior 10/12 dangerous result (83.33%), the nominal recall interval is
55.20%–95.30%. Even 12/12 observed dangerous candidates gives a nominal lower
bound of about 75.75%; zero alerts on twelve safe cases has an upper nominal
false-positive bound of about 24.25%. Thus small perfect examples cannot prove
population recall ≥90% or false-positive rate ≤5%.

Unit-test success is a code-regression result. Repeated templates are not
independent samples; source families, repeated code hashes and unresolved
labels remain visible. A point threshold or interval threshold never enables
learned-model promotion in this evaluator.

## Required external validation

All 40+24+24 historical cases are now **exposed development regressions**.
V9 reports them as such and retires automatic rescoring of the frozen V8
manifest as a fresh audit on later PRs. No rotating synthetic percentage is
reported as independent production accuracy.

The next independent measurement needs a separate reviewed external corpus:

1. Freeze the engine and corpus before scoring; retain immutable source
   repository revisions, paths, fixture context and case/code hashes.
2. Split by source repository and pattern family, not random near-duplicate
   snippets. Exclude development/training inputs and record the complete
   inventory. Simple whitespace fingerprints are only a copy check; a clean
   fingerprint result cannot prove no semantic leakage or renamed templates.
3. Start with at least 100 reviewed unsafe and 100 reviewed safe cases from
   at least five disjoint repositories and ten families. These are minimum
   protocol checks, not a guarantee of representative or independent sampling.
4. Keep positive execution/source-to-sink evidence for unsafe labels and
   reviewed semantic justification for safe labels. Reviewers should be
   separate from engine authors. An unexecuted browser payload alone does not
   establish safety.
5. Report every case and class, confidence intervals appropriate to the
   sampling plan, and results by source group. Correlated repository/template
   cases require group-aware inference rather than treating every row as iid.
6. Score the locked external set once. After viewing errors or using them to
   change the engine, classify that set as exposed regression and obtain a
   new independent set for the next release decision.

`holdout_protocol.audit_holdout` checks metadata, overlap, source grouping,
review evidence and sample sizes. It deliberately does not certify reviewer
identity, actual unseen status, complete training inventory or population
representativeness from self-declared metadata. Those need independent
verification. The current synthetic corpus fails this external protocol.

No adequately verified external holdout or learned-weight evaluation is
provided by V9. Production accuracy remains unestablished. No training, live
target scan or model promotion is performed.

## Reproduce

CI verifies all 88 exposed fixtures with intercepted Chromium and prints
`V9_DIAGNOSTIC_EVIDENCE`. It uploads per-case browser reports, all decision
counts, nominal intervals, a comparison on the identical V8 cases and the
external-holdout rejection reasons. Final run results are recorded after CI.
