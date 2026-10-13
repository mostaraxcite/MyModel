# Controller-collected DOM context V13

V12's manual fixture input/receiver profile is now replaceable by a capture
made by the trusted test controller **before** it delivers the original
fragment. The existing isolated browser harness exposes that precise capture
boundary; without a callback, historical execution remains unchanged.

The collector parses selector requests from the snippet without executing it.
It queries actual first elements and records existence/count/tag, then derives
input-read fields only when their values equal the controller's fresh marker.
Authentic jQuery DOM selections referenced by the snippet may become external
bindings; a node is movable only after bounded inert-subtree inspection.
Fields, selectors and bindings are measured, not copied from the V12 profile.
Escaped/invalid/oversized selectors, ambiguous global bindings and unsupported
nodes are omitted or rejected rather than guessed.

The known, hash-checked jQuery 4.0.0 bytes are delivered by the fixture
controller. Trusted setup retains baseline function identities. Capture checks
actual library aliases/method references and selected native DOM API/getter
identities against that baseline; method/version names alone cannot establish
authenticity. Only ordinary DOM receivers are admitted. This is a controlled
fixture boundary, not a probe that certifies an already-running hostile page.

## Receipt integrity and lifetime

A live controller session keeps a random signing key in memory. Capture
receipts bind the observations to source bytes, vendor hash, frame URL,
fresh marker, monotonic capture time and session. A MAC detects edits;
verification also rejects another source/session, expired evidence and replay.
The key is never written in the report. The trusted controller must retain
exclusive access to the session object. Untrusted code/model JSON cannot
assert its own verification flag or supply an authoritative session.

The adapter derives the conditional DOM context after authenticating the
receipt and passes it to the grounded analyzer. Its result records integrity
verification separately from semantic trust and browser XSS confirmation.
Saved receipts alone cannot authorize later analysis: the original live
session/key is needed. Reports remain inspectable through their hashes and
retained observations, but they are not portable credentials.

## Limits

Equality to a marker establishes the test controller's input in this local
fixture. It does not establish attacker access to production DOM fields.
The controller/setup, known vendor delivery and pre-execution boundary are
trusted. Receipt authenticity does not certify representative sampling,
independent label review or whole-application safety. Manual contextual API
input remains explicitly unverified; this adapter does not relabel it trusted.

This stage runs no live target scan, adds no learned-weight inference and
provides no automatic global policy for unrelated sites. The original cases
are exposed regression fixtures. Independent 100 unsafe + 100 safe review is
still incomplete.

## Validation

Local checkout: 432 tests passed, including 13 new receipt/selector tests.
CI collects actual entry-state observations for all 24 original V11 fragments,
reviews them using those observations and rechecks runtime execution. Three
additional browser checks alter a jQuery method, alter a native getter and
remove the controlled input marker. No manual source/selector profile is used.
The pipeline retains every observation, receipt and per-case decision;
rejected context and runtime negatives remain visible rather than being
counted as safe benchmark samples.

```
python -m evaluation.browser_context_v13_regression \
  --output results/xss-browser-context-v13.json
```
