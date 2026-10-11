"""Frozen, independently authored synthetic XSS code review cases.

Expected labels indicate static, potentially exploitable source-to-sink paths,
NOT remotely executed or browser-confirmed vulnerabilities. NEVER use for training.
All pairs keep the source constant and vary the security-relevant operation.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

CASES = [
    # Explicit taint-to-sink pairs. Repeated source names do not indicate
    # the same generated code families used to fine-tune the adapter.
    ("fragment-dom-unsafe", "dom-html", "vulnerable", "const cardValue = window.location.hash.substring(1);\nprofileCard.insertAdjacentHTML('beforeend', cardValue);"),
    ("fragment-dom-safe", "dom-html", "safe", "const cardValue = window.location.hash.substring(1);\nprofileCard.insertAdjacentText('beforeend', cardValue);"),
    ("search-dom-unsafe", "dom-html", "vulnerable", "const b = new URLSearchParams(location.search).get('bio');\ndocument.querySelector('#bio').outerHTML = b;"),
    ("search-dom-safe", "dom-html", "safe", "const b = new URLSearchParams(location.search).get('bio');\ndocument.querySelector('#bio').textContent = b;"),
    ("message-dom-unsafe", "cross-window", "vulnerable", "addEventListener('message', evt => { document.querySelector('#notice').innerHTML = evt.data; });"),
    ("message-dom-safe", "cross-window", "safe", "addEventListener('message', evt => { document.querySelector('#notice').innerText = evt.data; });"),
    ("write-unsafe", "document-write", "vulnerable", "const t = new URL(location.href).searchParams.get('t');\ndocument.write('<p>' + t + '</p>');"),
    ("write-safe", "document-write", "safe", "const t = new URL(location.href).searchParams.get('t');\ndocument.querySelector('#message').append(document.createTextNode(t));"),
    ("iframe-unsafe", "srcdoc", "vulnerable", "const html = new URLSearchParams(location.search).get('embed');\ndocument.querySelector('iframe#preview').srcdoc = html;"),
    ("iframe-safe", "srcdoc", "safe", "const html = new URLSearchParams(location.search).get('embed');\ndocument.querySelector('iframe#preview').title = html;"),
    ("attribute-unsafe", "dom-attr", "vulnerable", "const handler = new URLSearchParams(location.search).get('handler');\ndocument.querySelector('#save').setAttribute('onclick', handler);"),
    ("attribute-safe", "dom-attr", "safe", "const handler = new URLSearchParams(location.search).get('handler');\ndocument.querySelector('#save').setAttribute('aria-label', handler);"),
    ("eval-unsafe", "js-code", "vulnerable", "const evalBody = window.location.hash.slice(1);\n(0, eval)(evalBody);"),
    ("eval-safe", "js-code", "safe", "const evalBody = window.location.hash.slice(1);\nconsole.log(evalBody);"),
    ("function-unsafe", "js-code", "vulnerable", "let suppliedScript = new URLSearchParams(location.search).get('code');\nnew Function(suppliedScript)();"),
    ("function-safe", "js-code", "safe", "let suppliedScript = new URLSearchParams(location.search).get('code');\nJSON.stringify(suppliedScript);"),
    ("timeout-unsafe", "js-code", "vulnerable", "let callbackText = new URLSearchParams(location.search).get('callback');\nsetTimeout(callbackText, 100);"),
    ("timeout-safe", "js-code", "safe", "let callbackText = new URLSearchParams(location.search).get('callback');\nsetTimeout(() => console.log(callbackText), 100);"),
    ("javascript-url-unsafe", "url", "vulnerable", "const dest = new URLSearchParams(location.search).get('next');\nwindow.location.href = dest;"),
    ("javascript-url-safe", "url", "safe", "const dest = new URLSearchParams(location.search).get('next');\nconst candidate = new URL(dest, location.origin);\nif (candidate.origin === location.origin && candidate.protocol === 'https:') window.location.href = candidate.href;"),
    ("attribute-url-unsafe", "url", "vulnerable", "const target = new URLSearchParams(location.search).get('link');\nnavLink.setAttribute('href', target);"),
    ("attribute-url-safe", "url", "safe", "const target = new URLSearchParams(location.search).get('link');\nnavLink.setAttribute('data-target', target);"),
    ("sanitizer-unsafe", "sanitizer", "vulnerable", "const post = new URLSearchParams(location.search).get('post');\narticleBox.innerHTML = post;"),
    ("sanitizer-safe", "sanitizer", "safe", "const post = new URLSearchParams(location.search).get('post');\narticleBox.innerHTML = DOMPurify.sanitize(post);"),
    ("unrelated-source-unsafe", "taint-tracing", "vulnerable", "let tainted = location.hash.slice(1);\nlet fallback = 'All good';\nheader.innerHTML = tainted;"),
    ("unrelated-source-safe", "taint-tracing", "safe", "let tainted = location.hash.slice(1);\nlet fallback = 'All good';\nheader.innerHTML = fallback;"),
    ("override-unsafe", "taint-tracing", "vulnerable", "let x = location.hash.slice(1);\nx = x.trim();\nbox.innerHTML = x;"),
    ("override-safe", "taint-tracing", "safe", "let x = location.hash.slice(1);\nx = 'constant-only';\nbox.innerHTML = x;"),
    ("branch-unsafe", "control-flow", "vulnerable", "const s = new URLSearchParams(location.search).get('preview');\nif (s !== null) outputArea.innerHTML = s;"),
    ("branch-safe", "control-flow", "safe", "const s = new URLSearchParams(location.search).get('preview');\nif (s !== null) outputArea.textContent = s;"),
    ("storage-unsafe", "storage", "vulnerable", "const memo = sessionStorage.getItem('userMemo');\nmemoArea.insertAdjacentHTML('afterbegin', memo);"),
    ("storage-safe", "storage", "safe", "const memo = sessionStorage.getItem('userMemo');\nmemoArea.replaceChildren(document.createTextNode(memo));"),
    ("decoded-unsafe", "encoding", "vulnerable", "const label = decodeURIComponent(new URLSearchParams(location.search).get('label'));\nitem.innerHTML = label;"),
    ("decoded-safe", "encoding", "safe", "const label = decodeURIComponent(new URLSearchParams(location.search).get('label'));\nitem.textContent = label;"),
    ("html-encoded-unsafe", "encoding", "vulnerable", "const label = new URLSearchParams(location.search).get('label');\nitem.innerHTML = decodeURIComponent(label);"),
    ("html-encoded-safe", "encoding", "safe", "const label = new URLSearchParams(location.search).get('label');\nitem.textContent = decodeURIComponent(label);"),
    ("promise-unsafe", "async-flow", "vulnerable", "Promise.resolve(new URLSearchParams(location.search).get('profile')).then(x => panel.innerHTML = x);"),
    ("promise-safe", "async-flow", "safe", "Promise.resolve(new URLSearchParams(location.search).get('profile')).then(x => panel.textContent = x);"),
    ("json-field-unsafe", "nested-data", "vulnerable", "const data = JSON.parse(decodeURIComponent(location.hash.slice(1)));\nviewer.innerHTML = data.description;"),
    ("json-field-safe", "nested-data", "safe", "const data = JSON.parse(decodeURIComponent(location.hash.slice(1)));\nviewer.textContent = data.description;"),
    ("array-unsafe", "transform", "vulnerable", "const words = new URLSearchParams(location.search).getAll('word');\nresult.innerHTML = words.join(' ');"),
    ("array-safe", "transform", "safe", "const words = new URLSearchParams(location.search).getAll('word');\nresult.textContent = words.join(' ');"),
    ("reduce-unsafe", "transform", "vulnerable", "const chunks = location.hash.slice(1).split(',');\nnode.innerHTML = chunks.reduce((x,y) => x + y, '');"),
    ("reduce-safe", "transform", "safe", "const chunks = location.hash.slice(1).split(',');\nnode.textContent = chunks.reduce((x,y) => x + y, '');"),
    ("static-unsafe", "source-selection", "vulnerable", "const defaultText = '<em>hi</em>';\nconst entered = location.hash.slice(1);\noutput.innerHTML = entered || defaultText;"),
    ("static-safe", "source-selection", "safe", "const defaultText = '<em>hi</em>';\nconst entered = location.hash.slice(1);\noutput.innerHTML = defaultText;"),
    ("template-unsafe", "template-string", "vulnerable", "const username = new URLSearchParams(location.search).get('user');\noutput.insertAdjacentHTML('beforeend', '<span>' + username + '</span>');"),
    ("template-safe", "template-string", "safe", "const username = new URLSearchParams(location.search).get('user');\nconst el = document.createElement('span'); el.textContent = username; output.append(el);"),
]

SYSTEM = "you are a helpful assistant."
PREAMBLE = (
    "You are an XSS analysis specialist for AUTHORIZED security testing and defensive review. "
    "Analyze the code for cross-site scripting only. Be precise about execution context and "
    "distinguish OBSERVED facts (present in the code) from INFERRED conclusions and from what "
    "is NOT ESTABLISHED. Do not label code vulnerable without an untrusted source reaching a "
    "sink in an executing context. If safety cannot be established, say so rather than guessing."
)
OUTPUT_FORMAT = """Respond in EXACTLY this format, one field per line:
Classification: <vulnerable|safe>
Confidence: <0.0-1.0>
Source: <untrusted source, or none>
Transformations: <encoders/sanitizers applied, or none>
Sink: <the sink, or none>
Execution Context: <html_text|html_attr|html_attr_url|js_string|js_code|url|css|dom_html|dom_attr|unknown>
Existing Defense: <contextual_encoding|sanitization|csp|trusted_types|framework_escaping|safe_dom_api|input_constraint|none>
Root Cause: <one line, or none if safe>
Evidence: <OBSERVED/INFERRED/NOT_ESTABLISHED note>
Missing Evidence: <what would change the verdict, or none>
Risk Explanation: <one line>
Recommended Validation: <how to confirm safely>
Remediation: <the fix, or none if safe>
References: <e.g. OWASP/CWE-79, or none>"""


def prompt(code: str) -> str:
    return f"{PREAMBLE}\n\nAnalyze this javascript code for XSS:\n\n```javascript\n{code}\n```\n\n{OUTPUT_FORMAT}\n"


def cases() -> list[dict]:
    records = [
        {"id": ident, "family": family, "label": verdict, "code": code, "prompt": prompt(code)}
        for ident, family, verdict, code in CASES
    ]
    assert len(records) == len({x["id"] for x in records})
    assert {x["label"] for x in records} == {"safe", "vulnerable"}
    return records


def assert_no_training_overlap(training_file: Path) -> dict:
    """Check exact prompt/snippet overlap with ALL rows, including earlier eval split."""
    known = set()
    for line in training_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        question = row["messages"][0]["content"]
        known.add(hashlib.sha256(question.strip().encode()).hexdigest())
        import re
        match = re.search(r"```javascript\n(.*?)\n```", question, re.S)
        if match:
            known.add(hashlib.sha256(match.group(1).strip().encode()).hexdigest())
    overlaps = []
    for case in cases():
        keys = (
            hashlib.sha256(case["prompt"].strip().encode()).hexdigest(),
            hashlib.sha256(case["code"].strip().encode()).hexdigest(),
        )
        if any(key in known for key in keys):
            overlaps.append(case["id"])
    if overlaps:
        raise ValueError("Frozen held-out corpus overlaps SFT training/eval: " + ",".join(overlaps))
    return {"cases": len(CASES), "positives": sum(x[2] == "vulnerable" for x in CASES),
            "negatives": sum(x[2] == "safe" for x in CASES),
            "exact_overlaps": 0, "basis": "static synthetic source-to-sink code review"}
