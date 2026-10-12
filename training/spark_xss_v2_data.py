"""Build audited Spark XSS v2 SFT corpus from prior training records.

First LoRA had 17/24 false positives. The v3 corpus had 85 positive vs
16 negative examples in a group dominated by typo sanitizer calls that
may throw before the sink is reached. Drop that group; never use
the independent test set as training data.
"""
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import re

BASE = Path("data/training/sft_v3.jsonl")
OUTPUT = Path("data/training/sft_v4_balanced.jsonl")
FENCE = chr(96) * 3

SOURCES = [
    ("visitorNote", "new URLSearchParams(window.location.search).get('publicNote')", "location.search"),
    ("currentEntry", "decodeURIComponent(window.location.hash.substring(1))", "location.hash"),
    ("requestedTitle", "new URL(window.location.href).searchParams.get('entry')", "location.search"),
    ("encodedInput", "String(new URLSearchParams(document.location.search).get('hint') ?? '')", "location.search"),
    ("pageValue", "window.location.hash.slice(1)", "location.hash"),
    ("searchTerm", "new URLSearchParams(location.search).get('item')", "location.search"),
    ("routeText", "new URL(location.href).searchParams.get('draft')", "location.search"),
    ("promptValue", "decodeURIComponent(location.hash.slice(1))", "location.hash"),
]

# Each pair holds the tainted source constant, changing only the
# security-relevant operation or a taint-killing re-assignment.
# family, potentially unsafe code, defended code, sink, safe sink, defense, context.
PAIRS = [
    ("dom-insert", "entry.insertAdjacentHTML('beforeend', $X);", "entry.insertAdjacentText('beforeend', $X);", "insertAdjacentHTML", "insertAdjacentText", "safe_dom_api", "dom_html"),
    ("dom-text", "entry.innerHTML = $X;", "entry.textContent = $X;", "innerHTML", "textContent", "safe_dom_api", "dom_html"),
    ("dom-replace", "entry.outerHTML = $X;", "entry.replaceChildren(document.createTextNode($X));", "outerHTML", "createTextNode", "safe_dom_api", "dom_html"),
    ("doc-write", "document.write($X);", "document.body.append(document.createTextNode($X));", "document.write", "createTextNode", "safe_dom_api", "dom_html"),
    ("frame-srcdoc", "document.querySelector('#previewPane').srcdoc = $X;", "document.querySelector('#previewPane').title = $X;", "srcdoc", "title", "safe_dom_api", "dom_html"),
    ("attr-event", "document.querySelector('#sendButton').setAttribute('onmouseover', $X);", "document.querySelector('#sendButton').setAttribute('aria-label', $X);", "setAttribute(onmouseover)", "setAttribute(aria-label)", "safe_dom_api", "dom_attr"),
    ("eval-code", "(0, eval)($X);", "console.info($X);", "eval", "console.info", "safe_dom_api", "js_code"),
    ("function-code", "const perform = new Function($X); perform();", "const display = String($X); console.info(display);", "new Function", "String", "safe_dom_api", "js_code"),
    ("timer-code", "setTimeout($X, 50);", "setTimeout(() => console.debug($X), 50);", "setTimeout(string)", "setTimeout(function)", "safe_dom_api", "js_code"),
    ("link-protocol", "document.querySelector('#readMore').href = $X;", "document.querySelector('#readMore').href = '/view?text=' + encodeURIComponent($X);", "href", "href(path)", "input_constraint", "html_attr_url"),
    ("navigation-protocol", "window.location.assign($X);", "window.location.assign('/profile?name=' + encodeURIComponent($X));", "location.assign", "location.assign(path)", "input_constraint", "url"),
    ("html-sanitizer", "const htmlSnippet = $X; entry.innerHTML = htmlSnippet;", "const htmlSnippet = DOMPurify.sanitize($X); entry.innerHTML = htmlSnippet;", "innerHTML", "DOMPurify.sanitize+innerHTML", "sanitization", "dom_html"),
    ("async-html", "Promise.resolve($X).then(value => entry.innerHTML = value);", "Promise.resolve($X).then(value => entry.textContent = value);", "innerHTML", "textContent", "safe_dom_api", "dom_html"),
    ("array-join", "const chunks = [$X, '']; entry.innerHTML = chunks.join('');", "const chunks = [$X, '']; entry.textContent = chunks.join('');", "innerHTML", "textContent", "safe_dom_api", "dom_html"),
    ("taint-kill", "let preview = $X; entry.innerHTML = preview;", "let preview = $X; preview = 'static fallback'; entry.innerHTML = preview;", "innerHTML(tainted)", "innerHTML(constant)", "input_constraint", "dom_html"),
    ("event-property", "document.querySelector('#action').onclick = new Function($X);", "document.querySelector('#action').title = $X;", "onclick(new Function)", "title", "safe_dom_api", "js_code"),
    ("markup-concat", "entry.insertAdjacentHTML('beforeend', '<b>' + $X + '</b>');", "const boldNode = document.createElement('b'); boldNode.textContent = $X; entry.append(boldNode);", "insertAdjacentHTML", "textContent", "safe_dom_api", "dom_html"),
    ("flow-branch", "const alternate = 'welcome'; const result = $X; entry.innerHTML = result;", "const alternate = 'welcome'; const result = $X; entry.innerHTML = alternate;", "innerHTML(tainted)", "innerHTML(constant)", "input_constraint", "dom_html"),
]


def answer(*, vulnerable, source, sink, safe_sink, family, defense, context):
    if vulnerable:
        fields = [
            "Classification: vulnerable", "Confidence: 0.86",
            f"Source: {source}", "Transformations: none", f"Sink: {sink}",
            f"Execution Context: {context}", "Existing Defense: none",
            f"Root Cause: Attacker-influenced input reaches {sink} without appropriate contextual protection.",
            f"Evidence: OBSERVED: source-to-sink path in {family}; runtime execution NOT_ESTABLISHED.",
            "Missing Evidence: Browser execution and deployment conditions have not been verified.",
            f"Risk Explanation: {sink} can parse untrusted markup or run script if relevant browser conditions hold.",
            "Recommended Validation: Check the flow and runtime behavior using a locally authorized fixture.",
            f"Remediation: Use {safe_sink} or apply context-appropriate encoding and validation.",
            "References: OWASP/CWE-79",
        ]
    else:
        transform = ("DOMPurify.sanitize" if defense == "sanitization" else
                     "constant overwrite" if family in ("taint-kill", "flow-branch") else
                     "path encoding" if family in ("link-protocol", "navigation-protocol") else "none")
        fields = [
            "Classification: safe", "Confidence: 0.92",
            f"Source: {source}", f"Transformations: {transform}",
            f"Sink: {safe_sink}", f"Execution Context: {context}",
            f"Existing Defense: {defense}", "Root Cause: none",
            f"Evidence: OBSERVED: {safe_sink} does not expose this untrusted value to an executing sink.",
            "Missing Evidence: none for the path shown; surrounding code not evaluated.",
            "Risk Explanation: The shown data flow does not execute attacker-controlled code.",
            "Recommended Validation: Verify API semantics and check surrounding code for alternate flows.",
            "Remediation: none", "References: OWASP/CWE-79",
        ]
    return "\n".join(fields) + "\n"


def build(base=BASE, output=OUTPUT):
    if output.resolve() == base.resolve():
        raise ValueError("Do not overwrite v3")
    rows = [json.loads(line) for line in base.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(rows) != 359:
        raise ValueError(f"Unexpected source version: {len(rows)}")
    originals = [r for r in rows if len(r.get("tags", [])) > 1 and r["tags"][0] == "train"]
    if len(rows) - len(originals) != 101:
        raise ValueError("Unexpected number of excluded speculative examples")
    # Collapse any exact duplicates of older SFT examples, not merely IDs.
    stable, seen = [], set()
    for row in originals:
        key = row["messages"][0]["content"]
        if key in seen:
            continue
        seen.add(key)
        stable.append(row)
    fence = FENCE + "javascript\n"
    sample = next(r for r in stable if fence in r["messages"][0]["content"])
    skeleton = sample["messages"][0]["content"]
    code_pattern = re.compile(re.escape(fence) + r".*?\n" + re.escape(FENCE), re.S)
    generated = []
    for family, bad, good, unsafe_sink, safe_sink, defense, context in PAIRS:
        for i, (variable, expression, src) in enumerate(SOURCES):
            declaration = f"const {variable} = {expression};"
            import_line = "import DOMPurify from 'dompurify';\n" if family == "html-sanitizer" else ""
            for vulnerable, suffix, sink in ((True, bad, unsafe_sink), (False, good, safe_sink)):
                code = import_line + declaration + "\n" + suffix.replace("$X", variable)
                prompt = code_pattern.sub(lambda _: fence + code + "\n" + FENCE, skeleton, count=1)
                if prompt == skeleton or code not in prompt:
                    raise ValueError("Failed to inject synthetic training snippet")
                generated.append({
                    "case_id": f"v2-{family}-{'v' if vulnerable else 's'}-{i:03d}",
                    "vulnerable": vulnerable, "origin": "synthetic",
                    "tags": ["train", "v2_" + family],
                    "messages": [
                        {"role": "user", "content": prompt},
                        {"role": "assistant", "content": answer(
                            vulnerable=vulnerable, source=src, sink=sink,
                            safe_sink=safe_sink, family=family,
                            defense=defense, context=context,
                        )},
                    ],
                })
    new_prompts = [row["messages"][0]["content"] for row in generated]
    if len(new_prompts) != len(set(new_prompts)):
        raise ValueError("Duplicate generated prompts")
    if set(new_prompts) & seen:
        raise ValueError("Generated example duplicates earlier SFT")
    combined = stable + generated
    labels = Counter("vulnerable" if row["vulnerable"] else "safe" for row in combined)
    if abs(labels["vulnerable"] - labels["safe"]) > 0.05 * len(combined):
        raise ValueError(f"Imbalanced corpus: {labels}")
    ids = [r["case_id"] for r in combined]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate case ID")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in combined), encoding="utf-8")
    manifest = {
        "status": "CURATED_SYNTHETIC_NOT_TRAINED",
        "base_sha256": sha256(base.read_bytes()).hexdigest(),
        "dataset_sha256": sha256(output.read_bytes()).hexdigest(),
        "retained_v3": len(stable),
        "excluded_speculative_or_nearmiss": len(rows) - len(originals),
        "new_pairs": len(generated) // 2,
        "new_records": len(generated), "total_records": len(combined),
        "labels": dict(labels), "new_families": len(PAIRS),
        "promotion": "NOT_EVALUATED",
    }
    (output.parent / (output.stem + "_manifest.json")).write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


if __name__ == "__main__":
    print(json.dumps(build(), indent=2))
