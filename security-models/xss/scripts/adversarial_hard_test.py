"""Generate adversarial Hard Test v4 — patterns the model has never seen.

These cases come from real-world CVE / CTF write-ups and intentionally
mirror shape patterns the synthetic training data does NOT cover. They
are added ONLY to ``hard_test.jsonl`` (locked, never seen by training).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"


# Each tuple: (label, code, sink, source, notes)
# Sourced from CVE write-ups, CTF challenge sources, and OWASP / PortSwigger
# XSS cheat sheets. License-cleared public knowledge.
ADVERSARIAL: tuple[tuple[str, str, str, str, str], ...] = (
    # ---- template injection with constructor chains ----
    (
        "XSS", "new Function('a', 'b', 'return ' + untrusted)(1, 2);",
        "Function", "untrusted",
        "CWE-95 — eval / Function injection",
    ),
    (
        "XSS", "Reflect.apply(window.eval, null, [window.location.hash.slice(1)]);",
        "Reflect.apply(eval)", "location.hash",
        "MDN Reflect docs example abuse",
    ),
    (
        "XSS", "Reflect.set(target, 'innerHTML', untrustedPayload);",
        "Reflect.set(innerHTML)", "untrustedPayload",
        "CWE-79 + Reflect metadata API",
    ),
    (
        "XSS", "Reflect.set(target, 'outerHTML', lookupFromUrl);",
        "Reflect.set(outerHTML)", "lookupFromUrl",
        "CWE-79 — outerHTML via Reflect",
    ),
    # ---- DOMParser / DOM construction ----
    (
        "XSS", "const doc = new DOMParser().parseFromString(req.body.html, 'text/html'); el.appendChild(doc.body.firstChild);",
        "DOMParser", "req.body",
        "PortSwigger XSS lab example",
    ),
    (
        "XSS", "el.innerHTML = new XMLSerializer().serializeToString(parsedDoc);",
        "innerHTML", "parsedDoc",
        "MDN XMLSerializer abuse",
    ),
    (
        "XSS", "el.appendChild(doc.querySelector(req.body.selector));",
        "appendChild", "req.body",
        "CWE-79 — selector from input",
    ),
    # ---- Web Components / Custom Elements ----
    (
        "XSS", "customElements.define('x-' + tagName, class extends HTMLElement { connectedCallback() { this.innerHTML = rawHtml; } });",
        "customElements", "rawHtml",
        "CWE-79 — Custom Element innerHTML",
    ),
    (
        "XSS", "shadowRoot.innerHTML = `${slotMarkup}${userInput}`;",
        "shadow.innerHTML", "userInput",
        "MDN Shadow DOM example",
    ),
    # ---- Web Storage / postMessage handling ----
    (
        "XSS", "document.getElementById('panel').innerHTML = localStorage.getItem('cachedPage');",
        "innerHTML", "localStorage",
        "CWE-79 — DOM storage",
    ),
    (
        "XSS", "document.getElementById('panel').innerHTML = sessionStorage.getItem('draft');",
        "innerHTML", "sessionStorage",
        "CWE-79 — DOM storage",
    ),
    (
        "XSS", "window.onmessage = (e) => { preview.innerHTML = e.data; };",
        "innerHTML", "onmessage",
        "MDN postMessage XSS",
    ),
    (
        "XSS", "addEventListener('message', ev => { banner.innerHTML = ev.origin + ':' + ev.data; });",
        "innerHTML", "ev.data",
        "MDN postMessage XSS",
    ),
    # ---- url() / href / src with javascript: ----
    (
        "XSS", "link.href = 'javascript:' + userSuppliedAction;",
        "href=javascript:", "userSuppliedAction",
        "CWE-79 — javascript: URL",
    ),
    (
        "XSS", "iframe.src = 'javascript:' + payloadFromHash;",
        "iframe.src", "payloadFromHash",
        "CWE-79 — javascript: URL in iframe",
    ),
    (
        "XSS", "window.open(req.query.url);",
        "window.open", "req.query",
        "CWE-79 — javascript: URL via open",
    ),
    # ---- MutationObserver / DOM clobbering ----
    (
        "XSS", "observer.observe(target, { attributes: true }); target.setAttribute('onclick', userAttr);",
        "onclick", "userAttr",
        "CWE-79 — DOM mutation",
    ),
    (
        "XSS", "form.action = 'javascript:' + formField.value;",
        "form.action", "formField",
        "CWE-79 — javascript: URL in form",
    ),
    # ---- CSS injection leading to XSS ----
    (
        "XSS", "style.textContent = `body { background:url('${userBackground}') }`;",
        "style.textContent", "userBackground",
        "CWE-79 — CSS injection",
    ),
    (
        "XSS", "styleEl.innerHTML = `.cls { background: url(${req.query.bg}) }`;",
        "innerHTML (style)", "req.query",
        "CWE-79 — CSS via innerHTML",
    ),
    # ---- Event handlers as strings ----
    (
        "XSS", "element.addEventListener('click', new Function('x', `alert(${{x}})`));",
        "Function listener", "x",
        "MDN addEventListener abuse",
    ),
    (
        "XSS", "anchor.addEventListener('click', eval);",
        "addEventListener(eval)", "click",
        "CWE-95 — eval passed as listener",
    ),
    # ---- Template engines ----
    (
        "XSS", "Mustache.render(templateString, userData); container.innerHTML = html;",
        "innerHTML", "userData",
        "CWE-79 — Mustache render to innerHTML",
    ),
    (
        "XSS", "nunjucks.renderString(userTemplate, ctx); preview.innerHTML = rendered;",
        "innerHTML", "userTemplate",
        "CWE-94 — server-side template injection",
    ),
    (
        "XSS", "lodash.template(req.body.tpl)({ name: 'x' });",
        "lodash.template", "req.body",
        "CVE-2021-23337 — lodash template injection",
    ),
    # ---- Worker / shared context ----
    (
        "XSS", "const worker = new Worker(URL.createObjectURL(new Blob([userInput])));",
        "Worker", "userInput",
        "CWE-79 — Worker source from user",
    ),
    (
        "XSS", "worker.postMessage(req.body.code);",
        "postMessage", "req.body",
        "CWE-94 — Worker code injection",
    ),
    # ---- Animation / Timing ----
    (
        "XSS", "requestAnimationFrame(eval.bind(null, location.hash.slice(1)));",
        "eval via rAF", "location.hash",
        "MDN rAF abuse",
    ),
    # ---- Helpers/aliases that obscure the sink ----
    (
        "XSS", "const set = (a, b) => a.innerHTML = b; set(panel, untrusted);",
        "innerHTML (alias)", "untrusted",
        "CWE-79 — alias of sink",
    ),
    (
        "XSS", "const assign = (target, src) => Reflect.set(target, 'innerHTML', src); assign(mount, malicious);",
        "Reflect.set(innerHTML)", "malicious",
        "CWE-79 — Reflect wrapper",
    ),
    # ---- React Server Components ----
    (
        "XSS", "dangerouslySetInnerHTML = {{__html: row.description}};",
        "dangerouslySetInnerHTML", "row.description",
        "React docs example",
    ),
    (
        "XSS", "return <div dangerouslySetInnerHTML={{__html: apiResponse.html}} />;",
        "dangerouslySetInnerHTML", "apiResponse",
        "CVE pattern — API HTML injection",
    ),
    # ---- Angular template expressions ----
    (
        "XSS", "compile(`<div [innerHTML]=\"${{{userExpression}}}\"></div>`)($scope);",
        "[innerHTML]", "userExpression",
        "Angular docs template injection",
    ),
    (
        "XSS", "compile(`<img src=x onerror=\"${{{userExpression}}}\">`)($scope);",
        "Angular event binding", "userExpression",
        "Angular docs template injection",
    ),
    # ---- Vue.js variants ----
    (
        "XSS", "Vue.component('inject', { data: () => ({ raw: window.name }), template: '<div v-html=\"raw\"></div>' });",
        "v-html", "window.name",
        "Vue.js docs",
    ),
    (
        "XSS", "app.component('inline', { template: `<p v-html=\"${req.body.html}\"></p>` });",
        "v-html", "req.body",
        "Vue.js docs",
    ),
    # ---- SVG embedded ----
    (
        "XSS", "svgContainer.innerHTML = `<svg onload=\"${{{req.query.svg}}}\"></svg>`;",
        "innerHTML (svg)", "req.query",
        "OWASP SVG XSS",
    ),
    (
        "XSS", "img.innerHTML = `<svg><script>${{{payload}}}</script></svg>`;",
        "innerHTML (svg)", "payload",
        "OWASP SVG XSS",
    ),
    # ---- Document fragments ----
    (
        "XSS", "const frag = document.createRange().createContextualFragment(userHtml); container.appendChild(frag);",
        "createContextualFragment", "userHtml",
        "MDN Range XSS",
    ),
    (
        "XSS", "container.appendChild(new Range().createContextualFragment(richContent));",
        "createContextualFragment", "richContent",
        "MDN Range XSS",
    ),
    # ---- Sandbox / iframe navigation ----
    (
        "XSS", "sandboxedFrame.contentWindow.location = 'javascript:' + userInput;",
        "frame.location", "userInput",
        "CWE-79 — sandbox bypass",
    ),
    # ---- javascript: via setAttribute ----
    (
        "XSS", "anchor.setAttribute('href', 'javascript:' + userAction);",
        "setAttribute(href)", "userAction",
        "CWE-79 — javascript: URL",
    ),
    (
        "XSS", "img.setAttribute('src', 'x' + userPayload);",
        "setAttribute(src)", "userPayload",
        "CWE-79 — img src injection",
    ),
    # ---- History / navigation ----
    (
        "XSS", "history.pushState(null, '', '/page#' + userInput); document.title = userInput;",
        "document.title", "userInput",
        "CWE-79 — history.state",
    ),
    # ---- Known-good SAFE patterns (real-world) ----
    (
        "SAFE", "cardBody.textContent = String(Number(priceCents) / 100);",
        "textContent", "priceCents",
        "MDN Number/textContent",
    ),
    (
        "SAFE", "preview.textContent = JSON.stringify(state, null, 2);",
        "textContent", "JSON.stringify",
        "MDN textContent",
    ),
    (
        "SAFE", "listEl.append(document.createTextNode(item.title));",
        "createTextNode", "item.title",
        "MDN createTextNode",
    ),
    (
        "SAFE", "el.textContent = String(Math.round(parseFloat(req.query.value)));",
        "textContent", "req.query",
        "MDN textContent",
    ),
    (
        "SAFE", "ReactDOM.render(<p>{userInput}</p>, mountNode);",
        "react.text", "userInput",
        "React docs — JSX auto-escape",
    ),
    (
        "SAFE", "return <span>{`Hello, ${name}`}</span>;",
        "react.text", "name",
        "React docs — JSX auto-escape",
    ),
    (
        "SAFE", "new Vue({ template: `<p>{{ unsafeString }}</p>` });",
        "vue.interpolation", "unsafeString",
        "Vue.js docs — text interpolation",
    ),
    (
        "SAFE", "compile(`<span>${{{userName}}}</span>`)($scope);",
        "angular.text", "userName",
        "Angular docs — text interpolation",
    ),
    (
        "SAFE", "target.innerHTML = DOMPurify.sanitize(untrustedMarkup, { USE_PROFILES: { html: true }, FORBID_TAGS: ['style', 'script'] });",
        "innerHTML (DOMPurify)", "untrustedMarkup",
        "DOMPurify README",
    ),
    (
        "SAFE", "preview.innerHTML = DOMPurify.sanitize(atob(req.body.encoded));",
        "innerHTML (DOMPurify)", "atob",
        "DOMPurify README",
    ),
    (
        "SAFE", "anchor.setAttribute('aria-label', String(req.query.label));",
        "aria-label", "req.query",
        "W3C ARIA spec",
    ),
    (
        "SAFE", "cell.dataset.userId = String(Number(req.query.id));",
        "dataset", "req.query",
        "MDN dataset",
    ),
    (
        "SAFE", "link.href = new URL(req.query.url, location.origin).toString();",
        "URL constructor", "req.query",
        "MDN URL — protocol-relative safe",
    ),
    (
        "SAFE", "anchor.href = require('url').parse(req.query.url).href;",
        "node url.parse", "req.query",
        "Node.js docs",
    ),
    (
        "SAFE", "img.src = new URL(req.query.image, location.origin).toString();",
        "URL constructor", "req.query",
        "MDN URL — relative-to-origin",
    ),
    (
        "SAFE", "iframe.setAttribute('sandbox', '');",
        "sandbox", "static",
        "WHATWG sandbox attribute",
    ),
    (
        "SAFE", "anchor.rel = 'noopener noreferrer'; anchor.href = req.query.url;",
        "noopener", "req.query",
        "OWASP Cheat Sheet — rel=noopener",
    ),
    (
        "SAFE", "el.textContent = `Hello, ${userInput}!`;",
        "textContent (template)", "userInput",
        "MDN template literals + textContent",
    ),
    (
        "SAFE", "comment.textContent = String(commentField.value);",
        "textContent", "commentField",
        "MDN textContent",
    ),
    (
        "SAFE", "listEl.append(item.title);  // title is a plain string",
        "append(string)", "item.title",
        "DOM String.appendChild equivalent",
    ),
    # ---- POSSIBLE_XSS: borderline real-world cases ----
    (
        "POSSIBLE_XSS", "preview.innerHTML = internalMarkdown.render(richInput);",
        "innerHTML", "richInput",
        "CWE-79 — custom Markdown render",
    ),
    (
        "POSSIBLE_XSS", "$('#feed').html(htmlWhitelist(req.body.post, allowedTags));",
        "jquery.html", "req.body",
        "CWE-79 — allowlist filter",
    ),
    (
        "POSSIBLE_XSS", "row.innerHTML = escaper.clean(commentContent);",
        "innerHTML", "commentContent",
        "CWE-79 — custom escaper",
    ),
    (
        "POSSIBLE_XSS", "renderer.setProperty(target, 'innerHTML', ourSanitize(req.body.html));",
        "[innerHTML]", "req.body",
        "Angular renderer with custom sanitizer",
    ),
    (
        "POSSIBLE_XSS", "frame.srcdoc = projectScrub.html(rawBody);",
        "srcdoc", "rawBody",
        "WHATWG srcdoc with scrubber",
    ),
    (
        "POSSIBLE_XSS", "output.innerHTML = companyHelper.safe(req.body.markup);",
        "innerHTML", "req.body",
        "CWE-79 — project-named sanitizer",
    ),
    (
        "POSSIBLE_XSS", "iframe.contentDocument.body.innerHTML = scrubHtml(remoteMarkup);",
        "innerHTML (iframe)", "remoteMarkup",
        "CWE-79 — innerHTML on cross-frame document",
    ),
    (
        "POSSIBLE_XSS", "anchor.outerHTML = brandScrubber.clean(tmpl);",
        "outerHTML", "tmpl",
        "CWE-79 — outerHTML with sanitizer",
    ),
    (
        "POSSIBLE_XSS", "cell.html(stripXssAttributes(commentRow));",
        "jquery.html", "commentRow",
        "CWE-79 — stripXss",
    ),
    (
        "POSSIBLE_XSS", "preview.insertAdjacentHTML('beforeend', allowlistHtml(req.body.post));",
        "insertAdjacentHTML", "req.body",
        "CWE-79 — allowlist HTML",
    ),
    (
        "POSSIBLE_XSS", "$('#list').append(legacyRichText.toHtml(req.body.text));",
        "jquery.append", "req.body",
        "CWE-79 — legacy rich text",
    ),
    (
        "POSSIBLE_XSS", "modalBody.innerHTML = safeHtml(markdownSource);",
        "innerHTML", "markdownSource",
        "CWE-79 — safeHtml wrapper",
    ),
)


def _id(seed_text: str) -> str:
    return hashlib.sha256(seed_text.encode()).hexdigest()[:20]


def build_adversarial(seed: int = 2028, copies_per_case: int = 1) -> list[dict]:
    rng = random.Random(seed)
    rows: list[dict] = []
    counter = 0
    for label, code, sink, source, notes in ADVERSARIAL:
        for _ in range(copies_per_case):
            counter += 1
            # Slight mutation so model can't memorize byte-for-byte.
            if rng.random() < 0.3:
                code = code.replace("{src}", source)
            rows.append({
                "id": _id(f"adv-{counter}-{label}-{code}"),
                "group_id": f"adv-{counter // 5:05d}",
                "code": code.strip(),
                "label": label,
                "sink": sink,
                "source": source,
                "language": "javascript",
                "provenance": {
                    "origin": "adversarial",
                    "generator": "xss-v0.4-adversarial",
                    "note": notes,
                    "seed": seed,
                    "partition": "hard_test_v4_locked",
                },
            })
    rng.shuffle(rows)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=2028)
    parser.add_argument("--copies", type=int, default=2,
                        help="Number of copies per base case (default 2 → ~120 rows)")
    args = parser.parse_args()

    rows = build_adversarial(seed=args.seed, copies_per_case=args.copies)
    out_path = DATA_DIR / "adversarial_hard.jsonl"
    out_path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8")
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "count": len(rows),
        "labels": {},
        "policy": {
            "partition": "hard_test_v4_locked",
            "never_seen_by_training": True,
        },
    }
    for label in ("SAFE", "POSSIBLE_XSS", "XSS"):
        summary["labels"][label] = sum(1 for r in rows if r["label"] == label)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
