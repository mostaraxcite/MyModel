"""Build field-level semantic supervision for the XSS specialist.

Each row supervises exactly one structural task (SOURCE, SINK, or DEFENSE).
This avoids asking one whole-snippet classifier to infer three different concepts.
No vulnerability verdict is emitted and locked benchmarks are never read.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path

from xss_specialist.multitask import (
    SOURCE_LABELS, SINK_LABELS, DEFENSE_LABELS, IGNORE_INDEX,
)

ROOT = Path(__file__).resolve().parents[1]


TRAIN = {
    "source": {
        "NONE": [
            "'hello'", '"static"', "42", "true", "config.siteTitle",
            "constValue", "DEFAULT_NAME", '"fixed text"',
        ],
        "BROWSER": [
            "location.hash", "location.search", "document.referrer", "window.name",
            "document.URL", "document.documentURI", "localStorage.badValue",
            "sessionStorage['input']", "event.data", "message.data",
        ],
        "SERVER": [
            "req.query.q", "req.body.name", "req.params.id", "request.query.term",
            "request.body.comment", "request.params.slug", "$_GET['q']", "$_POST['name']",
        ],
        "FRAMEWORK": [
            "props.value", "props.html", "route.params.slug", "router.query.q",
            "paramMap.get('id')", "params.userInput", "ctx.params.name", "pageProps.content",
        ],
        "OTHER": [
            "externalQueue.read()", "process.env.USER_TEXT", "stdin.read()",
            "messageBus.next()", "customInput.value", "thirdParty.payload",
            "socketMessage.body", "pluginContext.data",
        ],
    },
    "sink": {
        "NONE": [
            "return VALUE", "VALUE.length", "JSON.parse(VALUE)", "const copy = VALUE",
            "items.push(VALUE)", "cache.set('k', VALUE)",
        ],
        "DANGEROUS_HTML": [
            "el.innerHTML = VALUE", "el.outerHTML = VALUE", "document.write(VALUE)",
            "document.writeln(VALUE)", "el.insertAdjacentHTML('beforeend', VALUE)",
            "$('#out').html(VALUE)", "<div dangerouslySetInnerHTML={{__html: VALUE}} />",
        ],
        "DANGEROUS_JS": [
            "eval(VALUE)", "window.eval(VALUE)", "Function(VALUE)()",
            "setTimeout(VALUE, 0)", "setInterval(VALUE, 100)",
            "new Function(VALUE)()",
        ],
        "DANGEROUS_URL": [
            "anchor.href = VALUE", "image.src = VALUE", "form.action = VALUE",
            "frame.src = VALUE", "script.src = VALUE", "link.href = VALUE",
        ],
        "SAFE_OUTPUT": [
            "el.textContent = VALUE", "el.innerText = VALUE",
            "el.insertAdjacentText('beforeend', VALUE)", "$('#out').text(VALUE)",
            "textNode.nodeValue = VALUE",
        ],
        "OTHER": [
            "auditLog.write(VALUE)", "telemetry.emit(VALUE)", "logger.info(VALUE)",
            "customRenderer.consume(VALUE)", "queue.publish(VALUE)", "unknownSink(VALUE)",
        ],
    },
    "defense": {
        "NONE": [
            "[NO_DEFENSE]", "DIRECT_TO_SINK", "UNSANITIZED", "NO_TRANSFORM",
        ],
        "SANITIZATION": [
            "DOMPurify.sanitize(VALUE)", "purifier.sanitize(VALUE)",
            "sanitizeHtml(VALUE)", "xssFilter.process(VALUE)", "sanitize(VALUE)",
        ],
        "CONTEXTUAL_ENCODING": [
            "escapeHtml(VALUE)", "htmlspecialchars(VALUE, ENT_QUOTES)",
            "encodeForHtml(VALUE)", "escapeAttribute(VALUE)",
            "encodeURIComponent(VALUE)",
        ],
        "FRAMEWORK_ESCAPING": [
            "<div>{VALUE}</div>", "<span>{VALUE}</span>",
            "{{ VALUE }}", "v-text=\"VALUE\"", "renderText(VALUE)",
        ],
        "SAFE_DOM_API": [
            "el.textContent = VALUE", "el.innerText = VALUE",
            "el.insertAdjacentText('beforeend', VALUE)", "$('#out').text(VALUE)",
            "document.createTextNode(VALUE)",
        ],
        "INPUT_CONSTRAINT": [
            "/^https?:\\/\\//.test(VALUE)", "allowedProtocols.has(new URL(VALUE).protocol)",
            "VALID_SCHEMES.includes(new URL(VALUE).protocol)",
            "validator.isURL(VALUE, { protocols: ['http','https'] })",
            "VALUE.startsWith('https://')",
        ],
        "OTHER": [
            "customGuard(VALUE)", "securityTransform(VALUE)", "normalizeInput(VALUE)",
            "policy.apply(VALUE)", "unknownProtection(VALUE)",
        ],
    },
}


DEV = {
    "source": {
        "NONE": ["'constant'", "0", "false", "settings.heading", "STATIC_TEXT"],
        "BROWSER": [
            "window.location.hash", "window.location.search", "document.cookie",
            "window.localStorage.token", "window.sessionStorage.note", "evt.data",
        ],
        "SERVER": [
            "req.query.search", "req.body.bio", "request.params.key",
            "request.body.message", "$_GET['name']", "$_POST['comment']",
        ],
        "FRAMEWORK": [
            "props.description", "route.params.id", "router.query.redirect",
            "paramMap.get('slug')", "ctx.params.term", "pageProps.body",
        ],
        "OTHER": [
            "externalStream.read()", "process.env.RAW_INPUT", "channel.receive()",
            "extensionPayload.value", "integration.data",
        ],
    },
    "sink": {
        "NONE": [
            "return String(VALUE)", "const result = VALUE", "store.push(VALUE)",
            "JSON.stringify(VALUE)",
        ],
        "DANGEROUS_HTML": [
            "target.innerHTML = VALUE", "container.outerHTML = VALUE",
            "document.write(String(VALUE))", "target.insertAdjacentHTML('afterbegin', VALUE)",
            "$('.slot').html(VALUE)", "<section dangerouslySetInnerHTML={{__html: VALUE}} />",
        ],
        "DANGEROUS_JS": [
            "eval(String(VALUE))", "globalThis.eval(VALUE)", "Function('return ' + VALUE)()",
            "setTimeout(VALUE, 1)", "setInterval(VALUE, 10)",
        ],
        "DANGEROUS_URL": [
            "button.formAction = VALUE", "iframe.src = VALUE", "a.href = VALUE",
            "object.data = VALUE", "base.href = VALUE",
        ],
        "SAFE_OUTPUT": [
            "target.textContent = VALUE", "target.innerText = String(VALUE)",
            "target.insertAdjacentText('afterbegin', VALUE)", "$('.slot').text(VALUE)",
        ],
        "OTHER": [
            "metrics.record(VALUE)", "eventBus.emit(VALUE)", "printer.output(VALUE)",
            "extensionSink(VALUE)",
        ],
    },
    "defense": {
        "NONE": ["[NO_PROTECTION]", "RAW_VALUE", "DIRECT_USE"],
        "SANITIZATION": [
            "DOMPurify.sanitize(String(VALUE))", "cleaner.sanitize(VALUE)",
            "sanitizeHtml(String(VALUE))", "htmlSanitizer.clean(VALUE)",
        ],
        "CONTEXTUAL_ENCODING": [
            "escapeHTML(VALUE)", "encodeForAttribute(VALUE)",
            "htmlEncode(VALUE)", "encodeURI(VALUE)",
        ],
        "FRAMEWORK_ESCAPING": [
            "<p>{String(VALUE)}</p>", "<label>{VALUE}</label>",
            "{{ String(VALUE) }}", "safeInterpolation(VALUE)",
        ],
        "SAFE_DOM_API": [
            "target.textContent = String(VALUE)", "target.innerText = VALUE",
            "target.insertAdjacentText('afterbegin', VALUE)", "document.createTextNode(String(VALUE))",
        ],
        "INPUT_CONSTRAINT": [
            "new URL(VALUE).protocol === 'https:'",
            "['http:','https:'].includes(new URL(VALUE).protocol)",
            "VALUE.match(/^https:\\/\\//)", "isAllowedUrl(VALUE)",
        ],
        "OTHER": [
            "projectPolicy(VALUE)", "customSanitizerMaybe(VALUE)",
            "transformSecurityValue(VALUE)", "guardPlugin.apply(VALUE)",
        ],
    },
}


def label_index(task: str, label: str) -> int:
    spaces = {
        "source": SOURCE_LABELS,
        "sink": SINK_LABELS,
        "defense": DEFENSE_LABELS,
    }
    return spaces[task].index(label)


def mutate(text: str, n: int, rng: random.Random) -> str:
    prefixes = ["", "const tmp = ", "let tmp = ", "value = "]
    suffixes = ["", ";", " /* reviewed field */"]
    if n % 4 == 0 and not text.startswith(("<", "{{", "[", "/")):
        return prefixes[rng.randrange(len(prefixes))] + text + suffixes[rng.randrange(len(suffixes))]
    return text + suffixes[rng.randrange(len(suffixes))]


def build(split: str, per_expression: int, seed: int) -> list[dict]:
    table = TRAIN if split == "train" else DEV
    rng = random.Random(seed)
    rows = []
    for task, classes in table.items():
        for label, expressions in classes.items():
            for expr_i, expr in enumerate(expressions):
                for n in range(per_expression):
                    field = mutate(expr, n, rng)
                    row = {
                        "id": f"semantic-field-v4:{split}:{task}:{label}:{expr_i}:{n}",
                        "text": f"[{task.upper()}]\n{field}",
                        "source_label": IGNORE_INDEX,
                        "sink_label": IGNORE_INDEX,
                        "defense_label": IGNORE_INDEX,
                        "flow_label": IGNORE_INDEX,
                        "metadata": {
                            "origin": "semantic-field-v4",
                            "split": split,
                            "task": task,
                            "label": label,
                            "base_expression": expr,
                        },
                    }
                    row[f"{task}_label"] = label_index(task, label)
                    rows.append(row)
    rng.shuffle(rows)
    return rows


def digest(row: dict) -> str:
    return hashlib.sha256(row["text"].encode()).hexdigest()


def task_counts(rows: list[dict], task: str, labels: list[str]) -> dict:
    out = {x: 0 for x in labels}
    key = f"{task}_label"
    for row in rows:
        value = int(row[key])
        if value != IGNORE_INDEX:
            out[labels[value]] += 1
    return out


def write(path: Path, rows: list[dict]):
    path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output-dir", type=Path, default=ROOT / "data" / "semantic-field-v4")
    p.add_argument("--train-repeat", type=int, default=12)
    p.add_argument("--dev-repeat", type=int, default=6)
    p.add_argument("--seed", type=int, default=8081)
    args = p.parse_args()

    train = build("train", args.train_repeat, args.seed)
    dev = build("dev", args.dev_repeat, args.seed + 1)
    overlap = {digest(r) for r in train} & {digest(r) for r in dev}
    if overlap:
        raise SystemExit(f"semantic field train/dev overlap: {len(overlap)}")

    manifest = {
        "schema": "xss-semantic-field-v4",
        "train_rows": len(train),
        "dev_rows": len(dev),
        "exact_text_overlap": 0,
        "task_formulation": "field-level masked multi-head",
        "whole_snippet_xss_target": False,
        "locked_hard_or_external_used": False,
        "train": {
            "source": task_counts(train, "source", SOURCE_LABELS),
            "sink": task_counts(train, "sink", SINK_LABELS),
            "defense": task_counts(train, "defense", DEFENSE_LABELS),
        },
        "dev": {
            "source": task_counts(dev, "source", SOURCE_LABELS),
            "sink": task_counts(dev, "sink", SINK_LABELS),
            "defense": task_counts(dev, "defense", DEFENSE_LABELS),
        },
    }
    for split in ("train", "dev"):
        for task, labels in (
            ("source", SOURCE_LABELS), ("sink", SINK_LABELS), ("defense", DEFENSE_LABELS)
        ):
            missing = [name for name in labels if manifest[split][task][name] == 0]
            if missing:
                raise SystemExit(f"missing {split}/{task} classes: {missing}")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write(args.output_dir / "train.jsonl", train)
    write(args.output_dir / "dev.jsonl", dev)
    (args.output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
