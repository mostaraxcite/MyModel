"""Build the deterministic, group-disjoint XSS-SLM v0.1 dataset."""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
from collections import Counter
from pathlib import Path


LABELS = ("SAFE", "POSSIBLE_XSS", "XSS")
SOURCES = ("location.hash", "location.search", "userInput", "message.data", "req.query.q")
TARGETS = ("result", "preview", "panel", "output", "container")
SANITIZERS = ("DOMPurify.sanitize", "sanitizeHtml", "escapeHtml")
DANGEROUS = (
    "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", ".html(",
    ".append(", "dangerouslySetInnerHTML", "v-html", "[innerHTML]", "srcdoc", "srcDoc",
    "onclick", "setAttribute('on", "eval(", "'ev' + 'al'", "setTimeout(", "new Function(",
    "outer' + 'HTML",
)


def _id(group_id: str, label: str, code: str) -> str:
    raw = f"{group_id}\0{label}\0{code}".encode()
    return hashlib.sha256(raw).hexdigest()[:20]


def _record(group_id: str, code: str, label: str, sink: str, source: str) -> dict:
    return {
        "id": _id(group_id, label, code),
        "group_id": group_id,
        "code": code,
        "label": label,
        "sink": sink,
        "source": source,
        "language": "javascript",
        "provenance": {"origin": "synthetic", "generator": "xss-v0.1"},
    }


def make_group(index: int, rng: random.Random) -> list[dict]:
    """Create a five-case contrast set: 2 safe, 1 uncertain, and 2 XSS."""
    group_id = f"contrast-{index:05d}"
    source = rng.choice(SOURCES)
    target = rng.choice(TARGETS)
    sanitizer = rng.choice(SANITIZERS)
    var = f"value{index}"
    prefix = f"const {var} = {source};\n"
    family = index % 8
    templates = (
        (
            (prefix + f"{target}.innerHTML = {var};", "innerHTML"),
            (prefix + f"{target}.insertAdjacentHTML('beforeend', {var});", "insertAdjacentHTML"),
            (prefix + f"{target}.textContent = {var};", "textContent"),
            (prefix + f"{target}.innerHTML = {sanitizer}({var});", "innerHTML"),
            (prefix + f"{target}.innerHTML = projectSanitizer({var});", "innerHTML"),
        ),
        (
            (prefix + f"$('#{target}').html({var});", "jquery.html"),
            (prefix + f"$('#{target}').append({var});", "jquery.append"),
            (prefix + f"$('#{target}').text({var});", "jquery.text"),
            (prefix + f"$('#{target}').html({sanitizer}({var}));", "jquery.html"),
            (prefix + f"$('#{target}').html(cleanMarkup({var}));", "jquery.html"),
        ),
        (
            (prefix + f"return <section dangerouslySetInnerHTML={{{{__html: {var}}}}} />;", "dangerouslySetInnerHTML"),
            (prefix + f"return React.createElement('div', {{dangerouslySetInnerHTML: {{__html: {var}}}}});", "dangerouslySetInnerHTML"),
            (prefix + f"return <section>{{{var}}}</section>;", "jsx.text"),
            (prefix + "return <section dangerouslySetInnerHTML={{__html: " + sanitizer + f"({var})}}}} />;", "dangerouslySetInnerHTML"),
            (prefix + "return <section dangerouslySetInnerHTML={{__html: cleanRichText(" + var + ")}} />;", "dangerouslySetInnerHTML"),
        ),
        (
            (prefix + f"const tpl = `<article v-html=\"{var}\"></article>`;", "v-html"),
            (prefix + f"app.config.globalProperties.$html = {var}; // consumed by v-html", "v-html"),
            (prefix + f"const tpl = `<article>{{{{ {var} }}}}</article>`;", "vue.interpolation"),
            (prefix + f"const clean = {sanitizer}({var}); const tpl = `<article v-html=\"clean\"></article>`;", "v-html"),
            (prefix + f"const clean = filterMarkup({var}); const tpl = `<article v-html=\"clean\"></article>`;", "v-html"),
        ),
        (
            (prefix + f"host.setAttribute('onclick', {var});", "onclick"),
            (prefix + f"frame.setAttribute('srcdoc', {var});", "srcdoc"),
            (prefix + f"host.setAttribute('title', {var});", "title"),
            (prefix + f"frame.setAttribute('srcdoc', {sanitizer}({var}));", "srcdoc"),
            (prefix + f"frame.setAttribute('srcdoc', scrubDocument({var}));", "srcdoc"),
        ),
        (
            (prefix + f"eval({var});", "eval"),
            (prefix + f"setTimeout({var}, 0);", "setTimeout"),
            (prefix + f"const parsed = JSON.parse({var}); {target}.textContent = parsed.title;", "textContent"),
            (prefix + f"{target}.innerHTML = {sanitizer}({var});", "innerHTML"),
            (prefix + f"new Function(compileUserCode({var}))();", "Function"),
        ),
        (
            (prefix + f"const trusted = sanitizer.bypassSecurityTrustHtml(decodeURIComponent({var})); template = '<div [innerHTML]=\"trusted\"></div>';", "[innerHTML]"),
            (prefix + f"renderer.setProperty({target}, 'innerHTML', atob({var}));", "innerHTML"),
            (prefix + f"template = '<div [innerHTML]=\"{var}\"></div>'; // Angular sanitizes ordinary HTML bindings", "angular.innerHTML"),
            (prefix + f"renderer.setProperty({target}, 'innerHTML', {sanitizer}(decodeURIComponent({var})));", "innerHTML"),
            (prefix + f"template = '<div [innerHTML]=\"{var} | companySafeHtml\"></div>';", "[innerHTML]"),
        ),
        (
            (prefix + f"const view = `<img src=x onerror=\"${{{var}}}\">`; {target}.innerHTML = view;", "innerHTML"),
            (prefix + f"const view = `<a href=\"javascript:${{{var}}}\">open</a>`; {target}.innerHTML = view;", "innerHTML"),
            (f"const html{index} = '<strong>Welcome</strong>'; {target}.innerHTML = html{index};", "innerHTML"),
            (prefix + f"{target}.innerHTML = {sanitizer}(`<b>${{{var}}}</b>`);", "innerHTML"),
            (prefix + f"{target}.innerHTML = renderTrustedTemplate({var});", "innerHTML"),
        ),
    )
    selected = templates[family]
    labels = ("XSS", "XSS", "SAFE", "SAFE", "POSSIBLE_XSS")
    return [_record(group_id, code, label, sink, source if index_tuple != 2 or family != 7 else "")
            for index_tuple, ((code, sink), label) in enumerate(zip(selected, labels))]


def validate_sample(sample: dict) -> list[str]:
    errors: list[str] = []
    required = {"id", "group_id", "code", "label", "sink", "language", "provenance"}
    missing = required - sample.keys()
    if missing:
        errors.append(f"missing fields: {sorted(missing)}")
        return errors
    if sample["label"] not in LABELS:
        errors.append("invalid label")
    if sample["language"] not in {"javascript", "html"}:
        errors.append("invalid language")
    code = sample["code"]
    has_dangerous = any(token in code for token in DANGEROUS)
    has_known_sanitizer = any(token in code for token in SANITIZERS)
    has_safe_sink = bool(re.search(r"\.(textContent|innerText)\s*=", code))
    if sample["label"] == "XSS" and (not has_dangerous or has_known_sanitizer or has_safe_sink):
        errors.append("XSS conflicts with sink/sanitizer rules")
    trusted_constant = not sample.get("source") and bool(re.search(r"const\s+html\w*\s*=", code))
    explicit_safe_api = "createTextNode" in code or ".text(" in code or "textContent" in code or "innerText" in code
    framework_default_safe = "Angular sanitizes ordinary HTML bindings" in code
    if sample["label"] == "SAFE" and has_dangerous and not (
        has_known_sanitizer or trusted_constant or explicit_safe_api or framework_default_safe
    ):
        errors.append("SAFE dangerous sink has no known sanitizer")
    if sample["label"] == "POSSIBLE_XSS" and not has_dangerous:
        errors.append("POSSIBLE_XSS has no dangerous sink")
    return errors


def validate_dataset(splits: dict[str, list[dict]]) -> dict:
    seen_ids: set[str] = set()
    seen_code: set[str] = set()
    split_groups: dict[str, set[str]] = {}
    errors: list[str] = []
    for split, rows in splits.items():
        split_groups[split] = {row["group_id"] for row in rows}
        for row in rows:
            errors.extend(f"{split}/{row.get('id', '?')}: {msg}" for msg in validate_sample(row))
            if row["id"] in seen_ids:
                errors.append(f"duplicate id: {row['id']}")
            if row["code"] in seen_code:
                errors.append(f"duplicate code: {row['id']}")
            seen_ids.add(row["id"])
            seen_code.add(row["code"])
    names = list(split_groups)
    for i, left in enumerate(names):
        for right in names[i + 1 :]:
            overlap = split_groups[left] & split_groups[right]
            if overlap:
                errors.append(f"group leakage between {left} and {right}: {len(overlap)}")
    if errors:
        raise ValueError("dataset validation failed:\n" + "\n".join(errors[:20]))
    return {
        split: {"count": len(rows), "labels": dict(sorted(Counter(r["label"] for r in rows).items()))}
        for split, rows in splits.items()
    }


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def build_dataset(count: int, seed: int) -> dict[str, list[dict]]:
    if count < 100 or count % 10:
        raise ValueError("count must be at least 100 and divisible by 10")
    if count % 5:
        raise ValueError("count must be divisible by five")
    rng = random.Random(seed)
    groups = [make_group(i, rng) for i in range(count // 5)]
    rng.shuffle(groups)
    train_end = int(len(groups) * 0.8)
    validation_end = int(len(groups) * 0.9)
    grouped = {
        "train": groups[:train_end],
        "validation": groups[train_end:validation_end],
        "test": groups[validation_end:],
    }
    splits = {name: [row for group in values for row in group] for name, values in grouped.items()}
    for rows in splits.values():
        rng.shuffle(rows)
    return splits


def hard_test_cases(count: int = 1000, seed: int = 2027) -> list[dict]:
    """Generate challenge cases from templates not used by the training generator."""
    if count % 5:
        raise ValueError("hard-test count must be divisible by five")
    rng = random.Random(seed)
    rows: list[dict] = []
    for index in range(count // 5):
        group_id = f"hard-{index:05d}"
        source = rng.choice(("window.name", "event.data", "params.get('term')", "apiResult.body", "formValue"))
        target = rng.choice(("mount", "article", "dialog", "slot", "viewRoot"))
        var = f"tainted_{index}"
        prefix = f"let {var} = {source};\n"
        family = index % 5
        variants = (
            (
                (prefix + f"Reflect.set({target}, 'innerHTML', {var});", "XSS", "innerHTML"),
                (prefix + f"{target}['outer' + 'HTML'] = {var};", "XSS", "outerHTML"),
                (prefix + f"{target}.replaceChildren(document.createTextNode({var}));", "SAFE", "createTextNode"),
                (prefix + f"{target}.innerHTML = DOMPurify.sanitize({var}, {{USE_PROFILES: {{html: true}}}});", "SAFE", "innerHTML"),
                (prefix + f"{target}.innerHTML = security.clean({var});", "POSSIBLE_XSS", "innerHTML"),
            ),
            (
                (prefix + f"jQuery({target}).html({var});", "XSS", "jquery.html"),
                (prefix + f"jQuery({target}).appendTo({var}); {target}.append({var});", "XSS", "jquery.append"),
                (prefix + f"jQuery({target}).empty().text({var});", "SAFE", "jquery.text"),
                (prefix + f"jQuery({target}).html(DOMPurify.sanitize({var}));", "SAFE", "jquery.html"),
                (prefix + f"jQuery({target}).html(app.clean({var}));", "POSSIBLE_XSS", "jquery.html"),
            ),
            (
                (prefix + f"const props = {{dangerouslySetInnerHTML: {{__html: {var}}}}}; return <div {{...props}} />;", "XSS", "dangerouslySetInnerHTML"),
                (prefix + f"return <iframe srcDoc={{{var}}} />;", "XSS", "srcdoc"),
                (prefix + f"return React.createElement('pre', null, {var});", "SAFE", "react.text"),
                (prefix + "return <div dangerouslySetInnerHTML={{__html: sanitizeHtml(" + var + ")}} />;", "SAFE", "dangerouslySetInnerHTML"),
                (prefix + "return <div dangerouslySetInnerHTML={{__html: props.cleaner(" + var + ")}} />;", "POSSIBLE_XSS", "dangerouslySetInnerHTML"),
            ),
            (
                (prefix + f"renderer.setProperty({target}, 'innerHTML', {var});", "XSS", "[innerHTML]"),
                (prefix + f"{target}.setAttribute('onfocus', {var}); {target}.focus();", "XSS", "onclick"),
                (prefix + f"renderer.setProperty({target}, 'textContent', {var});", "SAFE", "textContent"),
                (prefix + f"renderer.setProperty({target}, 'innerHTML', sanitizeHtml({var}));", "SAFE", "innerHTML"),
                (prefix + f"renderer.setProperty({target}, 'innerHTML', trustService.scrub({var}));", "POSSIBLE_XSS", "innerHTML"),
            ),
            (
                (prefix + f"window['ev' + 'al']({var});", "XSS", "eval"),
                (prefix + f"const run = new Function('return ' + {var}); run();", "XSS", "Function"),
                (prefix + f"const decoded = JSON.parse({var}); {target}.append(document.createTextNode(decoded.name));", "SAFE", "createTextNode"),
                (prefix + f"{target}.innerHTML = escapeHtml({var});", "SAFE", "innerHTML"),
                (prefix + f"{target}.innerHTML = decodeThenFilter({var});", "POSSIBLE_XSS", "innerHTML"),
            ),
        )[family]
        rows.extend(_record(group_id, code, label, sink, source) for code, label, sink in variants)
    rng.shuffle(rows)
    return rows


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=root / "data")
    parser.add_argument("--count", type=int, default=10_000)
    parser.add_argument("--seed", type=int, default=1337)
    args = parser.parse_args()

    splits = build_dataset(args.count, args.seed)
    summary = validate_dataset(splits)
    for name, rows in splits.items():
        write_jsonl(args.output_dir / f"{name}.jsonl", rows)
    hard_rows = hard_test_cases()
    for row in hard_rows:
        errors = validate_sample(row)
        if errors:
            raise ValueError(f"invalid hard case {row['id']}: {errors}")
    write_jsonl(args.output_dir / "hard_test.jsonl", hard_rows)
    manifest = {"seed": args.seed, "total": args.count, "splits": summary, "hard_test": len(hard_rows)}
    (args.output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
