"""Build class-complete semantic supervision for XSS structural heads.

This corpus trains only Source/Sink/Defense structure. It never emits a vulnerability
verdict and never reads Hard/External benchmarks. Train/dev templates and identifier
banks are disjoint; the independent real upstream integration gate remains separate.
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

TRAIN_VARS = ["inputValue","queryData","rawText","userArg","requestValue","candidate","incoming","fieldValue"]
DEV_VARS = ["payloadText","externalValue","messageData","routeValue","unsafeValue","provided","entry","fragmentValue"]
TRAIN_ELEMS = ["box","panel","target","output","slot","container"]
DEV_ELEMS = ["view","region","mount","surface","holder","node"]


def idx(space, label):
    return space.index(label)


def specs(group: str):
    if group == "train":
        return [
            ("browser_html_none", "BROWSER","DANGEROUS_HTML","NONE",
             lambda v,e: f"const {v} = location.hash.slice(1);\n{e}.innerHTML = {v};"),
            ("server_js_none", "SERVER","DANGEROUS_JS","NONE",
             lambda v,e: f"const {v} = req.query.code;\neval({v});"),
            ("framework_url_none", "FRAMEWORK","DANGEROUS_URL","NONE",
             lambda v,e: f"const {v} = props.nextUrl;\n{e}.href = {v};"),
            ("none_safe_api", "NONE","SAFE_OUTPUT","SAFE_DOM_API",
             lambda v,e: f"const {v} = 'hello';\n{e}.textContent = {v};"),
            ("browser_html_sanitize", "BROWSER","DANGEROUS_HTML","SANITIZATION",
             lambda v,e: f"const {v} = window.name;\nconst clean = DOMPurify.sanitize({v});\n{e}.innerHTML = clean;"),
            ("server_html_encode", "SERVER","DANGEROUS_HTML","CONTEXTUAL_ENCODING",
             lambda v,e: f"const {v} = req.body.name;\nconst encoded = escapeHtml({v});\nres.send('<p>' + encoded + '</p>');"),
            ("framework_escape", "FRAMEWORK","SAFE_OUTPUT","FRAMEWORK_ESCAPING",
             lambda v,e: f"function {e}({{ {v} }}) {{ return <div>{{{v}}}</div>; }}"),
            ("browser_url_constraint", "BROWSER","DANGEROUS_URL","INPUT_CONSTRAINT",
             lambda v,e: f"const {v} = new URLSearchParams(location.search).get('next');\nif (/^https?:\\/\\//.test({v})) {e}.href = {v};"),
            ("other_other_none", "OTHER","OTHER","NONE",
             lambda v,e: f"const {v} = externalQueue.read();\nauditLog.write({v});"),
            ("browser_no_sink", "BROWSER","NONE","NONE",
             lambda v,e: f"const {v} = document.referrer;\nconst size = {v}.length;"),
            ("other_safe_api", "OTHER","SAFE_OUTPUT","SAFE_DOM_API",
             lambda v,e: f"const {v} = process.env.MESSAGE;\n{e}.innerText = {v};"),
            ("other_html_custom", "OTHER","DANGEROUS_HTML","OTHER",
             lambda v,e: f"const {v} = externalValue;\nconst transformed = securityTransform({v});\n{e}.innerHTML = transformed;"),
        ]
    return [
        ("browser_html_hold", "BROWSER","DANGEROUS_HTML","NONE",
         lambda v,e: f"let {v} = document.referrer;\n{e}.insertAdjacentHTML('beforeend', {v});"),
        ("server_js_hold", "SERVER","DANGEROUS_JS","NONE",
         lambda v,e: f"const {v} = request.body.script;\nFunction({v})();"),
        ("framework_url_hold", "FRAMEWORK","DANGEROUS_URL","NONE",
         lambda v,e: f"const {v} = route.params.image;\n{e}.src = {v};"),
        ("none_safe_hold", "NONE","SAFE_OUTPUT","SAFE_DOM_API",
         lambda v,e: f"let {v} = 'static';\n{e}.insertAdjacentText('beforeend', {v});"),
        ("browser_sanitize_hold", "BROWSER","DANGEROUS_HTML","SANITIZATION",
         lambda v,e: f"const {v} = document.URL;\nconst cleaned = purifier.sanitize({v});\n{e}.outerHTML = cleaned;"),
        ("server_encode_hold", "SERVER","DANGEROUS_HTML","CONTEXTUAL_ENCODING",
         lambda v,e: f"const {v} = request.query.title;\nconst safeText = encodeHtml({v});\nresponse.write(safeText);"),
        ("framework_escape_hold", "FRAMEWORK","SAFE_OUTPUT","FRAMEWORK_ESCAPING",
         lambda v,e: f"const {e} = (props) => <span>{{props.{v}}}</span>;"),
        ("browser_constraint_hold", "BROWSER","DANGEROUS_URL","INPUT_CONSTRAINT",
         lambda v,e: f"const {v} = window.name;\nif (allowedProtocols.has(new URL({v}).protocol)) {e}.href = {v};"),
        ("other_other_hold", "OTHER","OTHER","OTHER",
         lambda v,e: f"const {v} = messageBus.next();\nconst checked = customGuard({v});\ntelemetry.emit(checked);"),
        ("browser_no_sink_hold", "BROWSER","NONE","NONE",
         lambda v,e: f"const {v} = location.search;\nconst count = {v}.split('&').length;"),
    ]


def build(group: str, per_template: int, seed: int):
    rng = random.Random(seed)
    vars_ = TRAIN_VARS if group == "train" else DEV_VARS
    elems = TRAIN_ELEMS if group == "train" else DEV_ELEMS
    rows = []
    for template, source, sink, defense, render in specs(group):
        for i in range(per_template):
            v = vars_[(i + rng.randrange(len(vars_))) % len(vars_)]
            e = elems[(i * 3 + rng.randrange(len(elems))) % len(elems)]
            text = render(v, e)
            rows.append({
                "id": f"semantic-v3:{group}:{template}:{i:04d}",
                "text": text,
                "source_label": idx(SOURCE_LABELS, source),
                "sink_label": idx(SINK_LABELS, sink),
                "defense_label": idx(DEFENSE_LABELS, defense),
                "flow_label": IGNORE_INDEX,
                "metadata": {
                    "origin": "semantic-v3-structural",
                    "group": group,
                    "template": template,
                    "source": source,
                    "sink": sink,
                    "defense": defense,
                },
            })
    return rows


def digest(row):
    return hashlib.sha256(row["text"].encode()).hexdigest()


def counts(rows, key, labels):
    out = {name: 0 for name in labels}
    for row in rows:
        out[labels[row[key]]] += 1
    return out


def write(path, rows):
    path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output-dir",type=Path,default=ROOT/"data"/"semantic-v3")
    p.add_argument("--train-per-template",type=int,default=80)
    p.add_argument("--dev-per-template",type=int,default=50)
    p.add_argument("--seed",type=int,default=7071)
    a=p.parse_args()

    train=build("train",a.train_per_template,a.seed)
    dev=build("dev",a.dev_per_template,a.seed+1)
    overlap={digest(r) for r in train}&{digest(r) for r in dev}
    if overlap:
        raise SystemExit(f"semantic-v3 train/dev text overlap: {len(overlap)}")

    manifest={
        "schema":"xss-semantic-v3-data",
        "train_rows":len(train),
        "dev_rows":len(dev),
        "exact_text_overlap":0,
        "template_overlap": sorted(
            {r["metadata"]["template"] for r in train}
            & {r["metadata"]["template"] for r in dev}
        ),
        "train":{
            "source":counts(train,"source_label",SOURCE_LABELS),
            "sink":counts(train,"sink_label",SINK_LABELS),
            "defense":counts(train,"defense_label",DEFENSE_LABELS),
        },
        "dev":{
            "source":counts(dev,"source_label",SOURCE_LABELS),
            "sink":counts(dev,"sink_label",SINK_LABELS),
            "defense":counts(dev,"defense_label",DEFENSE_LABELS),
        },
        "whole_snippet_xss_target":False,
        "locked_hard_or_external_used":False,
    }
    if manifest["template_overlap"]:
        raise SystemExit("semantic-v3 template overlap")
    for split in ("train","dev"):
        for task in ("source","sink","defense"):
            missing=[k for k,v in manifest[split][task].items() if v==0]
            if missing:
                raise SystemExit(f"missing {split} {task} classes: {missing}")

    a.output_dir.mkdir(parents=True,exist_ok=True)
    write(a.output_dir/"train.jsonl",train)
    write(a.output_dir/"dev.jsonl",dev)
    (a.output_dir/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
    print(json.dumps(manifest,indent=2))


if __name__=="__main__":
    main()
