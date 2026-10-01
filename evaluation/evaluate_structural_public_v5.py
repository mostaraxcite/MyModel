"""Broader public-repository development gate for the XSS structural hybrid.

Pinned upstream repositories provide the reviewed field expressions. This is a
development benchmark, not a locked promotion set, and it never confirms XSS.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from sklearn.metrics import accuracy_score, f1_score

from xss_specialist.dual_branch import LABEL_SPACES
from xss_specialist.field_advisor import StructuralFieldAdvisor


def line_with(text: str, *parts: str) -> str:
    for raw in text.splitlines():
        line = raw.strip()
        if line and all(part in line for part in parts):
            return line
    raise ValueError(f"missing line containing {parts!r}")


def script_with(html: str, *parts: str) -> str:
    blocks = re.findall(r"<script(?:\s[^>]*)?>(.*?)</script>", html, re.I | re.S)
    for block in blocks:
        if all(part in block for part in parts):
            return block
    raise ValueError(f"missing script block containing {parts!r}")


def add(out, case_id, expected, source_expression, sink_expression, defense_expression, relation):
    out.append({
        "id": case_id,
        "expected": expected,
        "fields": {
            "source_expression": source_expression,
            "sink_expression": sink_expression,
            "defense_expression": defense_expression,
            "relation": relation,
        },
    })


def build_cases(*, firing: Path, dompurify: Path, nodegoat: Path, express: Path, jquery: Path, vue: Path, angular: Path):
    out=[]

    # Google Firing Range: browser sources crossed with HTML/JS sinks.
    source_specs=[
        ("document/referrer.tmpl", "document.referrer"),
        ("localStorage/property.tmpl", "localStorage.badValue"),
        ("sessionStorage/property.tmpl", "sessionStorage.badValue"),
        ("window/name.tmpl", "window.name"),
    ]
    sink_specs=[
        ("innerHtml.tmpl", "DANGEROUS_HTML", "div.innerHTML", ("div.innerHTML","payload")),
        ("documentWrite.tmpl", "DANGEROUS_HTML", "document.write", ("document.write","payload")),
        ("eval.tmpl", "DANGEROUS_JS", "eval", ("eval(","payload")),
    ]
    for source_rel, source_expr in source_specs:
        source_text=(firing/"src/tests/dom/data/sources"/source_rel).read_text(errors="replace")
        source_line=line_with(source_text,"payload","=")
        for sink_rel,sink_label,sink_name,needles in sink_specs:
            sink_text=(firing/"src/tests/dom/data/sinks"/sink_rel).read_text(errors="replace")
            sink_line=line_with(sink_text,*needles)
            add(
                out,
                f"firing:{source_rel}:{sink_rel}",
                {"source":"BROWSER","sink":sink_label,"defense":"NONE","flow":"CONNECTED"},
                source_expr,
                sink_line,
                "[NO_DEFENSE]",
                {"source_expression":"payload","sink_expression":sink_name,"flow_excerpt":sink_line},
            )

    # DOMPurify official demos: sanitizer is a real defense; opaque call return => UNKNOWN flow.
    for rel in ("demos/basic-demo.html","demos/hooks-demo.html","demos/config-demo.html","demos/hooks-target-blank-demo.html"):
        html=(dompurify/rel).read_text(errors="replace")
        block=script_with(html,"DOMPurify.sanitize","innerHTML")
        sanitize=line_with(block,"DOMPurify.sanitize")
        sink=line_with(block,"innerHTML")
        add(
            out,
            f"dompurify:{rel}",
            {"source":"OTHER","sink":"DANGEROUS_HTML","defense":"SANITIZATION","flow":"UNKNOWN"},
            "dirty",
            sink,
            sanitize,
            {"source_expression":"dirty","sink_expression":"clean","flow_excerpt":sanitize},
        )

    # OWASP NodeGoat: server input to eval and URL redirect.
    contrib=(nodegoat/"app/routes/contributions.js").read_text(errors="replace")
    eval_line=line_with(contrib,"eval(req.body.preTax)")
    add(
        out,
        "nodegoat:server-eval",
        {"source":"SERVER","sink":"DANGEROUS_JS","defense":"NONE","flow":"CONNECTED"},
        "req.body.preTax",
        eval_line,
        "[NO_DEFENSE]",
        {"source_expression":"req.body.preTax","sink_expression":"eval","flow_excerpt":eval_line},
    )

    routes=(nodegoat/"app/routes/index.js").read_text(errors="replace")
    redirect=line_with(routes,"res.redirect(req.query.url)")
    add(
        out,
        "nodegoat:server-redirect",
        {"source":"SERVER","sink":"DANGEROUS_URL","defense":"NONE","flow":"CONNECTED"},
        "req.query.url",
        redirect,
        "[NO_DEFENSE]",
        {"source_expression":"req.query.url","sink_expression":"res.redirect","flow_excerpt":redirect},
    )

    # Express: raw response sink, contextual encoding, and static-source control.
    vhost=(express/"examples/vhost/index.js").read_text(errors="replace")
    raw_send=line_with(vhost,"res.send('requested '","req.params.sub")
    add(
        out,
        "express:raw-server-send",
        {"source":"SERVER","sink":"DANGEROUS_HTML","defense":"NONE","flow":"CONNECTED"},
        "req.params.sub",
        raw_send,
        "[NO_DEFENSE]",
        {"source_expression":"req.params.sub","sink_expression":"res.send","flow_excerpt":raw_send},
    )

    route_map=(express/"examples/route-map/index.js").read_text(errors="replace")
    encoded_send=line_with(route_map,"res.send('user '","escapeHtml(req.params.uid)")
    add(
        out,
        "express:encoded-server-send",
        {"source":"SERVER","sink":"DANGEROUS_HTML","defense":"CONTEXTUAL_ENCODING","flow":"CONNECTED"},
        "req.params.uid",
        encoded_send,
        "escapeHtml(req.params.uid)",
        {"source_expression":"req.params.uid","sink_expression":"res.send","flow_excerpt":encoded_send},
    )

    hello=(express/"examples/hello-world/index.js").read_text(errors="replace")
    static_send=line_with(hello,"res.send('Hello World')")
    add(
        out,
        "express:static-send-control",
        {"source":"NONE","sink":"DANGEROUS_HTML","defense":"NONE","flow":"UNKNOWN"},
        "'Hello World'",
        static_send,
        "[NO_DEFENSE]",
        {"source_expression":"requestData","sink_expression":"res.send","flow_excerpt":static_send},
    )

    # jQuery implementation: safe text sink and an actual literal overwrite.
    manipulation=(jquery/"src/manipulation.js").read_text(errors="replace")
    safe_line=line_with(manipulation,"this.textContent = value")
    add(
        out,
        "jquery:text-content-connected",
        {"source":"OTHER","sink":"SAFE_OUTPUT","defense":"SAFE_DOM_API","flow":"CONNECTED"},
        "value",
        safe_line,
        safe_line,
        {"source_expression":"value","sink_expression":"this.textContent","flow_excerpt":safe_line},
    )
    literal_line=line_with(manipulation,'elem.textContent = ""')
    add(
        out,
        "jquery:text-content-disconnected",
        {"source":"OTHER","sink":"SAFE_OUTPUT","defense":"SAFE_DOM_API","flow":"DISCONNECTED"},
        "value",
        literal_line,
        literal_line,
        {"source_expression":"value","sink_expression":"elem.textContent","flow_excerpt":literal_line},
    )

    # Vue compiler tests: framework source, raw v-html, and escaped v-text.
    vue_text=(vue/"packages/compiler-ssr/__tests__/ssrElement.spec.ts").read_text(errors="replace")
    add(
        out,
        "vue:v-html",
        {"source":"FRAMEWORK","sink":"DANGEROUS_HTML","defense":"NONE","flow":"UNKNOWN"},
        "_ctx.foo",
        '<div v-html="foo"/>',
        "[NO_DEFENSE]",
        {"source_expression":"_ctx.foo","sink_expression":"v-html","flow_excerpt":line_with(vue_text,'<div v-html="foo"/>')},
    )
    add(
        out,
        "vue:v-text",
        {"source":"FRAMEWORK","sink":"SAFE_OUTPUT","defense":"FRAMEWORK_ESCAPING","flow":"UNKNOWN"},
        "_ctx.foo",
        '<div v-text="foo"/>',
        'v-text="foo"',
        {"source_expression":"_ctx.foo","sink_expression":"v-text","flow_excerpt":line_with(vue_text,'<div v-text="foo"/>')},
    )

    # Angular explicitly documents/uses bypassSecurityTrustHtml: it is not a sanitizer.
    angular_text=(angular/"adev/src/app/features/home/components/code-block/code-block.ts").read_text(errors="replace")
    bypass=line_with(angular_text,"bypassSecurityTrustHtml(highlightedHtml)")
    add(
        out,
        "angular:security-bypass-open-set",
        {"source":"OTHER","sink":"NONE","defense":"OTHER","flow":"CONNECTED"},
        "highlightedHtml",
        bypass,
        bypass,
        {"source_expression":"highlightedHtml","sink_expression":"bypassSecurityTrustHtml","flow_excerpt":bypass},
    )

    return out


def task_metrics(rows, task):
    labels=LABEL_SPACES[task]
    index={label:i for i,label in enumerate(labels)}
    truth=[index[r["expected"][task]] for r in rows]
    pred=[index[r["predicted"][task]] for r in rows]
    present=sorted(set(truth))
    return {
        "macro_f1_present":float(f1_score(truth,pred,labels=present,average="macro",zero_division=0)),
        "accuracy":float(accuracy_score(truth,pred)),
        "present_labels":[labels[i] for i in present],
    }


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--semantic-dir",type=Path,required=True)
    p.add_argument("--flow-dir",type=Path,required=True)
    p.add_argument("--firing-range-root",type=Path,required=True)
    p.add_argument("--dompurify-root",type=Path,required=True)
    p.add_argument("--nodegoat-root",type=Path,required=True)
    p.add_argument("--express-root",type=Path,required=True)
    p.add_argument("--jquery-root",type=Path,required=True)
    p.add_argument("--vue-root",type=Path,required=True)
    p.add_argument("--angular-root",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()

    advisor=StructuralFieldAdvisor(a.semantic_dir,a.flow_dir)
    source=build_cases(
        firing=a.firing_range_root,
        dompurify=a.dompurify_root,
        nodegoat=a.nodegoat_root,
        express=a.express_root,
        jquery=a.jquery_root,
        vue=a.vue_root,
        angular=a.angular_root,
    )
    if len(source)<24:
        raise SystemExit(f"insufficient public cases: {len(source)}")

    rows=[]
    for case in source:
        f=case["fields"]
        result=advisor.review_fields(
            source_expression=f["source_expression"],
            sink_expression=f["sink_expression"],
            defense_expression=f["defense_expression"],
            relation=f["relation"],
        )
        pred={t:result[t]["label"] for t in ("source","sink","defense","flow")}
        rows.append({
            "id":case["id"],
            "expected":case["expected"],
            "predicted":pred,
            "authority":{t:result[t]["authority"] for t in ("source","sink","defense","flow")},
            "tuple_correct":pred==case["expected"],
        })

    metrics={t:task_metrics(rows,t) for t in ("source","sink","defense","flow")}
    coverage={t:set(metrics[t]["present_labels"]) for t in metrics}
    required={
        "source":{"NONE","BROWSER","SERVER","FRAMEWORK","OTHER"},
        "sink":{"DANGEROUS_HTML","DANGEROUS_JS","DANGEROUS_URL","SAFE_OUTPUT","OTHER"},
        "defense":{"NONE","SANITIZATION","CONTEXTUAL_ENCODING","FRAMEWORK_ESCAPING","SAFE_DOM_API","OTHER"},
        "flow":{"CONNECTED","DISCONNECTED","UNKNOWN"},
    }
    coverage_ok=all(required[t].issubset(coverage[t]) for t in required)
    tuple_accuracy=sum(r["tuple_correct"] for r in rows)/len(rows)

    passed=bool(
        coverage_ok
        and metrics["source"]["macro_f1_present"]>=.90
        and metrics["sink"]["macro_f1_present"]>=.90
        and metrics["defense"]["macro_f1_present"]>=.90
        and metrics["flow"]["macro_f1_present"]>=.90
        and tuple_accuracy>=.85
    )

    report={
        "schema":"xss-structural-public-v5",
        "case_count":len(rows),
        "repositories":[
            "google/firing-range","cure53/DOMPurify","OWASP/NodeGoat",
            "expressjs/express","jquery/jquery","vuejs/core","angular/angular",
        ],
        "metrics":metrics,
        "required_class_coverage":{k:sorted(v) for k,v in required.items()},
        "coverage_ok":coverage_ok,
        "tuple_accuracy":tuple_accuracy,
        "research_gate_passed":passed,
        "locked_hard_or_external_used":False,
        "promotion_allowed":False,
        "final_judge":False,
        "cases":rows,
    }
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2))
    if not passed:
        raise SystemExit("public structural v5 development gate failed")


if __name__=="__main__":
    main()
