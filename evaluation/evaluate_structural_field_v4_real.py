"""Independent real-upstream gate for field-level semantic + canonical flow advisor."""
from __future__ import annotations
import argparse, json, re
from pathlib import Path
from sklearn.metrics import accuracy_score, f1_score
from xss_specialist.field_advisor import StructuralFieldAdvisor
from xss_specialist.dual_branch import LABEL_SPACES

FIRING = [
    ("src/tests/dom/data/sources/document/referrer.tmpl","document.referrer"),
    ("src/tests/dom/data/sources/localStorage/property.tmpl","localStorage.badValue"),
    ("src/tests/dom/data/sources/sessionStorage/property.tmpl","sessionStorage['badValue']"),
    ("src/tests/dom/data/sources/window/name.tmpl","window.name"),
]
SINKS=[
    ("src/tests/dom/data/sinks/innerHtml.tmpl","DANGEROUS_HTML","div.innerHTML = payload;","div.innerHTML"),
    ("src/tests/dom/data/sinks/documentWrite.tmpl","DANGEROUS_HTML","document.write(payload);","document.write"),
    ("src/tests/dom/data/sinks/eval.tmpl","DANGEROUS_JS","eval(payload);","eval"),
]
DOMPURIFY=[
    "demos/basic-demo.html","demos/hooks-demo.html","demos/config-demo.html",
    "demos/hooks-target-blank-demo.html","demos/hooks-sanitize-css-demo.html",
]

def find_line(text,*parts):
    for raw in text.splitlines():
        line=raw.strip()
        if line and all(p in line for p in parts):
            return line
    raise ValueError(f"line not found: {parts}")

def script_blocks(html):
    return re.findall(r"<script(?:\s[^>]*)?>(.*?)</script>",html,re.I|re.S)

def cases(firing:Path,dom:Path):
    out=[]
    for source_path,source_expr in FIRING:
        source=(firing/source_path).read_text(errors="replace")
        payload_line=find_line(source,"payload","=")
        for sink_path,sink_label,sink_stmt,sink_expr in SINKS:
            sink=(firing/sink_path).read_text(errors="replace")
            real_sink=find_line(sink,*([sink_expr,"payload"] if sink_expr!="eval" else ["eval(","payload"]))
            out.append({
                "id":f"firing:{Path(source_path).stem}:{Path(sink_path).stem}",
                "expected":{"source":"BROWSER","sink":sink_label,"defense":"NONE","flow":"CONNECTED"},
                "fields":{
                    "source_expression":source_expr,
                    "sink_expression":real_sink,
                    "defense_expression":"[NO_DEFENSE]",
                    "relation":{
                        "source_expression":"payload",
                        "sink_expression":sink_expr,
                        "flow_excerpt":real_sink,
                    },
                },
            })
    for rel in DOMPURIFY:
        html=(dom/rel).read_text(errors="replace")
        blocks=[b for b in script_blocks(html) if "DOMPurify.sanitize" in b and "innerHTML" in b]
        if not blocks: continue
        block=max(blocks,key=len)
        sanitize=find_line(block,"DOMPurify.sanitize")
        sink=find_line(block,"innerHTML")
        dirty="dirty"
        out.append({
            "id":f"dompurify:{Path(rel).name}",
            "expected":{"source":"NONE","sink":"DANGEROUS_HTML","defense":"SANITIZATION","flow":"UNKNOWN"},
            "fields":{
                "source_expression":"'static fixture input'",
                "sink_expression":sink,
                "defense_expression":sanitize,
                "relation":{
                    "source_expression":dirty,
                    "sink_expression":"clean",
                    "flow_excerpt":sanitize,
                },
            },
        })
    return out

def metrics(rows,task):
    labels=LABEL_SPACES[task]; idx={x:i for i,x in enumerate(labels)}
    y=[idx[r["expected"][task]] for r in rows]; p=[idx[r["predicted"][task]] for r in rows]
    present=sorted(set(y))
    return {
        "macro_f1_present":float(f1_score(y,p,labels=present,average="macro",zero_division=0)),
        "accuracy":float(accuracy_score(y,p)),
        "present_labels":[labels[i] for i in present],
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--semantic-dir",type=Path,required=True)
    p.add_argument("--flow-dir",type=Path,required=True)
    p.add_argument("--firing-range-root",type=Path,required=True)
    p.add_argument("--dompurify-root",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    advisor=StructuralFieldAdvisor(a.semantic_dir,a.flow_dir)
    source=cases(a.firing_range_root,a.dompurify_root)
    if len(source)<16: raise SystemExit(f"insufficient real cases: {len(source)}")
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
            "id":case["id"],"expected":case["expected"],"predicted":pred,
            "confidence":{t:result[t]["confidence"] for t in ("source","sink","defense","flow")},
            "tuple_correct":pred==case["expected"],
        })
    m={t:metrics(rows,t) for t in ("source","sink","defense","flow")}
    tuple_acc=sum(r["tuple_correct"] for r in rows)/len(rows)
    passed=bool(
        m["source"]["macro_f1_present"]>=.85 and
        m["sink"]["macro_f1_present"]>=.85 and
        m["defense"]["macro_f1_present"]>=.80 and
        m["flow"]["macro_f1_present"]>=.85 and
        tuple_acc>=.75
    )
    report={
        "schema":"xss-structural-field-v4-real",
        "case_count":len(rows),"metrics":m,"tuple_accuracy":tuple_acc,
        "research_gate_passed":passed,"promotion_allowed":False,
        "locked_hard_or_external_used":False,"final_judge":False,"cases":rows,
    }
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2))
if __name__=="__main__": main()
