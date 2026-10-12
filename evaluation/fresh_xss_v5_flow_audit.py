"""Frozen, second-wave synthetic XSS static coverage audit.

Audits local AST candidate/abstention behavior, NEVER browser execution or
real website exploitability. Created after V5 code was merged; it is NOT used
for training or code tuning. Never reuse its results as untouched evaluation.
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path

from xss_specialist.grounded_advisor import grounded_review


@dataclass(frozen=True)
class Case:
    id: str
    label: str
    family: str
    code: str
    reviewer_note: str


# Cases and labels are fixed BEFORE the first evaluation. Potentially unsafe
# indicates source-to-execution potential, not confirmed XSS in a real browser.
CASES: tuple[Case, ...] = (
    Case("VU01","unsafe","message-html",
         "window.addEventListener('message', (event) => { const markup=event.data; box.outerHTML=markup; });",
         "Attacker-origin messages could reach an HTML parser."),
    Case("VU02","unsafe","anchor-link",
         "const anchor=document.createElement('a');let destination=req.query.returnTo;anchor.setAttribute('href',destination);",
         "Unrestricted URL schemes are potentially script-capable."),
    Case("VU03","unsafe","external-script",
         "const external=window.name;const element=document.querySelector('script');element.src=external;",
         "A trusted-script element loads an untrusted URL."),
    Case("VU04","unsafe","for-source",
         "let markup=location.hash;for(let j=0;j<3;j++){markup+='.';}result.innerHTML=markup;",
         "A small bounded loop preserves untrusted markup."),
    Case("VU05","unsafe","location-navigation",
         "const nextPage=document.referrer;window.location.href=nextPage;",
         "Untrusted navigation URL can include a script URL scheme."),
    Case("VU06","unsafe","message-alias",
         "window.addEventListener('message', evt => {const html=String(evt.data); target.insertAdjacentHTML('beforebegin',html);});",
         "Cross-window data passes through an ordinary string conversion."),
    Case("VU07","unsafe","window-timer",
         "const expression=window.location.search;window.setTimeout(expression,45);",
         "String timer can interpret attacker-controlled script."),
    Case("VU08","unsafe","promise-handler",
         "Promise.resolve(location.search).then(output => { pane.innerHTML=output; });",
         "An asynchronous Promise handler carries untrusted content to HTML."),

    Case("VS01","safe","message-text",
         "addEventListener('message', evt => { feedback.textContent=evt.data; });",
         "DOM text property does not parse HTML."),
    Case("VS02","safe","encoded-relative-link",
         "const link=document.createElement('a');link.href='/settings?ref='+encodeURIComponent(document.referrer);",
         "Root-relative path plus an encoded value cannot create script URL scheme."),
    Case("VS03","safe","for-constant",
         "let summary=location.hash;for(let j=0;j<2;j++){summary='verified';}pane.outerHTML=summary;",
         "Tainted value overwritten by constants in a guaranteed iteration."),
    Case("VS04","safe","local-script-constant",
         "const s=document.createElement('script');s.src='/assets/widget.js';",
         "Fixed literal script URL is not attacker-supplied."),
    Case("VS05","safe","console-only",
         "const term=req.query.q;console.warn(term);panel.innerHTML='<span>done</span>';",
         "Logging does not connect untrusted data to the static HTML sink."),
    Case("VS06","safe","inert-data-attr",
         "let text=window.name;badge.setAttribute('data-note',text);",
         "data-* attribute is inert for local script execution."),
    Case("VS07","safe","typed-text-node",
         "const value=document.URL;const text=document.createTextNode(value);box.replaceChildren(text);",
         "A Text node supplied to replaceChildren is inert."),
    Case("VS08","safe","scoped-url-builder",
         "const value=document.URL;const u=new URL('/docs?ref='+encodeURIComponent(value),location.origin);anchor.href=u.href;",
         "Explicit root-relative URL with same-origin base cannot create javascript scheme."),

    Case("VQ01","needs_review","unknown-mutation",
         "const script=document.createElement('script');changeElement(script);script.src=location.search;",
         "An unknown call may change element alias/type."),
    Case("VQ02","needs_review","unbounded-loop",
         "let value=location.hash;for(let j=0;j<count;j++){value='constant';}node.innerHTML=value;",
         "Iteration count and whether assignment occurs are unknown."),
    Case("VQ03","needs_review","dynamic-event",
         "window.addEventListener(eventType, e => {stage.outerHTML=e.data;});",
         "Unknown event kind and callback provenance."),
    Case("VQ04","needs_review","dynamic-element",
         "const element=document.querySelector(tagFromConfig);element.src=window.name;",
         "An unknown element may or may not be an executable script."),
    Case("VQ05","needs_review","external-library",
         "const html=untrustedPlugin.getTemplate();stage.innerHTML=html;",
         "Plugin data provenance and semantics are not established."),
    Case("VQ06","needs_review","branch-type-mutation",
         "let script=document.createElement('script');if(config){script=proxy;}script.src=location.hash;",
         "Branch may replace script element with unknown object."),
    Case("VQ07","needs_review","unknown-url-rewrite",
         "const dest=routeFixup(location.search);document.createElement('a').href=dest;",
         "Unknown rewrite could allow or reject unsafe schemes."),
    Case("VQ08","needs_review","dynamic-constructor",
         "const content=location.hash;new UnknownWidget(content).render();",
         "Constructor implementation and DOM behavior are unavailable."),
)


def manifest() -> dict:
    counts = Counter(case.label for case in CASES)
    if len(CASES) != 24 or len({case.id for case in CASES}) != 24:
        raise ValueError("Frozen suite requires 24 distinct cases")
    if counts != {"unsafe": 8, "safe": 8, "needs_review": 8}:
        raise ValueError("Frozen expected labels have changed")
    fingerprints = [sha256(c.code.encode()).hexdigest() for c in CASES]
    if len(set(fingerprints)) != len(CASES):
        raise ValueError("Duplicate case in fixed audit")
    return {
        "suite":"XSS-STATIC-FLOW-V5-2026-10-13",
        "created_for":"one-time-post-merge-static_audit",
        "source_revision":"683356c6acf974b7ae0c72e39121cc06052cb69a",
        "count":dict(counts),
        "code_sha256":{c.id:sha256(c.code.encode()).hexdigest() for c in CASES},
        "model_evaluated":False, "training_use":"FORBIDDEN",
        "browser_executions":0, "promotion":"DO_NOT_PROMOTE",
        "limitations":"new synthetic patterns; semantic similarity with development is possible",
    }


def evaluate() -> dict:
    info=manifest()
    confusion={gold:Counter({"CANDIDATE":0,"SAFE":0,"INCONCLUSIVE":0})
               for gold in ("unsafe","safe","needs_review")}
    cases=[]
    for c in CASES:
        result=grounded_review(c.code)
        status=result["decision"]["status"]
        if status not in confusion[c.label]:
            raise RuntimeError("Oracle returned unexpected decision")
        if result["browser_confirmed"] or result["model_has_final_authority"]:
            raise AssertionError("Unexpected runtime/browser or model authority")
        confusion[c.label][status]+=1
        cases.append({
            "id":c.id,"family":c.family,"expected_static_class":c.label,
            "oracle":status,"reviewer_note":c.reviewer_note,
            "limitations":result["limitations"],
            "snippet_sha256":info["code_sha256"][c.id],
        })
    n=8
    return {
        "manifest":info,
        "total":len(CASES),
        "metrics":{
            "candidate_recall_on_unsafe":confusion["unsafe"]["CANDIDATE"]/n,
            "unsafe_abstention":confusion["unsafe"]["INCONCLUSIVE"]/n,
            "unsafe_incorrectly_safe":confusion["unsafe"]["SAFE"]/n,
            "safe_false_positive_rate":confusion["safe"]["CANDIDATE"]/n,
            "safe_abstention":confusion["safe"]["INCONCLUSIVE"]/n,
            "under_specified_overclaim_rate":1-confusion["needs_review"]["INCONCLUSIVE"]/n,
            "decision_coverage":sum(
                c["oracle"]!="INCONCLUSIVE" for c in cases
            )/len(CASES),
        },
        "confusion":{k:dict(v) for k,v in confusion.items()},
        "cases":cases,
        "runtime_xss_confirmed":0,
        "production_approval":False,
    }


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    result=evaluate()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps({k:v for k,v in result.items() if k!="cases"},indent=2))


if __name__=="__main__":
    main()
