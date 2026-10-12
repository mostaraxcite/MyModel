"""Novel, reviewed synthetic JavaScript XSS examples, not browser executions.

Exact source snippets do not come from previous training/evaluation sets.
Two partitions: diagnostic may guide development; audit is scored once
after code is frozen. Static labels mean possible paths, not real exploits.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
import argparse
import json
from pathlib import Path

from xss_specialist.grounded_advisor import grounded_review

@dataclass(frozen=True)
class Case:
    id: str
    family: str
    expected: str
    partition: str
    code: str
    rationale: str
    trusted_modules: tuple[str, ...] = ()

CASES = (
    Case("U01","html_concat","unsafe","diagnostic","const ref=document.referrer; notice.innerHTML='<em>'+ref+'</em>';","Referrer flows into an HTML parser."),
    Case("U02","html_adjacent","unsafe","diagnostic","const info=req.body.publicDescription; card.insertAdjacentHTML('afterbegin',info);","Request body flows into HTML parsing."),
    Case("U03","document_write","unsafe","diagnostic","const label=req.query.displayName; document.writeln('<section>'+label+'</section>');","Untrusted query content reaches document.writeln."),
    Case("U04","html_url_constructor","unsafe","diagnostic","const raw=new URL(location.href).searchParams.get('body'); preview.outerHTML=raw;","Untrusted URL value reaches outerHTML."),
    Case("U05","javascript_eval","unsafe","diagnostic","const script=window.name; window.eval(script);","Untrusted window.name passed to eval."),
    Case("U06","function_constructor","unsafe","diagnostic","let task=document.URL; const fn=new Function(task);","Untrusted document URL compiled as JS."),
    Case("U07","event_attribute","unsafe","diagnostic","const listener=req.body.handler; button.setAttribute('onchange',listener);","Event attribute may interpret untrusted JS."),
    Case("U08","iframe_srcdoc","unsafe","diagnostic","const fragment=decodeURI(document.location.hash); previewFrame.srcdoc=fragment;","Iframe srcdoc parses markup."),
    Case("U09","html_concat_alias","unsafe","diagnostic","const t=String(req.params.topic); tile.innerHTML='<strong>'+t+'</strong>';","Untrusted text concatenated into HTML."),
    Case("U10","timer_string","unsafe","diagnostic","const command=req.query.task; setInterval(command,250);","String-based timer may execute JS."),
    Case("U11","postmessage_callback","unsafe","audit","window.addEventListener('message',function(msg){view.innerHTML=msg.data;});","Unrestricted cross-window message rendered as HTML."),
    Case("U12","loop_flow","unsafe","audit","let assembled=location.hash;for(let i=0;i<2;i++){assembled+='!';}node.outerHTML=assembled;","Taint survives a loop before outerHTML."),
    Case("U13","javascript_href","unsafe","audit","const next=new URLSearchParams(window.location.search).get('continue');jump.setAttribute('href',next);","Missing scheme check permits dangerous link URL."),
    Case("U14","script_src","unsafe","audit","const src=new URLSearchParams(location.search).get('lib');document.querySelector('script').src=src;","Untrusted script URL may execute code subject to browser policy."),
    Case("U15","uppercased_html","unsafe","audit","const incoming=location.search.toUpperCase();panel.innerHTML=incoming;","Uppercasing does not make markup safe."),

    Case("S01","text_dom","safe","diagnostic","let markup=document.referrer;region.textContent=markup;","textContent inserts inert text."),
    Case("S02","insert_adjacent_text","safe","diagnostic","const t=req.query.label;region.insertAdjacentText('afterbegin',t);","insertAdjacentText is text-only."),
    Case("S03","attribute_title","safe","diagnostic","const t=window.location.hash;badge.setAttribute('title',t);","Title attribute is not a JS execution sink."),
    Case("S04","innertext","safe","diagnostic","const name=req.body.nickname;status.innerText=name;","innerText does not parse HTML."),
    Case("S05","overwrite","safe","diagnostic","let t=location.search;t='fixed status';status.outerHTML=t;","Untrusted value overwritten before sink."),
    Case("S06","sanitized_html","safe","diagnostic","import purify from 'dompurify';let msg=document.URL;modal.innerHTML=purify.sanitize(msg);","Audited sanitizer protects the HTML sink.",("dompurify",)),
    Case("S07","create_text_node","safe","diagnostic","const label=location.hash;const text=document.createTextNode(label);target.appendChild(text);","Text node cannot interpret HTML."),
    Case("S08","data_attribute","safe","diagnostic","let info=req.params.memo;item.setAttribute('data-note',info);","data-* is inert for local XSS analysis."),
    Case("S09","percent_encoded_html","safe","diagnostic","const data=location.hash;preview.innerHTML=encodeURIComponent(data);","Percent encoding removes markup delimiters."),
    Case("S10","append_string","safe","audit","let name=location.search;content.append(name);","Node.append inserts strings as text."),
    Case("S11","replace_text_node","safe","audit","let title=window.name;slot.replaceChildren(document.createTextNode(title));","Text node is inert when appended."),
    Case("S12","log_then_constant","safe","audit","const query=location.search;console.info(query);detail.innerHTML='<span>Ready</span>';","Logging does not change static HTML value."),
    Case("S13","sanitizer_alias","safe","audit","import cleaner from 'dompurify';const v=window.name;const result=cleaner.sanitize(v);tile.outerHTML=result;","Audited sanitizer protects HTML.",("dompurify",)),
    Case("S14","fixed_path_prefix","safe","audit","const name=location.search;action.href='/profile?key='+encodeURIComponent(name);","Fixed path prefix prevents javascript scheme."),
    Case("S15","constant_sink","safe","audit","const bad=req.query.html;const clean='all good';section.innerHTML=clean;","Untrusted input disconnected from HTML sink."),

    Case("Q01","unknown_filter","needs_review","diagnostic","const v=maybeClean(location.hash);view.outerHTML=v;","Unknown sanitizer effect."),
    Case("Q02","dynamic_attribute","needs_review","diagnostic","const v=req.body.message;target.setAttribute(attributeFromConfig,v);","Unresolved attribute execution context."),
    Case("Q03","opaque_library","needs_review","diagnostic","const v=plugin.getMessage();target.innerHTML=v;","Unknown trust and implementation."),
    Case("Q04","mutating_call","needs_review","diagnostic","let v=location.hash;mutateState(v);target.innerHTML=v;","Unresolved side effects."),
    Case("Q05","unreviewed_package","needs_review","diagnostic","import clean from 'unreviewed-html';const s=clean.sanitize(location.hash);box.innerHTML=s;","Unverified sanitizer identity."),
    Case("Q06","complex_branch","needs_review","diagnostic","const content=maybeHtml?location.hash:input;node.innerHTML=content;","Unresolved branch and alternate source."),
    Case("Q07","callback_unknown","needs_review","diagnostic","remoteApi.fetchContent(function(value){output.innerHTML=value;});","Unknown remote callback and provenance."),
    Case("Q08","storage_trust","needs_review","audit","let text=sessionStorage.getItem('draftText');surface.innerHTML=text;","Storage may be attacker-controlled; origin is not established."),
    Case("Q09","unknown_escape","needs_review","audit","let raw=location.hash;output.innerHTML=unknownEscape(raw);","Unverified escaping routine."),
    Case("Q10","dynamic_method","needs_review","audit","const text=location.hash;editor[methodName]('beforeend',text);","Dynamic method may parse markup or text."),
    Case("Q11","widget_bridge","needs_review","audit","const value=widgetBridge.read();widgetBridge.render(value);","Unknown library source and rendering context."),
    Case("Q12","resolver_href","needs_review","audit","const address=resolver.getRoute(req.query.id);portal.setAttribute('href',address);","URL resolver and scheme policy are unverified."),
)
LABELS=("unsafe","safe","needs_review")
DECISIONS=("CANDIDATE","SAFE","INCONCLUSIVE")
PARTITIONS=("diagnostic","audit")

def dataset_manifest() -> dict:
    counts=Counter(c.expected for c in CASES)
    parts=Counter(c.partition for c in CASES)
    if len(CASES)!=42 or len({c.id for c in CASES})!=42:
        raise ValueError("Expected exactly 42 unique static cases")
    if counts!=Counter({"unsafe":15,"safe":15,"needs_review":12}):
        raise ValueError("Label distribution changed unexpectedly")
    if parts!=Counter({"diagnostic":26,"audit":16}):
        raise ValueError("Partition distribution changed unexpectedly")
    if len({c.code.strip() for c in CASES})!=len(CASES):
        raise ValueError("Duplicate code in suite")
    return {
        "id":"manual-xss-static-2026-10-13-v1",
        "scope":"local_JS_static_potential_NOT_browser_confirmed",
        "source":"new_manual_synthetic_examples_not_real_sites",
        "label_distribution":dict(counts),
        "partitions":dict(parts),
        "code_sha256":{c.id:sha256(c.code.encode()).hexdigest() for c in CASES},
        "test_only":True, "training_use":"FORBIDDEN",
        "promotion":"DO_NOT_PROMOTE",
    }

def evaluate(*,partition:str) -> dict:
    if partition not in PARTITIONS:
        raise ValueError("Select diagnostic or audit partition explicitly")
    dataset_manifest()
    selected=[c for c in CASES if c.partition==partition]
    confusion={k:Counter({d:0 for d in DECISIONS}) for k in LABELS}
    details=[]
    for c in selected:
        report=grounded_review(c.code,trusted_modules=c.trusted_modules)
        d=report["decision"]["status"]
        if d not in DECISIONS:
            raise AssertionError("Invalid oracle decision")
        if report["browser_confirmed"] or report["model_has_final_authority"]:
            raise AssertionError("Static suite cannot confirm execution")
        confusion[c.expected][d]+=1
        details.append({
            "id":c.id,"family":c.family,"expected":c.expected,
            "static_decision":d,"rationale":c.rationale,
            "sha256":sha256(c.code.encode()).hexdigest(),
            "limitations":report["limitations"],
        })
    unsafe=sum(confusion["unsafe"].values())
    safe=sum(confusion["safe"].values())
    unclear=sum(confusion["needs_review"].values())
    return {
        "suite":"manual-xss-static-2026-10-13-v1",
        "partition":partition, "n":len(selected),
        "metrics":{
            "unsafe_candidate_recall":confusion["unsafe"]["CANDIDATE"]/unsafe,
            "unsafe_missed_as_safe":confusion["unsafe"]["SAFE"]/unsafe,
            "unsafe_abstention":confusion["unsafe"]["INCONCLUSIVE"]/unsafe,
            "safe_false_positive_rate":confusion["safe"]["CANDIDATE"]/safe,
            "safe_abstention":confusion["safe"]["INCONCLUSIVE"]/safe,
            "needs_review_overclaim_rate":(
                unclear-confusion["needs_review"]["INCONCLUSIVE"])/unclear,
            "decision_coverage":sum(
                v["static_decision"]!="INCONCLUSIVE" for v in details)/len(details),
        },
        "confusion":{k:dict(v) for k,v in confusion.items()},
        "cases":details, "browser_confirmed":0,"model_evaluated":False,
        "promotion":"DO_NOT_PROMOTE",
    }

def main() -> None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--partition",choices=PARTITIONS,required=True)
    p.add_argument("--report",type=Path)
    args=p.parse_args()
    report=evaluate(partition=args.partition)
    if args.report:
        args.report.parent.mkdir(parents=True,exist_ok=True)
        args.report.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({k:v for k,v in report.items() if k!="cases"},indent=2))

if __name__=="__main__":
    main()
