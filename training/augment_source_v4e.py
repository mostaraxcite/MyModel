"""Train-only source augmentation for v4e.

This file intentionally contains no examples copied from the sealed External v6
repositories. It broadens SOURCE lexical coverage for NONE/BROWSER/SERVER/
FRAMEWORK/OTHER while leaving the frozen dev set untouched.
"""
from __future__ import annotations
import argparse, json, random
from pathlib import Path
from xss_specialist.multitask import SOURCE_LABELS, IGNORE_INDEX

EXTRA={
"NONE":[
"'fixed'","42","true","null","undefined","config.siteTitle","settings.defaultLocale",
"static_message","default_value","'https://example.invalid/static'","100 + 23",
],
"BROWSER":[
"document.referrer","document.URL","document.documentURI","document.cookie",
"window.name","location.hash","location.search","window.location.search",
"localStorage.getItem('draft')","sessionStorage.getItem('filter')",
"event.data","message.data",
],
"SERVER":[
"req.query.term","req.body.comment","req.params.slug","request.query.page",
"request.body.profile","request.params.userId","$_GET['q']","$_POST['message']",
"httpRequest.query.keyword","httpRequest.body.bio","incomingRequest.params.code",
"serverRequest.query.value",
],
"FRAMEWORK":[
"route.params.slug","router.query.term","props.userInput","params.articleId",
"paramMap.get('slug')","pageProps.query","loaderData.value","routeData.item",
"_ctx.params.name","componentProps.search","navigation.params.id","viewParams.filter",
],
"OTHER":[
"payload.value","state.currentFilter","cacheEntry.content","serviceResult.text",
"record.description","messagePayload.body","userSelection.value","storeValue",
"domainObject.name","responseModel.title","queueItem.data","runtimeInput",
"formState.note","customInput.current","result.value","item.payload",
],
}

def row(label,expr,i,n):
    return {
        "id":f"source-v4e:{label}:{i}:{n}",
        "text":f"[SOURCE]\n{expr}",
        "source_label":SOURCE_LABELS.index(label),
        "sink_label":IGNORE_INDEX,
        "defense_label":IGNORE_INDEX,
        "flow_label":IGNORE_INDEX,
        "metadata":{
            "origin":"source-v4e-independent-hard-train",
            "label":label,
            "base_expression":expr,
            "external_v6_derived":False,
        },
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--base-train",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--repeat",type=int,default=10)
    p.add_argument("--seed",type=int,default=10111)
    a=p.parse_args()
    rows=[json.loads(x) for x in a.base_train.read_text().splitlines() if x.strip()]
    existing={r["text"] for r in rows}
    rng=random.Random(a.seed); added=0
    suffixes=["",";"," /* source-hard */"]
    for label,exprs in EXTRA.items():
        for i,expr in enumerate(exprs):
            for n in range(a.repeat):
                text=expr+suffixes[(n+rng.randrange(len(suffixes)))%len(suffixes)]
                r=row(label,text,i,n)
                if r["text"] in existing: continue
                rows.append(r); existing.add(r["text"]); added+=1
    rng.shuffle(rows)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text("".join(json.dumps(r,sort_keys=True)+"\n" for r in rows))
    counts={name:0 for name in SOURCE_LABELS}
    for r in rows:
        v=int(r["source_label"])
        if v!=IGNORE_INDEX: counts[SOURCE_LABELS[v]]+=1
    report={
        "schema":"xss-source-v4e-augmentation",
        "rows":len(rows),"added_rows":added,"source_counts":counts,
        "dev_modified":False,"external_v6_used":False,"locked_hard_used":False,
    }
    (a.output.parent/"manifest.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2))

if __name__=="__main__": main()
