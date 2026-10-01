"""Targeted sink-only augmentation for semantic field v4d.

Keeps the existing dev set untouched and adds new train-only families focused on
the remaining weak sink classes: NONE, OTHER, DANGEROUS_JS, DANGEROUS_URL.
"""
from __future__ import annotations
import argparse, json, random
from pathlib import Path
from xss_specialist.multitask import SINK_LABELS, IGNORE_INDEX

EXTRA={
"NONE":[
"const copy2 = String(VALUE)","const flag = !!VALUE","const n = Number(VALUE)",
"const arr = [VALUE]","const obj = {value: VALUE}","return Boolean(VALUE)",
"const encodedJson = JSON.stringify({value: VALUE})","const clone = structuredClone(VALUE)",
"Promise.resolve(VALUE)","String(VALUE).trim()","VALUE?.toString()","Object.freeze({value: VALUE})",
],
"OTHER":[
"appBus.dispatch(VALUE)","domainEvents.publish(VALUE)","mailQueue.push(VALUE)",
"searchIndex.add(VALUE)","analytics.track(VALUE)","rpcClient.send(VALUE)",
"customStore.persist(VALUE)","jobQueue.schedule(VALUE)","webhookClient.post(VALUE)",
"featureFlag.log(VALUE)","telemetry.capture(VALUE)","pluginHost.forward(VALUE)",
"nativeApi.invoke(VALUE)","reportEngine.add(VALUE)","streamWriter.write(VALUE)",
"messageBroker.emit(VALUE)","auditChannel.record(VALUE)","metricsSink.observe(VALUE)",
"customConsumer.accept(VALUE)","unclassifiedOutput(VALUE)",
],
"DANGEROUS_JS":[
"window.setTimeout(VALUE,0)","globalThis.setInterval(VALUE,1)","(0,eval)(VALUE)",
"Function('x', VALUE)","new Function('return '+VALUE)()","window['eval'](VALUE)",
"globalThis['setTimeout'](VALUE,10)","Reflect.construct(Function,[VALUE])",
],
"DANGEROUS_URL":[
"window.location.href = VALUE","document.location = VALUE","location.href = VALUE",
"anchor.setAttribute('href', VALUE)","iframe.setAttribute('src', VALUE)",
"form.setAttribute('action', VALUE)","script.setAttribute('src', VALUE)",
"window.open(VALUE)","location.assign(VALUE)","location.replace(VALUE)",
],
}

def row(label,expr,i,n):
    return {
        "id":f"sink-v4d:{label}:{i}:{n}",
        "text":f"[SINK]\n{expr}",
        "source_label":IGNORE_INDEX,
        "sink_label":SINK_LABELS.index(label),
        "defense_label":IGNORE_INDEX,
        "flow_label":IGNORE_INDEX,
        "metadata":{"origin":"sink-v4d-hard-train","label":label,"base_expression":expr},
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--base-train",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--repeat",type=int,default=12)
    p.add_argument("--seed",type=int,default=10091)
    a=p.parse_args()
    rows=[json.loads(x) for x in a.base_train.read_text().splitlines() if x.strip()]
    existing={r["text"] for r in rows}
    added=0; rng=random.Random(a.seed)
    suffixes=["",";"," /* sink-hard */"]
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
    counts={name:0 for name in SINK_LABELS}
    for r in rows:
        v=int(r["sink_label"])
        if v!=IGNORE_INDEX: counts[SINK_LABELS[v]]+=1
    report={
        "schema":"xss-sink-v4d-augmentation",
        "rows":len(rows),"added_rows":added,"sink_counts":counts,
        "dev_modified":False,"locked_hard_or_external_used":False,
    }
    (a.output.parent/"manifest.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2))
if __name__=="__main__": main()
