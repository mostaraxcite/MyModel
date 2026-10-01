"""Augment semantic-field v4 training with diverse hard unknown/OTHER examples.

The v4 dev set is left untouched. This only expands training using new template
families after aggregate class metrics showed OTHER as the dominant weakness.
No locked Hard/External data is read.
"""
from __future__ import annotations
import argparse, json, random, hashlib
from pathlib import Path
from xss_specialist.multitask import SOURCE_LABELS,SINK_LABELS,DEFENSE_LABELS,IGNORE_INDEX

EXTRA={
"source":{
"OTHER":[
"mqttMessage.payload","websocketFrame.data","ipcChannel.read()","kafkaRecord.value",
"redisStream.message","filesystemWatcher.event","nativeBridge.input","electronMessage.args",
"browserExtension.message","grpcRequest.metadata.value","amqpDelivery.body","workerMessage.data",
"serialPort.read()","customProtocol.payload","pluginApi.readInput()","thirdPartySdk.rawValue",
"analyticsEvent.properties.value","clipboardAdapter.read()","deviceBridge.message","hookContext.external",
],
"BROWSER":[
"history.state.userInput","navigator.clipboard.readText()","window.opener.name",
"document.location.search","window.location.href","location.pathname",
],
"SERVER":[
"req.headers['x-input']","req.cookies.userValue","request.files.upload.name",
"request.headers.get('x-value')","ctx.request.body.note","event.request.queryStringParameters.q",
],
"FRAMEWORK":[
"searchParams.get('q')","loaderData.message","useParams().slug","useSearchParams()[0].get('next')",
"routeData.payload","serverProps.userText",
],
"NONE":[
"APP_NAME","settings.version","Math.PI","'trusted-static'","Object.freeze({}).name","KNOWN_CONSTANT",
],
},
"sink":{
"OTHER":[
"messageBus.publish(VALUE)","socket.send(VALUE)","storage.save(VALUE)","database.insert(VALUE)",
"metrics.tag(VALUE)","auditTrail.append(VALUE)","cache.write(VALUE)","worker.postMessage(VALUE)",
"nativeBridge.send(VALUE)","notificationQueue.enqueue(VALUE)","pluginSink.consume(VALUE)",
"reporter.capture(VALUE)","eventStore.record(VALUE)","logger.debug(VALUE)","trace.addAttribute(VALUE)",
"customOutput.render(VALUE)","serializer.store(VALUE)","transport.write(VALUE)","observer.next(VALUE)",
"applicationHook(VALUE)",
],
"NONE":[
"const normalized = VALUE.trim()","VALUE.toLowerCase()","Boolean(VALUE)","Number(VALUE)",
"Array.from(VALUE)","Object.assign({}, {value: VALUE})",
],
"DANGEROUS_JS":[
"globalThis.setTimeout(VALUE, 0)","window.setInterval(VALUE, 10)","Reflect.construct(Function,[VALUE])",
],
"DANGEROUS_URL":[
"location.assign(VALUE)","location.replace(VALUE)","window.open(VALUE)","meta.content = VALUE",
],
"SAFE_OUTPUT":[
"node.append(document.createTextNode(VALUE))","element.replaceChildren(document.createTextNode(VALUE))",
],
},
"defense":{
"OTHER":[
"projectSpecificGuard(VALUE)","vendorSecurityWrapper(VALUE)","customPolicyEngine.check(VALUE)",
"legacyFilter.transform(VALUE)","pluginSanitizer.handle(VALUE)","applicationEscape(VALUE)",
"safeish(VALUE)","normalizeThenTrust(VALUE)","companySecurity.clean(VALUE)","unknownEncoder(VALUE)",
"domainPolicy.apply(VALUE)","securityMiddleware.process(VALUE)","tenantGuard(VALUE)",
"customValidationLayer(VALUE)","proprietaryEscape(VALUE)","frameworkPlugin.filter(VALUE)",
"redactMaybe(VALUE)","userDefinedSanitizer(VALUE)","thirdPartyGuard.process(VALUE)","securityHook(VALUE)",
],
"SANITIZATION":[
"sanitizeHtmlFragment(VALUE)","DOMPurify.sanitize(VALUE, {USE_PROFILES:{html:true}})",
"htmlSanitizer.sanitize(VALUE)","bleach.clean(VALUE)",
],
"CONTEXTUAL_ENCODING":[
"encodeForJavaScript(VALUE)","encodeForURL(VALUE)","escapeCss(VALUE)","escapeXml(VALUE)",
],
"INPUT_CONSTRAINT":[
"URL.canParse(VALUE)","/^\\w{1,32}$/.test(VALUE)","allowedValues.has(VALUE)",
],
}
}

SPACES={"source":SOURCE_LABELS,"sink":SINK_LABELS,"defense":DEFENSE_LABELS}

def add_rows(rows,repeat,seed):
    rng=random.Random(seed)
    existing={r["text"] for r in rows}
    for task,classes in EXTRA.items():
        for label,exprs in classes.items():
            li=SPACES[task].index(label)
            for i,expr in enumerate(exprs):
                for n in range(repeat):
                    variants=[
                        expr,
                        expr+";",
                        "value = "+expr if not expr.startswith(("<","/","'")) else expr,
                        expr+" /* hard-negative family */",
                    ]
                    field=variants[(n+rng.randrange(len(variants)))%len(variants)]
                    text=f"[{task.upper()}]\n{field}"
                    if text in existing: continue
                    row={
                        "id":f"semantic-field-v4c:train:{task}:{label}:{i}:{n}",
                        "text":text,
                        "source_label":IGNORE_INDEX,
                        "sink_label":IGNORE_INDEX,
                        "defense_label":IGNORE_INDEX,
                        "flow_label":IGNORE_INDEX,
                        "metadata":{
                            "origin":"semantic-field-v4c-hard-unknown",
                            "task":task,"label":label,"base_expression":expr,
                        },
                    }
                    row[f"{task}_label"]=li
                    rows.append(row); existing.add(text)
    rng.shuffle(rows)
    return rows

def counts(rows,task):
    out={x:0 for x in SPACES[task]}
    key=f"{task}_label"
    for r in rows:
        v=int(r[key])
        if v!=IGNORE_INDEX: out[SPACES[task][v]]+=1
    return out

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--base-train",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--repeat",type=int,default=8)
    p.add_argument("--seed",type=int,default=9091)
    a=p.parse_args()
    rows=[json.loads(x) for x in a.base_train.read_text().splitlines() if x.strip()]
    base=len(rows)
    rows=add_rows(rows,a.repeat,a.seed)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text("".join(json.dumps(r,sort_keys=True)+"\n" for r in rows))
    report={
        "schema":"xss-semantic-field-v4c-augmentation",
        "base_rows":base,"augmented_rows":len(rows),"added_rows":len(rows)-base,
        "counts":{t:counts(rows,t) for t in SPACES},
        "dev_modified":False,
        "locked_hard_or_external_used":False,
    }
    (a.output.parent/"augmentation_manifest.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2))
if __name__=="__main__": main()
