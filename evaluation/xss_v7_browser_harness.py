"""Isolated browser fixture verification; requests are fulfilled/aborted locally."""
import json,secrets
from urllib.parse import urlparse

def javascript_string(value):
    return json.dumps(value).replace('<','\\u003c')

def run_browser(browser,case):
    nonce=secrets.token_hex(12)
    proof=f'window.__auditProof={json.dumps(nonce)}'
    html_payload=f'<img src="http://audit.local/missing" onerror="{proof.replace(chr(34),chr(39))}">'
    kind=case['payload_kind']
    payload={'html':html_payload,'json_html':json.dumps({'content':html_payload}),
             'json_object':{'content':html_payload},'javascript':'javascript:'+proof+';void(0)',
             'js':proof,'remote_script':'http://audit.local/proof.js'}[kind]
    context=browser.new_context(service_workers='block')
    errors=[];requests=[];observations=[]
    # window.name is an explicitly controlled fixture input, not scanner output.
    context.add_init_script("let proofValue=null;Object.defineProperty(window,'__auditProof',{get(){return proofValue;},set(value){proofValue=value;console.debug('__XSS_AUDIT_MARKER__'+value);}});window.name="+javascript_string(payload if isinstance(payload,str) else '')+';')
    code=case['code'].replace('</script','<\\/script')
    main='<!doctype html><html><body><div id="panel"></div><img id="picture"><script>'+code+'</script></body></html>'
    sender='<!doctype html><script>parent.postMessage('+javascript_string(payload)+',"http://audit.local");</script>'
    def route_handler(route):
        url=route.request.url;u=urlparse(url)
        requests.append({'url':url,'resource_type':route.request.resource_type,'method':route.request.method})
        if u.netloc=='audit.local' and u.path=='/case':
            route.fulfill(status=200,content_type='text/html',body=main)
        elif u.netloc=='sender.local':
            route.fulfill(status=200,content_type='text/html',body=sender)
        elif u.netloc=='audit.local' and u.path=='/proof.js':
            route.fulfill(status=200,content_type='text/javascript',body=proof+';')
        elif u.netloc=='audit.local' and u.path=='/missing':
            route.fulfill(status=404,content_type='text/plain',body='missing')
        else:
            route.abort('blockedbyclient')
    context.route('**/*',route_handler)
    page=context.new_page()
    page.on('console',lambda message:observations.append(message.text) if message.text=='__XSS_AUDIT_MARKER__'+nonce else None)
    page.on('pageerror',lambda e:errors.append(str(e)))
    page.goto('http://audit.local/case',wait_until='load')
    if case['trigger']=='message':
        # A distinct origin sends an actual postMessage, not a forged event.
        page.evaluate("const sender=document.createElement('iframe');sender.src='http://sender.local/message';document.body.appendChild(sender);")
    if case['trigger']=='click':
        # Explicitly test the created link in an attached, user-clicked context.
        page.evaluate("jump.textContent='audit-link';jump.id='audit-link';document.body.appendChild(jump);")
        page.locator('#audit-link').click(no_wait_after=True)
    try:
        page.wait_for_function('(nonce)=>window.__auditProof===nonce',arg=nonce,timeout=450)
    except Exception:
        pass
    marker=page.evaluate('window.__auditProof')
    dom=page.evaluate("document.querySelector('#panel')?.innerHTML ?? null")
    executed=marker==nonce or bool(observations)
    result={'executed':executed,'expected_execution':case['label']=='unsafe',
            'label_agrees':executed==(case['label']=='unsafe'),
            'proof_nonce':nonce,'observed_marker':marker,'errors':errors,'requests':requests,
            'network_policy':'all requests locally fulfilled or aborted; no external network',
            'panel_html':dom,'trigger':case['trigger'],'synchronous_marker_observations':observations,
            'scope':'synthetic fixture proof only; created links mounted and user-clicked by harness'}
    context.close()
    return result
