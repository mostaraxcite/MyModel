"""Execute selected source fragments in explicit, network-isolated fixtures.

Labels concern these conditional output fixtures, not original applications.
Author review is disclosed; this is not an independent production benchmark.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import secrets
from urllib.parse import urlparse

from evaluation.decision_metrics import score_decisions
from xss_specialist.grounded_advisor import grounded_review


ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / 'evaluation/fixtures/xss_external_conditional_v11.json'
MANIFEST = ROOT / 'evaluation/fixtures/xss_external_conditional_v11_manifest.json'
VENDOR = ROOT / 'evaluation/vendor/jquery-4.0.0.js'
SOURCES = ROOT / 'evaluation/fixtures/xss_external_sources_v10.json'


def load_frozen():
    manifest = json.loads(MANIFEST.read_text())
    if hashlib.sha256(CASES.read_bytes()).hexdigest() != manifest['cases_sha256']:
        raise ValueError('Frozen case hash mismatch')
    if hashlib.sha256(VENDOR.read_bytes()).hexdigest() != manifest['jquery_sha256']:
        raise ValueError('Frozen dependency hash mismatch')
    # Content-addressed upstream blob, not a mutable default-branch assertion.
    raw = VENDOR.read_bytes()
    blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    if blob != manifest['jquery_blob_sha']:
        raise ValueError('Upstream jQuery blob mismatch')
    sources = json.loads(SOURCES.read_text())
    sources = {(s['repository'], s['revision'], s['path']): s['code'] for s in sources}
    cases = json.loads(CASES.read_text())
    seen = set()
    for case in cases:
        if case['id'] in seen:
            raise ValueError('Duplicate case identity')
        seen.add(case['id'])
        provenance = case['provenance']
        original = sources[(provenance['repository'], provenance['revision'], provenance['path'])]
        fragment = case['original_fragment']
        if hashlib.sha256(original.encode()).hexdigest() != case['source_sha256'] or fragment not in original:
            raise ValueError('Original source/fragment mismatch')
        if hashlib.sha256(fragment.encode()).hexdigest() != case['fragment_sha256']:
            raise ValueError('Fragment hash mismatch')
        # Setup is never part of the static input: no injected synthetic source.
        expected = 'const externalCallback = ' + fragment + ';' if case['fixture_kind'].endswith('callback') else fragment
        if case['code'] != expected:
            raise ValueError('Static input changed from declared original fragment')
    return cases, manifest


def js_string(value):
    return json.dumps(value).replace('<', '\\u003c')


def fixture_script(case):
    code = case['code']
    kind = case['fixture_kind']
    if kind == 'this-literal':
        code = '(function(){' + code + '}).call({_elt:__host});'
    elif kind == 'svg-callback':
        code += '\nwindow.__callbackResult=externalCallback.call(__svg,__input);'
    elif kind == 'dropdown-callback':
        code += '\nexternalCallback(__editor,null,function(){});'
    return code + '\nwindow.__fixtureCompleted=true;'


def run_browser(browser, case, vendor, *, before_fixture=None):
    # Letters-only nonce keeps the SVG fixture's four-number validation intact
    # when a markup payload is appended to its numeric input.
    nonce = ''.join(secrets.choice('abcdef') for _ in range(32))
    proof = "window.__auditProof='" + nonce + "'"
    payload = '<img src="http://audit.local/missing" onerror="' + proof + '">'
    context = browser.new_context(service_workers='block')
    observations, errors, requests = [], [], []
    context.add_init_script("let proofValue=null;Object.defineProperty(window,'__auditProof',{get(){return proofValue;},set(value){proofValue=value;console.debug('__EXTERNAL_XSS_MARKER__'+value);}});")
    setup = '''
window.__contextBaselineJQ=window.jQuery;
window.__contextBaselineMethods=Object.fromEntries(['html','text','val','attr','prop','find','get','append','prepend'].map(k=>[k,window.jQuery.fn[k]]));
window.__contextBaselineNative={query:Document.prototype.querySelectorAll,attribute:Element.prototype.getAttribute,text:Object.getOwnPropertyDescriptor(Node.prototype,'textContent').get,innerText:Object.getOwnPropertyDescriptor(HTMLElement.prototype,'innerText').get,value:Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').get};
const payload=PAYLOAD;
document.querySelector('textarea').value=payload;
document.querySelector('.some-element').textContent=payload;
document.querySelector('.some-element').setAttribute('data-target',payload);
document.querySelector('#foo').textContent=payload;
const nested=document.createElement('input');nested.className='bla';nested.value=payload;document.querySelector('#foo').appendChild(nested);
document.querySelector('#div1').setAttribute('data-target',payload);
document.querySelector('input').name=payload;
document.querySelector('option').value=payload;
const cite=document.createElement('cite');cite.textContent=payload;
document.querySelector('#quote').appendChild(cite);
window.$cite=jQuery(cite);window.$elm=jQuery('#quote');
window.__host=document.createElement('div');document.body.appendChild(__host);
window.__svg=document.querySelector('svg');
window.__input='0.1,0.2,0.3,0.4'+payload;
window.__editor={createDropDown:function(caller,name,node){document.body.appendChild(node);},closeDropDown:function(){}};
'''.replace('PAYLOAD', js_string(payload))
    main = '<!doctype html><html><body><div id="id"></div><textarea></textarea><div class="some-element"></div><div id="foo"></div><div id="div1"></div><input><select><option></option></select><div id="quote"></div><svg><path></path><line></line><line></line></svg><script src="/jquery.js"></script><script>' + setup + '</script><script src="/fixture.js"></script></body></html>'

    def route_handler(route):
        u = urlparse(route.request.url)
        requests.append({'url': route.request.url, 'resource_type': route.request.resource_type})
        if u.netloc == 'audit.local' and u.path == '/case':
            route.fulfill(status=200, content_type='text/html', body=main)
        elif u.netloc == 'audit.local' and u.path == '/jquery.js':
            route.fulfill(status=200, content_type='text/javascript', body=vendor)
        elif u.netloc == 'audit.local' and u.path == '/fixture.js':
            if before_fixture is not None:
                # The parser has completed trusted vendor/setup scripts, but
                # the original fragment has not been delivered or executed.
                before_fixture(route.request.frame, case, payload)
            route.fulfill(status=200, content_type='text/javascript', body=fixture_script(case))
        elif u.netloc == 'audit.local' and u.path == '/missing':
            route.fulfill(status=404, content_type='text/plain', body='missing')
        else:
            route.abort('blockedbyclient')

    context.route('**/*', route_handler)
    page = context.new_page()
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.on('console', lambda msg: observations.append(msg.text) if msg.text == '__EXTERNAL_XSS_MARKER__' + nonce else None)
    try:
        page.goto('http://audit.local/case', wait_until='load')
        try:
            page.wait_for_function('(nonce)=>window.__auditProof===nonce', arg=nonce, timeout=500)
        except Exception:
            pass
        runtime = page.evaluate('({proof:window.__auditProof,completed:window.__fixtureCompleted===true,jquery:window.jQuery?.fn.jquery,callbackResult:window.__callbackResult})')
        executed = runtime['proof'] == nonce or bool(observations)
        return {'executed': executed, 'fixture_completed': runtime['completed'],
                'label_agrees': executed == (case['label'] == 'unsafe'),
                'jquery_version': runtime.get('jquery'), 'proof_nonce': nonce,
                'observed_marker': runtime['proof'], 'callback_result': runtime.get('callbackResult'),
                'errors': errors, 'requests': requests,
                'network_policy': 'every request locally fulfilled or aborted; no live targets',
                'scope': 'conditional extracted output fixture only; safe label is semantic, not inferred from nonexecution'}
    finally:
        context.close()


def evaluate(output):
    from playwright.sync_api import sync_playwright
    cases, manifest = load_frozen()
    vendor = VENDOR.read_text()
    rows = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        version = browser.version
        try:
            for case in cases:
                evidence = run_browser(browser, case, vendor)
                static = grounded_review(case['code'])
                rows.append(case | {'browser': evidence, 'static_status': static['decision']['status'],
                                    'static_limitations': static.get('limitations', []),
                                    'browser_status': 'tested'})
        finally:
            browser.close()
    valid = all(r['browser']['label_agrees'] and r['browser']['fixture_completed'] and not r['browser']['errors'] for r in rows)
    report = {'manifest': manifest, 'cases_sha256': manifest['cases_sha256'], 'chromium': version,
              'fixture_validation_passed': valid, 'results': rows,
              'metrics': score_decisions(rows, manifest),
              'source_group_counts': dict(Counter(r['lineage_group'] for r in rows)),
              'independence_verified': False, 'production_accuracy_established': False,
              'model_evaluated': False, 'promotion': 'DO_NOT_PROMOTE'}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + '\n')
    compact = {'fixture_validation_passed': valid, 'counts': report['metrics']['counts'],
               'unsafe_candidate_recall': report['metrics']['unsafe_candidate_recall'],
               'safe_false_positive_rate': report['metrics']['safe_false_positive_rate'],
               'decision_coverage': report['metrics']['decision_coverage'],
               'browser_unsafe_executed': sum(r['browser']['executed'] for r in rows if r['label']=='unsafe')}
    print('V11_EXTERNAL_CONDITIONAL_EVIDENCE=' + json.dumps(report, separators=(',', ':')))
    print(json.dumps(compact))
    if not valid:
        raise SystemExit('Fixture/label mismatch: inspect retained evidence; do not relabel to fit the engine')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    evaluate(parser.parse_args().output)
