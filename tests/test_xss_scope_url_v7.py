"""Exposed regression examples and semantic boundaries, NOT held-out accuracy."""
import json
from pathlib import Path
import pytest
from xss_specialist.grounded_advisor import grounded_review

def status(code):return grounded_review(code)['decision']['status']

REGRESSION=Path(__file__).resolve().parents[1]/'evaluation/fixtures/xss_scope_url_v7_regression.jsonl'
CASES=[json.loads(line) for line in REGRESSION.read_text().splitlines()]

@pytest.mark.parametrize('case',CASES,ids=lambda c:c['id'])
def test_exposed_browser_audit_regression(case):
    result=grounded_review(case['code'])
    expected=('CANDIDATE' if case['label']=='unsafe' else
              'INCONCLUSIVE' if case['id'] in {'S13','S14'} else 'SAFE')
    assert result['decision']['status']==expected,result
    assert result['browser_confirmed'] is False

@pytest.mark.parametrize('code',[
    "let x=window.name;{let x='constant';{let x='other';}}panel.innerHTML=x;",
    "let x='fixed';{x=window.name;}panel.innerHTML=x;",
    "let x=window.name;{const x='fixed';panel.textContent=x;}panel.innerHTML=x;",
    "let x=window.name;window.addEventListener('message',e=>{var x='fixed';});panel.innerHTML=x;",
    "let x=window.name;window.addEventListener('message',e=>{{var x='fixed';}});panel.innerHTML=x;",
    "window.addEventListener('message',({data: content})=>{panel.innerHTML=content;},true);",
    "const packet={clean:'fixed',dirty:window.name};const alias=packet;panel.innerHTML=alias.dirty;",
    "function pass(a){const b=a;return b;}panel.innerHTML=pass(window.name);",
])
def test_new_scope_and_flow_paths(code):assert status(code)=='CANDIDATE'

@pytest.mark.parametrize('code',[
    "let x=window.name;{x='fixed';}panel.innerHTML=x;",
    "const packet={clean:'fixed',dirty:window.name};panel.innerHTML=packet.clean;",
    "const node=document.createElement('div');node.setAttribute('href',window.name);",
    "const node=document.createElement('img');node.href=window.name;",
    "window.onmessage=e=>{panel.textContent=e.data;};",
    "panel.innerHTML='<article>'+encodeURIComponent(window.name)+'</article>';",
    "const value=encodeURIComponent(window.name);panel.innerHTML='<div>'+value+'</div>';",
])
def test_new_bounded_safe_paths(code):assert status(code)=='SAFE'

@pytest.mark.parametrize('code',[
    "const value=encodeURIComponent(window.name);panel.innerHTML='<script>'+value+'</script>';",
    "const value=encodeURIComponent(window.name);panel.innerHTML='<button onclick=\"'+value+'\">x</button>';",
    "const value=encodeURIComponent(window.name);panel.innerHTML='<a href=\"javascript:'+value+'\">x</a>';",
    "const value=encodeURIComponent(window.name);panel.innerHTML='<div>'+value+window.name+'</div>';",
    "const value=encodeURIComponent(window.name);panel.innerHTML='<div>'+decodeURIComponent(value)+'</div>';",
    "const node=document.createElement('script');node.src='https://fixed.invalid/'+encodeURIComponent(window.name);",
    "const node=document.createElement('a');node.href='javascript:'+encodeURIComponent(window.name);",
])
def test_protection_does_not_escape_its_context(code):assert status(code)=='CANDIDATE'

@pytest.mark.parametrize('code',[
    "function pass(x){mutate(x);return 'safe';}panel.innerHTML=pass(window.name);",
    "function pass(x){return pass(x);}panel.innerHTML=pass(window.name);",
    "function pass(x){return 'fixed';}while(flag){pass=unknown;}panel.innerHTML=pass(window.name);",
    "function pass(x){return 'fixed';}if(flag){pass=unknown;}panel.innerHTML=pass(window.name);",
    "let x=window.name;for(let i=0;i<1;i++){i+=1;x='fixed';}panel.innerHTML=x;",
    "const packet={content:window.name};const alias=packet;unknown(alias);panel.innerHTML=packet.content;",
    "const packet={get content(){return window.name;}};panel.innerHTML=packet.content;",
    "const encodeURIComponent=unknown;panel.innerHTML=encodeURIComponent(window.name);",
    "const document=library;const node=document.createElement('div');node.setAttribute('href',window.name);",
    "const window=library;window.onmessage=e=>{panel.innerHTML=e.data;};",
    "window.addEventListener('message',e=>{panel.innerHTML=e.data;},options);",
])
def test_unknown_effects_cannot_claim_safe(code):assert status(code)=='INCONCLUSIVE'

def test_escaped_prefix_is_not_certified_safe():
    assert status("const node=document.createElement('a');node.href='/\\x2f'+encodeURIComponent(window.name);")!='SAFE'

@pytest.mark.parametrize('code',[
    "const value=encodeURIComponent(window.name);panel.innerHTML='<script/>'+value+'</script>';",
    "const value=encodeURIComponent(window.name);panel.innerHTML='<script>'+value+'</script><div>XSSENCODEDMARKER0END</div>';",
    "let safe='fixed';function pass(x){const unused=external.getter;return 'fixed';}pass(window.name);panel.innerHTML=safe;",
])
def test_malformed_context_and_unreviewed_getter_do_not_claim_safe(code):
    assert status(code)!='SAFE'
