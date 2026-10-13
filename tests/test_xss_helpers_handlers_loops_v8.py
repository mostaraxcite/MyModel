"""V7's exposed audit is now regression data; exercise V8 semantic boundaries."""
import json
from pathlib import Path
import pytest
from xss_specialist.grounded_advisor import grounded_review

def status(code):
    return grounded_review(code)['decision']['status']

EXPOSED=Path(__file__).resolve().parents[1]/'evaluation/fixtures/xss_scope_url_v7_fresh.jsonl'
CASES=[json.loads(line) for line in EXPOSED.read_text().splitlines()]

@pytest.mark.parametrize('case',CASES,ids=lambda c:c['id'])
def test_previously_fresh_audit_is_exposed_regression(case):
    result=grounded_review(case['code'])
    expected=('CANDIDATE' if case['label']=='unsafe' else
              'INCONCLUSIVE' if case['id'] in {'N-S10','N-S11'} else 'SAFE')
    assert result['decision']['status']==expected,result
    assert result['browser_confirmed'] is False

@pytest.mark.parametrize('code',[
    "function receive(event){const value=event.data;panel.innerHTML=value;}addEventListener('message',receive);",
    "function receive({data: value}){panel.innerHTML='<div>'+value+'</div>';}window.onmessage=receive;",
    "function receive(value){panel.innerHTML=value;}Promise.resolve(window.name).then(receive);",
    "function a(x){return b(x);}function b(x){return c(x);}function c(x){return x;}panel.innerHTML=a(window.name);",
    "let markup='';for(let i=0;i<5;i++){markup+=window.name;i++;}panel.innerHTML=markup;",
    "let markup='';for(let i=0;i<5;i++){markup=window.name;++i;}panel.innerHTML=markup;",
    "let markup='';for(let i=0;i<7;i++){markup=window.name;i+=2;}panel.innerHTML=markup;",
])
def test_new_supported_dangerous_paths(code):
    assert status(code)=='CANDIDATE'

@pytest.mark.parametrize('code',[
    "function receive(event){panel.textContent=event.data;}window.addEventListener('message',receive,true);",
    "function a(x){return b(x);}function b(x){return c(x);}function c(x){return encodeURIComponent(x);}const value=a(window.name);panel.innerHTML='<div>'+value+'</div>';",
    "let markup=window.name;for(let i=0;i<5;i++){markup='fixed';i++;}panel.innerHTML=markup;",
    "let markup=window.name;for(let i=0;i<7;i++){markup='fixed';i+=2;}panel.innerHTML=markup;",
])
def test_new_supported_bounded_safe_paths(code):
    assert status(code)=='SAFE'

@pytest.mark.parametrize('code',[
    "let value='fixed';function receive(e){panel.innerHTML=value;}window.addEventListener('message',receive);value=window.name;",
    "let value='fixed';window.addEventListener('message',e=>{panel.innerHTML=value;});value=window.name;",
    "let value=window.name;function receive(e){panel.innerHTML=value;}{const value='fixed';window.addEventListener('message',receive);}",
    "let value=window.name;function read(){return value;}{const value='fixed';panel.innerHTML=read();}",
    "let value=window.name;function outer(x){const value='fixed';return inner(x);}function inner(x){return value;}panel.innerHTML=outer('constant');",
    "function receive(e){panel.innerHTML=e.data;}receive=unknown;window.addEventListener('message',receive);",
    "function receive(e){panel.innerHTML=e.data;}unknown();window.onmessage=receive;",
    "function a(x){return b(x);}function b(x){return a(x);}panel.innerHTML=a(window.name);",
    "function a(x){return b(x);}function b(x){return c(x);}function c(x){return d(x);}function d(x){return x;}panel.innerHTML=a(window.name);",
    "function encode(x){return 'fixed';}function receive(e){panel.innerHTML=encode(e.data);}window.onmessage=receive;encode=unknown;",
    "let x=window.name;for(let i=0;i<3;i++){i-=1;x='fixed';}panel.innerHTML=x;",
    "let x=window.name;for(let i=0;i<3;i++){if(flag){i+=1;}x='fixed';}panel.innerHTML=x;",
    "let x=window.name;for(let i=0;i<3;i++){i=window.name;x='fixed';}panel.innerHTML=x;",
    "let x=window.name;for(let i=0;i<3;i++){unknown();i+=1;x='fixed';}panel.innerHTML=x;",
    "let x=window.name;for(let i=0;i<20;i++){i+=1;x='fixed';}panel.innerHTML=x;",
    "let x=window.name;for(let i=0;i<3;i++){let i=0;i++;x='fixed';}panel.innerHTML=x;",
    "let x=window.name;for(let i=0;i<8;i++){for(let j=0;j<8;j++){for(let k=0;k<2;k++){x='fixed';}}}panel.innerHTML=x;",
])
def test_unknown_identity_scope_recursion_and_counter_effects_abstain(code):
    assert status(code)=='INCONCLUSIVE'
