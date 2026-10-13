import json
from pathlib import Path
import pytest
from xss_specialist.grounded_advisor import grounded_review

def status(code):return grounded_review(code)['decision']['status']

CASES=[json.loads(line) for line in (Path(__file__).resolve().parents[1]/'evaluation/fixtures/xss_helpers_handlers_loops_v8_fresh.jsonl').read_text().splitlines()]

@pytest.mark.parametrize('case',CASES,ids=lambda c:c['id'])
def test_v8_audit_is_exposed_v9_regression(case):
    result=grounded_review(case['code'])
    assert result['decision']['status']==('CANDIDATE' if case['label']=='unsafe' else 'INCONCLUSIVE' if case['id']=='V8-S09' else 'SAFE')
    assert result['browser_confirmed'] is False

@pytest.mark.parametrize('code',[
    "window.onmessage=e=>{panel.innerHTML=value;};let value=window.name;",
    "let value='fixed';Promise.resolve('ignored').then(e=>{panel.innerHTML=value;});value=window.name;",
    "let value='fixed';window.onmessage=e=>{const copy=value;panel.innerHTML=copy;};value=window.name;",
    "let value='fixed';window.onmessage=e=>{panel.innerHTML=value;};if(window.name){value=window.name;}",
    "let value='fixed';function receive(e){panel.innerHTML=value;}window.onmessage=receive;receive=unknown;value=window.name;",
])
def test_deferred_global_capture_sees_final_connected_source(code):assert status(code)=='CANDIDATE'

@pytest.mark.parametrize('code',[
    "let value=window.name;window.onmessage=e=>{panel.innerHTML=value;};value='fixed';",
    "let value='fixed';window.onmessage=e=>{panel.innerHTML=value;};unknown();",
    "let value='fixed';window.onmessage=e=>{panel.innerHTML=value;};unknown();value=window.name;",
    "let value='fixed';window.onmessage=e=>{panel.innerHTML=value;};window.onmessage=null;value=window.name;",
    "let value='fixed';function receive(e){panel.innerHTML=value;}window.addEventListener('message',receive);window.removeEventListener('message',receive);value=window.name;",
    "let value=window.name;function receive(e){panel.innerHTML=value;}{const value='fixed';window.onmessage=receive;}",
    "let value=window.name;function read(){return value;}{const value='fixed';panel.innerHTML=read();}",
])
def test_unknown_or_cross_scope_capture_does_not_retain_spurious_candidate(code):assert status(code)=='INCONCLUSIVE'

def test_deferred_capture_replaces_provisional_path_without_duplicate_alert():
    result=grounded_review("let value='fixed';window.onmessage=e=>{panel.innerHTML=value;};value=window.name;")
    assert len(result['paths'])==1
    assert result['paths'][0]['source']['expressions']==['window.name']

def helper_chain(n):
    return ''.join(f'function f{i}(v){{return '+(f'f{i+1}(v)' if i<n-1 else 'v')+';}' for i in range(n))+'panel.innerHTML=f0(window.name);'

def test_acyclic_chain_review_uses_budget_not_four_function_cutoff():assert status(helper_chain(12))=='CANDIDATE'

def test_helper_budget_exhaustion_abstains():assert status(helper_chain(65))=='INCONCLUSIVE'

def test_captured_object_dirty_field_does_not_taint_its_constant_clean_field_by_guess():
    code="const packet={dirty:window.name,clean:'fixed'};window.onmessage=e=>{panel.innerHTML=packet.clean;};"
    assert status(code)=='INCONCLUSIVE'
