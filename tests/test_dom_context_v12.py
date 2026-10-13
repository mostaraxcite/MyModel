import copy
import json
from pathlib import Path
import pytest
from xss_specialist.grounded_advisor import grounded_review
from xss_specialist.dom_context import validate_context

ROOT=Path(__file__).resolve().parents[1]
CONTEXT=json.loads((ROOT/'evaluation/fixtures/xss_dom_context_v12.json').read_text())
CASES=json.loads((ROOT/'evaluation/fixtures/xss_external_conditional_v11.json').read_text())

def status(code,context=CONTEXT):
    return grounded_review(code,dom_context=context)['decision']['status']

@pytest.mark.parametrize('case',[c for c in CASES if c['label']=='unsafe'],ids=lambda c:c['id'])
def test_exposed_conditional_dom_regressions(case):
    r=grounded_review(case['code'],dom_context=CONTEXT)
    assert r['decision']['status']=='CANDIDATE'
    assert r['browser_confirmed'] is False
    assert r['source']['status']=='CONDITIONAL_DOM_CONTEXT'
    assert r['dom_context']['verified_by_engine'] is False

@pytest.mark.parametrize('case',[c for c in CASES if c['label']=='safe'],ids=lambda c:c['id'])
def test_no_alerts_on_exposed_safe_output_fixtures(case):
    assert status(case['code']) in {'SAFE','INCONCLUSIVE'}

@pytest.mark.parametrize('code',[
    'const $=unknown;$("#id").html($("textarea").val());',
    'function $(x){return x;}$("#id").html($("textarea").val());',
    'const document=other;$("#id").html(document.getElementById("foo").textContent);',
    'unknown();$("#id").html($("textarea").val());',
    '$.fn.html=unknown;$("#id").html($("textarea").val());',
    '$("textarea").val("fixed");$("#id").html($("textarea").val());',
    'document.getElementById("foo").textContent="fixed";$("#id").html(document.getElementById("foo").textContent);',
    '$("#other").html($("unlisted").val());',
    '$("#id").html($("textarea").prop("unreviewed"));',
    '$("invalid [").html($("textarea").val());',
    'window.onmessage=e=>{$("#id").html($("textarea").val());};',
    '$("#id").html($("textarea").get(99).value);',
])
def test_shadowing_unknown_effects_writes_and_unlisted_inputs_abstain(code):
    assert status(code)=='INCONCLUSIVE'

def test_context_is_never_inferred_from_library_name():
    assert status('$("#id").html($("textarea").val());',None)=='INCONCLUSIVE'

def test_literal_selector_aliases_preserve_a_connected_source():
    assert status('const src=$("textarea");const dst=$("#id");dst.html(src.val());')=='CANDIDATE'

def test_text_setter_is_safe_output_not_html_parser():
    assert status('$("#id").text($("textarea").val());')=='SAFE'

def test_attribute_setter_is_not_an_attribute_input_read():
    assert status('$(".some-element").attr("data-target",$("textarea").val());')=='SAFE'

def test_same_named_custom_method_does_not_become_jquery():
    code='const box={html:unknown};box.html($("textarea").val());'
    assert status(code)=='INCONCLUSIVE'

def test_moving_an_arbitrary_dom_node_is_not_certified_inert():
    context=copy.deepcopy(CONTEXT);context['bindings']['$cite']['inert_node']=False
    assert status('$elm.prepend($cite);',context)=='INCONCLUSIVE'

@pytest.mark.parametrize('context',[{}, {'evidence_ref':'x','jquery_globals':[{}]}, {'evidence_ref':'x','inputs':{'textarea':['anything']}}, {'evidence_ref':'x','model_confirmed':True}])
def test_invalid_policy_fails_without_guessing(context):
    with pytest.raises(ValueError):validate_context(context)
