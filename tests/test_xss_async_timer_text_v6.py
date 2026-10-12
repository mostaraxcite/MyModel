"""New development cases for opt-in V6 async and inert DOM operations.

Do not score previous frozen 24-case audit during this implementation.
"""
import pytest

from xss_specialist.grounded_advisor import grounded_review


def review(code):
    return grounded_review(code)


@pytest.mark.parametrize("code",[
    "const stringBody=req.body.expression;window.setTimeout(stringBody,25);",
    "const stringBody=document.referrer;window.setInterval(stringBody,1000);",
])
def test_window_string_timers_are_executable_sinks(code):
    result=review(code)
    assert result["decision"]["status"]=="CANDIDATE",result
    assert result["paths"][0]["sink"]["kind"]=="SCRIPT_EXECUTION"
    assert result["browser_confirmed"] is False


def test_timer_function_callback_is_not_mistaken_for_executable_string():
    code="const input=location.search;window.setTimeout(()=>console.info(input),42);"
    assert review(code)["decision"]["status"]=="INCONCLUSIVE"


@pytest.mark.parametrize("code",[
    "Promise.resolve(window.name).then(result => { card.insertAdjacentHTML('afterend',result); });",
    "Promise.resolve(req.body.label).then(value => screen.outerHTML=value);",
])
def test_resolved_promises_transfer_taint_into_callback(code):
    result=review(code)
    assert result["decision"]["status"]=="CANDIDATE",result
    assert result["paths"][0]["flow"]["relation"]=="CONNECTED"
    assert result["paths"][0]["sink"]["kind"]=="HTML_PARSER"


@pytest.mark.parametrize("code",[
    "Promise.resolve(location.hash).then(result => { card.textContent=result; });",
    "Promise.resolve(req.query.nick).then(value => title.insertAdjacentText('beforeend',value));",
])
def test_resolved_promises_to_text_are_locally_safe(code):
    result=review(code)
    assert result["decision"]["status"]=="SAFE",result
    assert result["paths"][0]["sink"]["kind"]=="TEXT_ONLY"


@pytest.mark.parametrize("code",[
    "unknownPromise(location.hash).then(v => box.innerHTML=v);",
    "const Promise=thirdParty.Promise;Promise.resolve(location.search).then(v => box.outerHTML=v);",
])
def test_unknown_promise_implementations_abstain(code):
    assert review(code)["decision"]["status"]=="INCONCLUSIVE"


def test_replacement_with_proven_text_node_is_safe():
    result=review("const data=window.location.hash;const span=document.createTextNode(data);node.replaceChildren(span);")
    assert result["decision"]["status"]=="SAFE",result
    assert result["paths"][0]["defense"]["status"]=="SAFE_OUTPUT_API"


@pytest.mark.parametrize("code",[
    "const source=location.search;const other=document.createElement('script');box.replaceChildren(other);",
    "const source=location.search;const text=document.createTextNode(source);box.replaceChildren(text,unknownNode);",
    "const source=location.search;const element=notTextNode(source);box.replaceChildren(element);",
])
def test_unproven_replacement_node_abstains(code):
    assert review(code)["decision"]["status"]=="INCONCLUSIVE"


def test_url_constructor_with_fixed_path_and_proven_anchor_is_safe():
    code=("const dest=req.query.to;const a=document.createElement('a');"
          "const url=new URL('/open?to='+encodeURIComponent(dest),location.origin);"
          "a.href=url.href;")
    result=review(code)
    assert result["decision"]["status"]=="SAFE",result
    assert result["paths"][0]["defense"]["status"]=="VERIFIED_RELATIVE_URL_PREFIX"


def test_url_constructor_with_unproven_anchor_stays_inconclusive():
    code=("const dest=window.name;"
          "const url=new URL('/open?to='+encodeURIComponent(dest),location.origin);"
          "anchor.href=url.href;")
    result=review(code)
    assert result["decision"]["status"]=="INCONCLUSIVE",result


@pytest.mark.parametrize("code",[
    ("const dest=req.query.to;const a=document.createElement('a');"
     "const url=new URL('javascript:'+encodeURIComponent(dest),location.origin);a.href=url.href;"),
    ("const dest=req.query.to;const a=document.createElement('a');"
     "const url=new URL('/open?to='+dest,location.origin);a.href=url.href;"),
])
def test_url_constructor_with_unprotected_value_never_approves(code):
    assert review(code)["decision"]["status"]!="SAFE"



@pytest.mark.parametrize("code",[
    "const window=otherWindow;const x=location.hash;window.setTimeout(x,10);",
    "const window=library;const x=location.search;window.eval(x);",
])
def test_shadowed_window_execution_api_never_assumed_global(code):
    assert review(code)["decision"]["status"]=="INCONCLUSIVE"
