"""New development regressions for bounded async flows, loops and URL sinks.

All samples are new local static code examples, NOT browser exploit proofs.
The old exposed 16-case audit is not consulted during this development.
"""
import pytest

from xss_specialist.grounded_advisor import grounded_review


def assess(code):
    return grounded_review(code)


@pytest.mark.parametrize("snippet", [
    "window.addEventListener('message', function(message){ panel.innerHTML = message.data; });",
    "addEventListener('message', e => { pane.outerHTML = e.data; });",
    "window.addEventListener('message', ev => box.insertAdjacentHTML('beforeend', ev.data));",
])
def test_untrusted_message_callback_to_html(snippet):
    r=assess(snippet)
    assert r["decision"]["status"]=="CANDIDATE", r
    assert r["paths"][0]["flow"]["relation"]=="CONNECTED"
    assert "message-event.data" in r["paths"][0]["source"]["expressions"]
    assert r["browser_confirmed"] is False


@pytest.mark.parametrize("snippet", [
    "window.addEventListener('message', function(event){ box.textContent = event.data; });",
    "addEventListener('message', e => { target.insertAdjacentText('afterbegin', e.data); });",
])
def test_message_callback_to_inert_text(snippet):
    r=assess(snippet)
    assert r["decision"]["status"]=="SAFE",r
    assert r["paths"][0]["sink"]["kind"]=="TEXT_ONLY"


def test_non_message_event_source_is_not_assumed_untrusted_message():
    r=assess("window.addEventListener('click', e => {box.innerHTML=e.data;});")
    assert r["decision"]["status"]=="INCONCLUSIVE"


@pytest.mark.parametrize("snippet",[
    "let x=location.hash; for(let j=0;j<3;j++){x+='!';} pane.outerHTML=x;",
    "let x=''; for(let k=0;k<2;k++){x+=document.referrer;}pane.innerHTML=x;",
])
def test_small_bounded_loops_keep_taint(snippet):
    r=assess(snippet)
    assert r["decision"]["status"]=="CANDIDATE",r
    assert r["paths"][0]["sink"]["kind"]=="HTML_PARSER"


@pytest.mark.parametrize("snippet",[
    "let x=location.hash;for(let n=0;n<2;n++){x='safe';}box.innerHTML=x;",
    "let x='ok';for(let n=0;n<2;n++){x='still ok';}box.innerHTML=x;",
])
def test_simple_constant_loops_do_not_invent_xss(snippet):
    assert assess(snippet)["decision"]["status"]=="SAFE"


@pytest.mark.parametrize("snippet",[
    "let x=location.hash; for(let n=0;n<20;n++){x+='a';}box.innerHTML=x;",
    "let x=location.hash;for(let n=0;n<limit;n++){x='safe';}box.innerHTML=x;",
    "let x=location.hash;while(flag){x='safe';}box.innerHTML=x;",
])
def test_unbounded_loop_cannot_claim_safe(snippet):
    assert assess(snippet)["decision"]["status"]=="INCONCLUSIVE"


@pytest.mark.parametrize("snippet,kind",[
    ("const x=location.hash;window.location.href=x;", "POTENTIAL_SCRIPT_URL"),
    ("const x=req.query.back;location.href=x;", "POTENTIAL_SCRIPT_URL"),
    ("const a=document.createElement('a');a.href=location.search;", "POTENTIAL_SCRIPT_URL"),
    ("const x=req.query.url;document.querySelector('a').setAttribute('href',x);", "POTENTIAL_SCRIPT_URL"),
    ("const x=location.hash;const s=document.createElement('script');s.src=x;", "REMOTE_SCRIPT_URL"),
    ("const url=location.search;document.querySelector('script').src=url;", "REMOTE_SCRIPT_URL"),
])
def test_tainted_script_urls_remain_candidates(snippet,kind):
    r=assess(snippet)
    assert r["decision"]["status"]=="CANDIDATE",r
    assert r["paths"][0]["sink"]["kind"]==kind
    assert r["paths"][0]["defense"]["status"]=="NONE"


@pytest.mark.parametrize("snippet", [
    "const x=location.search;const a=document.createElement('a');a.href='/view?id='+encodeURIComponent(x);",
    "const x=window.name;document.querySelector('a').setAttribute('href','/safe?q='+encodeURIComponent(x));",
])
def test_bounded_fixed_relative_url_encoding_is_safe(snippet):
    r=assess(snippet)
    assert r["decision"]["status"]=="SAFE",r
    assert r["paths"][0]["defense"]["status"]=="VERIFIED_RELATIVE_URL_PREFIX"


@pytest.mark.parametrize("snippet",[
    "const x=location.search;const a=document.createElement('a');a.href='javascript:'+encodeURIComponent(x);",
    "const x=location.search;const a=document.createElement('a');a.href='/safe?x='+x;",
    "const x=location.search;const a=document.createElement('a');a.href='//evil.invalid/'+encodeURIComponent(x);",
    "const x=location.hash;document.querySelector('script').src=encodeURIComponent(x);",
])
def test_url_html_encoding_is_not_universal_url_safety(snippet):
    assert assess(snippet)["decision"]["status"]=="CANDIDATE"


@pytest.mark.parametrize("snippet",[
    "const url=location.search;const img=document.createElement('img');img.src=url;",
    "const url=location.hash;widget.href=url;",
    "const url=location.search;target[dynamicProperty]=url;",
])
def test_unknown_dom_element_or_property_abstains(snippet):
    assert assess(snippet)["decision"]["status"]=="INCONCLUSIVE"


def test_console_call_no_longer_discards_safe_constant_sink():
    r=assess("const q=location.hash;console.info(q);pane.innerHTML='<em>fixed</em>';")
    assert r["decision"]["status"]=="SAFE"
    assert r["browser_confirmed"] is False


def test_untrusted_shadowed_console_still_abstains():
    r=assess("const console=unsafeProxy;const q=location.hash;console.info(q);pane.innerHTML='fixed';")
    assert r["decision"]["status"]=="INCONCLUSIVE"
