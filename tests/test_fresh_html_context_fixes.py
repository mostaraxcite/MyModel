"""Defense-context regression: do not confuse HTML encoding with JS safety."""
import pytest

from xss_specialist.grounded_advisor import grounded_review


def _status(code):
    return grounded_review(code)["decision"]["status"]


def test_encoding_entire_untrusted_html_text_is_bounded_safe():
    r=grounded_review(
        "const input=location.hash;panel.innerHTML=encodeURIComponent(input);"
    )
    assert r["decision"]["status"]=="SAFE"
    path=r["paths"][0]
    assert path["flow"]["relation"]=="CONNECTED"
    assert path["defense"]["status"]=="CONTEXTUAL_HTML_ENCODING"
    assert path["defense"]["context_compatible"] is True
    assert "JavaScript execution contexts" in path["explanation"]
    assert r["browser_confirmed"] is False


@pytest.mark.parametrize("code", [
    "const input=location.hash;eval(encodeURIComponent(input));",
    "const input=location.search;new Function(encodeURIComponent(input));",
    "const input=location.hash;panel.setAttribute('onload',encodeURIComponent(input));",
    "const input=location.hash;panel.innerHTML=decodeURIComponent(encodeURIComponent(input));",
    "const input=location.hash;panel.innerHTML=encodeURIComponent(input)+input;",
    "const input=location.hash;panel.innerHTML=input+encodeURIComponent(input);",
])
def test_context_escape_cannot_be_overclaimed(code):
    assert _status(code)=="CANDIDATE"


@pytest.mark.parametrize("attr",["data-view", "data-user-payload", "aria-label", "title"])
def test_known_inert_literal_dom_attributes(attr):
    code=f"const name=location.search;node.setAttribute('{attr}',name);"
    r=grounded_review(code)
    assert r["decision"]["status"]=="SAFE"
    assert r["paths"][0]["defense"]["status"]=="SAFE_OUTPUT_API"


@pytest.mark.parametrize("code",[
    "const input=location.hash;node.setAttribute('onclick',input);",
    "const input=location.hash;node.setAttribute('onerror',encodeURIComponent(input));",
])
def test_unsafe_event_attributes_still_raise_candidate(code):
    assert _status(code)=="CANDIDATE"


def test_created_text_node_is_proven_inert_for_appendchild_only():
    code="const x=location.hash;const node=document.createTextNode(x);box.appendChild(node);"
    r=grounded_review(code)
    assert r["decision"]["status"]=="SAFE"
    assert r["paths"][0]["sink"]["kind"]=="TEXT_ONLY"
    assert r["paths"][0]["flow"]["relation"]=="CONNECTED"


@pytest.mark.parametrize("code",[
    "const x=location.hash;const node=document.createElement('script');box.appendChild(node);",
    "const x=location.hash;const node=document.createTextNode(x);unknown(node);box.appendChild(node);",
    "const x=location.hash;const node=document.createTextNode(x);box.appendChild(other);",
])
def test_unproven_appended_nodes_cannot_be_declared_safe(code):
    assert _status(code)=="INCONCLUSIVE"
