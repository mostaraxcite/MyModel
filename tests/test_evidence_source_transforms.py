"""Known JS source transforms must preserve taint, not silently mark SAFE."""
import pytest

from xss_specialist.evidence_pipeline import review_evidence


@pytest.mark.parametrize("expression",[
    "location.hash.slice(1)",
    "window.location.hash.substring(1)",
    "decodeURIComponent(location.hash.slice(1))",
    "new URLSearchParams(location.search).get('name')",
    "URLSearchParams(location.search).get('name')",
    "new URL(location.href).searchParams.get('name')",
    "new URLSearchParams(document.location.search).get('name')",
    "String(new URLSearchParams(location.search).get('name') ?? '')",
])
def test_url_source_transformations_preserve_untrusted_flow(expression):
    report=review_evidence("const value = "+expression+"; panel.innerHTML = value;")
    assert report["decision"]["status"]=="CANDIDATE", (expression, report)
    assert report["paths"][0]["flow"]["relation"]=="CONNECTED"


@pytest.mark.parametrize("expression",[
    "location.hash.slice(1)",
    "decodeURIComponent(location.hash.slice(1))",
    "new URLSearchParams(location.search).get('name')",
    "new URL(location.href).searchParams.get('name')",
])
def test_derived_untrusted_value_to_text_api_is_not_xss(expression):
    r=review_evidence("const value = "+expression+"; panel.textContent = value;")
    assert r["decision"]["status"]=="SAFE", (expression, r)
    assert r["paths"][0]["defense"]["status"]=="SAFE_OUTPUT_API"


def test_json_parse_nested_tainted_property_is_traced():
    code="const data = JSON.parse(decodeURIComponent(location.hash.slice(1))); pane.innerHTML = data.description;"
    r=review_evidence(code)
    assert r["decision"]["status"]=="CANDIDATE",r


def test_getall_join_is_tracked_but_not_a_sanitizer():
    code="const chunks = new URLSearchParams(location.search).getAll('word'); pane.innerHTML = chunks.join(' ');"
    assert review_evidence(code)["decision"]["status"]=="CANDIDATE"


def test_unknown_side_effects_always_abstain():
    code="const v=new URLSearchParams(location.search).get('q'); opaqueMutator(v); pane.innerHTML=v;"
    assert review_evidence(code)["decision"]["status"]=="INCONCLUSIVE"


def test_not_every_get_call_is_a_source():
    r=review_evidence("const v = unknownStore.get('q'); pane.innerHTML=v;")
    assert r["decision"]["status"]=="INCONCLUSIVE"
