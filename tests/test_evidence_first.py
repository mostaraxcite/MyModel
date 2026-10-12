"""Evidence-first deterministic XSS gates: safe APIs, taint, sanitizers, abstention."""
import hashlib

import pytest

from xss_specialist.evidence_pipeline import review_evidence, validate_advisory
from xss_specialist.system import review
from xss_specialist.taint import analyze


def test_direct_untrusted_html_path_is_candidate_not_confirmed():
    text="const payload = location.hash; output.innerHTML = payload;"
    r=review_evidence(text)
    assert r["source"]["observed"] == ["location.hash"]
    assert r["decision"]["status"] == "CANDIDATE"
    assert r["decision"]["confirmed"] is False
    p=r["paths"][0]
    assert p["flow"]["relation"] == "CONNECTED"
    assert p["flow"]["trace"] == ["location.hash", "payload", "output.innerHTML"]
    assert p["sink"]["kind"] == "HTML_PARSER"
    assert p["defense"]["status"] == "NONE"


@pytest.mark.parametrize("code,sinkname", [
    ("output.textContent = location.hash;", "output.textContent"),
    ("output.insertAdjacentText('beforeend', location.hash);", "output.insertAdjacentText"),
    ("const p=location.hash; output.setAttribute('aria-label',p);", "output.setAttribute"),
])
def test_safe_dom_api_is_observed_and_not_alerted(code, sinkname):
    r=review_evidence(code)
    assert r["decision"]["status"] == "SAFE", r
    assert r["source"]["status"] == "OBSERVED"
    assert r["source"]["observed"] == ["location.hash"]
    assert r["paths"][0]["sink"]["expression"] == sinkname
    assert r["paths"][0]["flow"]["relation"] == "CONNECTED"
    assert r["paths"][0]["defense"]["status"] == "SAFE_OUTPUT_API"


@pytest.mark.parametrize("code", [
    "output.insertAdjacentHTML('beforeend', location.hash);",
    "const v=location.search; output.setAttribute('onclick',v);",
    "const v=document.URL; eval(v);",
])
def test_unsafe_html_attribute_or_javascript_sinks(code):
    r=review_evidence(code)
    assert r["decision"]["status"] == "CANDIDATE", r
    assert r["paths"][0]["defense"]["status"] == "NONE"


def test_local_overwrite_severs_flow():
    r=review_evidence("let x=location.hash; x='fixed'; output.innerHTML=x;")
    assert r["decision"]["status"] == "SAFE"
    assert r["source"]["observed"] == ["location.hash"]
    assert r["paths"][0]["flow"]["relation"] == "DISCONNECTED"


def test_verified_html_sanitization_needs_audited_import():
    code="import p from 'dompurify'; const x=location.hash; const y=p.sanitize(x); box.innerHTML=y;"
    assert review_evidence(code)["decision"]["status"] == "INCONCLUSIVE"
    r=review_evidence(code, trusted_modules=("dompurify",))
    assert r["decision"]["status"] == "SAFE", r
    assert r["paths"][0]["defense"]["status"] == "VERIFIED_CONTEXTUAL_SANITIZATION"


def test_html_sanitizer_does_not_prove_javascript_safety():
    code="import p from 'dompurify'; const y=p.sanitize(location.hash); eval(y);"
    r=review_evidence(code, trusted_modules=("dompurify",))
    assert r["decision"]["status"] == "CANDIDATE"
    assert r["paths"][0]["defense"]["status"] == "NONE"


@pytest.mark.parametrize("code", [
    "const x=notAuditedSanitize(location.hash); output.innerHTML=x;",
    "function render(x) { output.innerHTML=x; }",
    "output.innerHTML = ;",
    "const n=location.hash; output.setAttribute(key,n);",
    "const n=location.hash; unknown(n); output.innerHTML=n;",
    "const user=location.hash; noSupportedSink(user);",
])
def test_unsupported_flow_abstains_instead_of_inventing_proof(code):
    assert review_evidence(code)["decision"]["status"] == "INCONCLUSIVE"


def test_model_cannot_override_grounded_evidence():
    code="output.textContent = location.hash;"
    actual=review_evidence(code)
    fake={k:actual[k] for k in ("source", "flow", "sink", "defense", "decision")}
    fake["snippet_sha256"]=actual["snippet_sha256"]
    assert validate_advisory(fake,actual)["accepted"] is True
    fake["decision"]={**fake["decision"],"status":"CANDIDATE"}
    rejected=validate_advisory(fake,actual)
    assert rejected["accepted"] is False
    assert rejected["decision"]["status"] == "SAFE"
    fake["decision"]=actual["decision"]
    fake["snippet_sha256"]=hashlib.sha256(b"another snippet").hexdigest()
    assert validate_advisory(fake,actual)["reason"] == "snippet_hash_mismatch"


def test_system_review_includes_evidence_and_keeps_browser_authority():
    candidate=review("box.innerHTML = location.hash;")
    assert candidate.verdict == "POSSIBLE_XSS"
    assert candidate.evidence["decision"]["status"] == "CANDIDATE"
    assert candidate.confirmed is False
    safe=review("box.insertAdjacentText('beforeend',location.hash);")
    assert safe.verdict == "SAFE"
    assert safe.evidence["paths"][0]["defense"]["status"] == "SAFE_OUTPUT_API"
    assert safe.to_dict()["evidence"]["model_has_final_authority"] is False
