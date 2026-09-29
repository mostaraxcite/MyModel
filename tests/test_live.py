"""Fast model-free/network-free tests for the live-assessment subsystem."""
from live.scope import Scope, Enforcer
from live.probes import plan, _signature
from live.sanitizer_id import verify_identity
from live.findings import correlate, CONFIRMED, LIKELY, NOT_VULNERABLE


def test_scope_blocks_out_of_scope_and_redirect():
    s = Scope(base_url="http://127.0.0.1:8099/", allowed_prefixes=["/"])
    assert s.in_scope("http://127.0.0.1:8099/x")[0]
    assert not s.in_scope("http://evil.example/x")[0]
    e = Enforcer(s)
    e.note_request("http://127.0.0.1:8099/a", final_url="http://evil.example/r", status=302)
    assert any("redirect_out_of_scope" in b.get("reason", "") for b in e.blocked_log)


def test_sanitizer_nearmiss_never_inherits_safety():
    assert verify_identity("DOMPurify.sanitize").status == "VERIFIED_SAFE"
    v = verify_identity("DOMPvrify.sanitize")
    assert v.status == "UNKNOWN" and v.nearest_known == "DOMPurify.sanitize"
    assert verify_identity("totallyFake").status == "UNKNOWN"


def test_probe_marker_first_and_signature():
    cand = {"url": "http://127.0.0.1/x", "param": "q", "context": "html_text", "delivery": "query"}
    m = plan(cand, "marker")
    assert len(m) == 1 and m[0].kind == "marker" and "<" not in m[0].payload
    ex = plan(cand, "exec")
    assert ex and all(e.kind == "exec" for e in ex)
    assert _signature("<img src=x onerror=1>").startswith("<img")


def test_finding_confirmed_only_from_execution():
    cand = {"url": "u", "param": "q", "context": "html_text"}
    marker_ev = {"reflected_html": True}
    # executed -> CONFIRMED
    f = correlate(cand, marker_ev, [{"executed": True, "raw_reflected": True}], None, "F1")
    assert f.status == CONFIRMED
    # raw reflected but not executed -> LIKELY (never CONFIRMED without execution)
    f2 = correlate(cand, marker_ev, [{"executed": False, "raw_reflected": True}], None, "F2")
    assert f2.status == LIKELY
    # reflected but encoded (no raw) -> NOT_VULNERABLE
    f3 = correlate(cand, marker_ev, [{"executed": False, "raw_reflected": False}], None, "F3")
    assert f3.status == NOT_VULNERABLE


def test_verified_safe_sanitizer_downgrades_but_unknown_does_not():
    cand = {"url": "u", "param": "q", "context": "html_text"}
    marker_ev = {"reflected_html": True}
    vs = verify_identity("DOMPurify.sanitize")
    f = correlate(cand, marker_ev, [{"executed": False, "raw_reflected": True}], vs, "F")
    assert f.status == NOT_VULNERABLE      # verified-safe sanitizer present
    uk = verify_identity("DOMPvrify.sanitize")
    f2 = correlate(cand, marker_ev, [{"executed": False, "raw_reflected": True}], uk, "F")
    assert f2.status == LIKELY             # near-miss must NOT grant safety


def test_pilot_refuses_without_acknowledgement():
    from live.pilot import PilotAuthorization, authorize
    a = PilotAuthorization(target="http://192.0.2.9/", operator_identity="op",
                           assessment_id="x", authorization_acknowledged=False)
    try:
        authorize(a, authorized_external=True)
        assert False
    except SystemExit:
        pass


def test_pilot_refuses_external_without_flag():
    from live.pilot import PilotAuthorization, authorize
    a = PilotAuthorization(target="http://192.0.2.9/", operator_identity="op",
                           assessment_id="x", authorization_acknowledged=True)
    try:
        authorize(a, authorized_external=False)
        assert False
    except SystemExit:
        pass


def test_js_code_probe_is_nondestructive():
    from live.probes import js_code_probe
    p = js_code_probe("query")
    assert p.kind == "exec" and "window.__X" in p.payload and "<" not in p.payload


def test_classify_quoted_vs_unquoted():
    from live.pipeline import classify_context
    q = classify_context('<input value="MARK', "MARK")
    u = classify_context('<div class=MARK', "MARK")
    assert q == "html_attr" and u == "html_attr_unquoted"


def test_monitoring_uses_summary_metadata_only(tmp_path):
    import json
    from live.monitoring import build, collect

    assessment = tmp_path / "assessments" / "pilot-1"
    assessment.mkdir(parents=True)
    (assessment / "summary.json").write_text(json.dumps({
        "target": "https://example.test/app/", "requests_made": 12,
        "candidates_tested": 3, "confirmed": 1, "likely": 1,
        "inconclusive": 1, "not_vulnerable": 0, "out_of_scope_blocked": 2,
    }))
    (assessment / "authorization.json").write_text(json.dumps({
        "assessment_id": "PILOT-1", "operator_identity": "reviewer@example.test",
        "authorization_acknowledged": True,
    }))
    (assessment / "HUMAN_REVIEW_REQUIRED.txt").write_text("required")
    # Sensitive evidence must not be parsed or copied into the dashboard.
    (assessment / "browser_evidence.jsonl").write_text('{"secret":"do-not-copy"}\n')

    rows = collect(tmp_path / "assessments")
    assert rows[0]["authorized_pilot"] and rows[0]["human_review_recorded"]
    snapshot = build(tmp_path / "assessments", tmp_path / "monitoring")
    assert snapshot["metrics"]["inconclusive_rate"] == 1 / 3
    dashboard = (tmp_path / "monitoring" / "dashboard.html").read_text()
    assert "PILOT-1" in dashboard and "do-not-copy" not in dashboard


def test_scope_normalizes_paths_before_exclusion():
    s = Scope(base_url="http://127.0.0.1:8099/app/", excluded_paths=["/app/admin"])
    assert not s.in_scope("http://127.0.0.1:8099/app/admin/delete")[0]
    assert not s.in_scope("http://127.0.0.1:8099/app/x/../admin/delete")[0]
    assert not s.in_scope("http://127.0.0.1:8099/app/%61dmin/delete")[0]
    assert not s.in_scope("http://127.0.0.1:8099/app/%2561dmin")[0]
    assert not s.in_scope("http://127.0.0.1:8099/app/..%2fadmin")[0]
    assert not s.in_scope("http://127.0.0.1:8099/app/../../etc")[0]
    assert s.in_scope("http://127.0.0.1:8099/app/x/../ok")[0]


def test_scope_prefix_is_segment_aware():
    s = Scope(base_url="http://127.0.0.1:8099/app")
    assert s.in_scope("http://127.0.0.1:8099/app")[0]
    assert s.in_scope("http://127.0.0.1:8099/app/x")[0]
    assert not s.in_scope("http://127.0.0.1:8099/application")[0]


def test_scope_refuses_external_hosts_without_authorization():
    s = Scope(base_url="http://127.0.0.1:8099/", allowed_subdomains=["example.com"])
    assert not s.in_scope("https://www.example.com/")[0]
    s2 = Scope(base_url="http://127.0.0.1:8099/", allowed_subdomains=["example.com"],
               authorized_external=True)
    assert s2.in_scope("https://www.example.com/")[0]


def test_enforcer_logs_max_depth():
    e = Enforcer(Scope(base_url="http://127.0.0.1:8099/", max_depth=1))
    assert not e.check("http://127.0.0.1:8099/x", depth=2)[0]
    assert e.blocked_log[-1]["reason"] == "max_depth"


def test_pilot_loopback_target_with_external_host_is_external():
    from live.pilot import PilotAuthorization, authorize
    a = PilotAuthorization(target="http://127.0.0.1/", operator_identity="op", assessment_id="x",
                           authorization_acknowledged=True, allowed_subdomains=["example.com"])
    try:
        authorize(a, authorized_external=False)
        assert False
    except SystemExit:
        pass


def test_pilot_enforces_test_classes():
    from live.pilot import PilotAuthorization, authorize
    base = dict(target="http://127.0.0.1/", operator_identity="op", assessment_id="x",
                authorization_acknowledged=True)
    assert authorize(PilotAuthorization(**base), False).allowed_test_classes == ["reflected", "dom"]
    try:
        authorize(PilotAuthorization(**base, allowed_test_classes=["reflected", "stored"]), False)
        assert False
    except SystemExit:
        pass
    s = authorize(PilotAuthorization(**base, stored_xss_permitted=True), False)
    assert s.allows("stored") and not s.allows("post")


def test_executor_refuses_unauthorized_test_class():
    from live.executor import execute
    e = Enforcer(Scope(base_url="http://127.0.0.1:8099/"))
    cand = {"url": "http://127.0.0.1:8099/f", "param": "q", "context": "html_text", "delivery": "form"}
    probe = plan(cand, "marker")[0]
    r = execute(cand, probe, e)
    assert r["blocked"] and r["reason"] == "test_class_not_authorized:post"
    assert e.requests_made == 0


def test_stored_requires_opt_in():
    from live.stored import assess_stored
    e = Enforcer(Scope(base_url="http://127.0.0.1:8099/"))
    r = assess_stored("http://127.0.0.1:8099/s", "http://127.0.0.1:8099/v", e, "S")
    assert r["status"] == "INCONCLUSIVE" and e.requests_made == 0


def test_acceptance_gate_is_not_a_committed_file():
    import subprocess
    from live.assess import ACCEPT_GATE, ROOT
    rel = ACCEPT_GATE.relative_to(ROOT)
    assert ACCEPT_GATE.is_absolute()
    tracked = subprocess.run(["git", "ls-files", "--error-unmatch", str(rel)], cwd=ROOT,
                             capture_output=True).returncode == 0
    ignored = subprocess.run(["git", "check-ignore", "-q", str(rel)], cwd=ROOT).returncode == 0
    assert not tracked and ignored
