"""Browser-level scope and safety tests against a throwaway loopback server.

The scope only allows 127.0.0.1; `localhost` on the same port stands in for an out-of-scope host,
so the test never touches the network yet can observe whether the browser reached it.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from live.executor import execute
from live.probes import Probe
from live.scope import Enforcer, Scope
from verification.browser_oracle import run_probe_on_url


def _browser_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            p.chromium.launch(headless=True).close()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _browser_available(), reason="headless Chromium unavailable")


class _App(BaseHTTPRequestHandler):
    hits: list[tuple[str, str, str]] = []   # (host, method, path)
    port = 0

    def log_message(self, *a):
        pass

    def _send(self, body: str, status: int = 200, headers: dict | None = None):
        data = body.encode()
        self.send_response(status)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("content-length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        self.hits.append((self.headers.get("host", "").split(":")[0], "GET", u.path))
        q = parse_qs(u.query).get("q", [""])[0]
        if u.path == "/redirect-out":
            return self._send("", 302, {"location": f"http://localhost:{self.port}/secret"})
        if u.path == "/redirect-in":
            return self._send("", 302, {"location": f"/echo?q={q}"})
        if u.path == "/echo":
            return self._send(f"<div>{q}</div><img src='http://localhost:{self.port}/leak.png'>")
        if u.path == "/slow":
            import time
            time.sleep(2)
            return self._send("late")
        if u.path == "/danger":
            return self._send(
                f"<div>{q}</div>"
                "<form action=/delete method=post><button id=del>delete</button></form>"
                "<a id=other href='/delete-link'>other</a>")
        return self._send("ok")

    def do_POST(self):
        u = urlparse(self.path)
        self.hits.append((self.headers.get("host", "").split(":")[0], "POST", u.path))
        body = self.rfile.read(int(self.headers.get("content-length") or 0)).decode()
        q = parse_qs(body).get("q", [""])[0]
        if u.path == "/form":
            return self._send(f"<div>{q}</div>")
        return self._send("posted")


@pytest.fixture()
def app():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _App)
    _App.port = srv.server_address[1]
    _App.hits = []
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{_App.port}"
    srv.shutdown()


def _scope(base):
    return Scope(base_url=base + "/", allowed_prefixes=["/"], rate_limit_rps=100)


def test_out_of_scope_redirect_and_subresource_are_never_requested(app):
    s = _scope(app)
    blocked = []
    ev = run_probe_on_url(app + "/redirect-out", "m", in_scope=s.in_scope)
    blocked += ev["scope_blocked"]
    ev2 = run_probe_on_url(app + "/echo?q=hi", "hi", in_scope=s.in_scope)
    blocked += ev2["scope_blocked"]
    assert all(host == "127.0.0.1" for host, _, _ in _App.hits), _App.hits
    reasons = {b["url"].split("/")[-1] for b in blocked}
    assert {"secret", "leak.png"} <= reasons
    assert ev2["reflected_html"]


def test_in_scope_redirect_is_followed(app):
    s = _scope(app)
    ev = run_probe_on_url(app + "/redirect-in?q=abc123", "abc123", in_scope=s.in_scope)
    assert ev["final_url"].startswith(app + "/echo") and ev["reflected_html"]


def test_navigation_timeout_is_reported_not_raised(app):
    ev = run_probe_on_url(app + "/slow", "m", timeout_ms=300, in_scope=_scope(app).in_scope)
    assert ev["executed"] is False and ev["error"].startswith("navigation_failed")


def test_interactions_never_submit_or_click_unrelated_controls(app):
    s = _scope(app)
    ev = run_probe_on_url(app + "/danger?q=x", "zzmarker", in_scope=s.in_scope,
                          interactions=["hover", "focus", "click", "hashnav", "submit"])
    assert "submit" not in ev["interactions_performed"]
    touched = {p for _, _, p in _App.hits}
    assert "/delete" not in touched and "/delete-link" not in touched


def test_post_form_candidates_are_posted_when_authorized(app):
    enf = Enforcer(Scope(base_url=app + "/", allowed_prefixes=["/"], rate_limit_rps=100,
                         allowed_test_classes=["reflected", "dom", "post"]))
    cand = {"url": app + "/form", "param": "q", "delivery": "form", "context": "html_text"}
    probe = Probe(marker="xzpost01", kind="marker", context="html_text", payload="xzpost01",
                  delivery="form")
    ev = execute(cand, probe, enf)
    assert not ev["blocked"] and ev["reflected_html"]
    assert ("127.0.0.1", "POST", "/form") in _App.hits
