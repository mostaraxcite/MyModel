"""End-to-end authority tests: static candidate -> explicitly scoped browser oracle."""
from __future__ import annotations

import html
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from live.scope import Enforcer, Scope
from xss_specialist.system import review


def _browser_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            p.chromium.launch(headless=True).close()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _browser_available(), reason="headless Chromium unavailable")


class _Target(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, body: str):
        data=body.encode()
        self.send_response(200)
        self.send_header("content-type","text/html; charset=utf-8")
        self.send_header("content-length",str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed=urlparse(self.path)
        value=parse_qs(parsed.query).get("q",[""])[0]
        if parsed.path == "/raw":
            return self._send(f"<main>{value}</main>")
        if parsed.path == "/encoded":
            return self._send(f"<main>{html.escape(value)}</main>")
        return self._send("ok")


@pytest.fixture()
def target():
    server=ThreadingHTTPServer(("127.0.0.1",0),_Target)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    base=f"http://127.0.0.1:{server.server_address[1]}"
    try:
        yield base
    finally:
        server.shutdown()


def enforcer(base: str) -> Enforcer:
    return Enforcer(Scope(
        base_url=base+"/",
        allowed_prefixes=["/"],
        max_requests=50,
        rate_limit_rps=100,
        allowed_test_classes=["reflected","dom"],
    ))


def test_only_observed_browser_execution_can_confirm_xss(target):
    result=review(
        "box.innerHTML = location.hash;",
        live_candidate={
            "url":target+"/raw?q=seed",
            "param":"q",
            "method":"GET",
            "context":"unknown",
            "delivery":"query",
        },
        enforcer=enforcer(target),
        finding_id="SYS-CONFIRM",
    )
    assert result.static_verdict == "CANDIDATE"
    assert result.verdict == "XSS"
    assert result.confirmed is True
    assert result.confirmation_status == "CONFIRMED_BROWSER_EXECUTION"
    assert result.browser_evidence["status"] == "CONFIRMED"
    assert result.browser_evidence["browser_result"] == "executed"


def test_browser_non_execution_does_not_turn_candidate_safe(target):
    result=review(
        "box.innerHTML = location.hash;",
        live_candidate={
            "url":target+"/encoded?q=seed",
            "param":"q",
            "method":"GET",
            "context":"unknown",
            "delivery":"query",
        },
        enforcer=enforcer(target),
        finding_id="SYS-NOEXEC",
    )
    assert result.static_verdict == "CANDIDATE"
    assert result.verdict == "POSSIBLE_XSS"
    assert result.confirmed is False
    assert result.requires_browser is True
    assert result.confirmation_status.startswith("UNCONFIRMED_")
    assert result.browser_evidence["browser_result"] == "not-executed"
