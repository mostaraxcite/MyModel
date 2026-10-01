from xss_specialist.semantic_oracle import classify_source, classify_sink, classify_defense


def test_real_server_and_framework_sources():
    assert classify_source("req.body.preTax")["label"] == "SERVER"
    assert classify_source("req.params.uid")["label"] == "SERVER"
    assert classify_source("_ctx.foo")["label"] == "FRAMEWORK"


def test_real_output_sinks():
    assert classify_sink("res.send('requested ' + req.params.sub)")["label"] == "DANGEROUS_HTML"
    assert classify_sink("return res.redirect(req.query.url)")["label"] == "DANGEROUS_URL"
    assert classify_sink("this.textContent = value")["label"] == "SAFE_OUTPUT"
    assert classify_sink('<div v-html="foo"/>')["label"] == "DANGEROUS_HTML"
    assert classify_sink('<div v-text="foo"/>')["label"] == "SAFE_OUTPUT"


def test_real_defense_semantics():
    assert classify_defense("escapeHtml(req.params.uid)")["label"] == "CONTEXTUAL_ENCODING"
    assert classify_defense('v-text="foo"')["label"] == "FRAMEWORK_ESCAPING"
    # Angular bypass APIs explicitly disable sanitization; do not mislabel them as protection.
    assert classify_defense("sanitizer.bypassSecurityTrustHtml(value)")["label"] == "OTHER"


def test_additional_framework_security_apis():
    assert classify_sink("render(unsafeHTML(content))")["label"] == "DANGEROUS_HTML"
    assert classify_sink('x-html="content"')["label"] == "DANGEROUS_HTML"
    assert classify_sink('x-text="content"')["label"] == "SAFE_OUTPUT"
    assert classify_defense("Handlebars.Utils.escapeExpression(value)")["label"] == "CONTEXTUAL_ENCODING"
    assert classify_defense('x-text="content"')["label"] == "FRAMEWORK_ESCAPING"
