import hashlib
import pytest
from evaluation.external_conditional_v11 import load_frozen, fixture_script


def test_frozen_sources_dependency_and_original_fragments_verify():
    cases, manifest = load_frozen()
    assert len(cases) == 24
    assert sum(c['label']=='unsafe' for c in cases) == 15
    assert sum(c['label']=='safe' for c in cases) == 9
    assert manifest['independence_verified'] is False
    assert manifest['labels_independently_reviewed'] is False
    assert all(c['label_review']['independent_review'] is False for c in cases)


def test_static_inputs_never_contain_harness_payload_or_dom_setup():
    cases, _ = load_frozen()
    for c in cases:
        assert '__auditProof' not in c['code']
        assert 'const payload=' not in c['code']
        assert hashlib.sha256(c['original_fragment'].encode()).hexdigest() == c['fragment_sha256']
        assert c['original_fragment'] in fixture_script(c)


def test_svg_cases_keep_complete_numeric_validation_callback():
    cases, _ = load_frozen()
    svg = [c for c in cases if c['fixture_kind']=='svg-callback']
    assert len(svg) == 2
    assert all('p.length === 4' in c['code'] and 'p.map' in c['code'] for c in svg)
    assert all(c['lineage_group']=='prism-previewers' for c in svg)
