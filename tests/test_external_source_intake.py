import pytest
from evaluation.external_source_intake import prepare, digest


def source(code):
    return {'id': 'fixture', 'repository': 'example/source', 'revision': 'a'*40,
            'path': 'test.js', 'code': code}


def test_upstream_annotation_never_becomes_a_safe_or_unsafe_label():
    result = prepare([source('// ok: rule\nnode.innerHTML = input;')], 'b'*40)
    assert len(result['review_candidates']) == 1
    assert result['review_candidates'][0]['label'] == 'needs_review'
    assert result['accuracy'] is None
    assert result['model_evaluated'] is False
    assert result['independence_verified'] is False


def test_reads_are_not_output_sink_review_locations():
    result = prepare([source('const value = node.innerHTML;')], 'b'*40)
    assert result['review_candidates'] == []


def test_context_offsets_preserve_utf8_original_function():
    code = 'const name="عربي";function render(x){node.innerHTML=x;}'
    result = prepare([source(code)], 'b'*40)
    row = result['review_candidates'][0]
    raw = code.encode()
    context = raw[row['context_start_byte']:row['context_end_byte']].decode()
    assert context == 'function render(x){node.innerHTML=x;}'
    assert digest(context) == row['context_sha256']


def test_tampered_content_and_duplicate_sources_fail():
    item = source('node.innerHTML=input;')
    with pytest.raises(ValueError, match='Duplicate'):
        prepare([item, item], 'b'*40)
    item['content_sha256'] = '0'*64
    with pytest.raises(ValueError, match='hash'):
        prepare([item], 'b'*40)


def test_moving_branches_cannot_masquerade_as_immutable_revisions():
    with pytest.raises(ValueError, match='Engine revision'):
        prepare([source('node.innerHTML=input;')], 'main')
    item = source('node.innerHTML=input;')
    item['revision'] = 'main'
    with pytest.raises(ValueError, match='Source revision'):
        prepare([item], 'b'*40)
