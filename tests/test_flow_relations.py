import json
from pathlib import Path

import pytest

from training.train_flow_relations import PreflightError, fit_model, train
from xss_specialist.flow_relations import LABELS, FlowRelationAdvisor, advise_review, audit_relation_splits, relation_text
from xss_specialist.taint import analyze


def record(name='a', label='CONNECTED', group='train'):
    return {'id':name, 'task':'FLOW_RELATION', 'source_expression':'input_'+name,
            'sink_expression':'output_'+name, 'flow_excerpt':f'assign {name} {label}',
            'label':label, 'verification':{'status':'REVIEWED', 'reviewer':'test fixture',
            'rationale':'unit-test schema assertion; not research data', 'reference':'tests/test_flow_relations.py'},
            'provenance':{k:group for k in ('repository','framework','template','generator')}}


def test_whole_snippet_labels_refused():
    with pytest.raises(ValueError, match='FLOW_RELATION'):
        relation_text({'code':'snippet','label':'XSS'})


def test_independent_relation_split():
    assert audit_relation_splits({'train':[record()], 'dev':[record('b',group='dev')]})['passed']


@pytest.mark.parametrize('key', ['repository','framework','template','generator'])
def test_overlap_fails(key):
    a,b=record(),record('b',group='dev')
    b['provenance'][key]='train'
    with pytest.raises(ValueError, match='overlap'):
        audit_relation_splits({'train':[a], 'dev':[b]})


@pytest.mark.parametrize('key', ['reviewer','rationale','reference','status'])
def test_unverified_label_fails(key):
    a=record(); a['verification'].pop(key)
    with pytest.raises(ValueError, match='reviewed'):
        audit_relation_splits({'train':[a]})


def test_duplicate_relation_fails():
    with pytest.raises(ValueError, match='duplicate'):
        audit_relation_splits({'train':[record(),record()]})


def test_review_cannot_be_whole_file():
    a=record(); a['flow_excerpt']='x'*4097
    with pytest.raises(ValueError, match='4096'):
        relation_text(a)


def test_insufficient_data_creates_no_weights(tmp_path):
    a,b=tmp_path/'train.jsonl',tmp_path/'dev.jsonl'
    a.write_text(json.dumps(record())+'\n')
    b.write_text(json.dumps(record('b',group='dev'))+'\n')
    with pytest.raises(PreflightError, match='20'):
        train(a,b,tmp_path/'candidate')
    assert not (tmp_path/'candidate').exists()


def test_fit_serialization_parity(tmp_path):
    # Numerical fitting test only: deliberately tiny artificial schema fixtures.
    # This does not create or promote a research checkpoint.
    rows=[record(f'{label}{i}',label) for label in LABELS for i in range(3)]
    artifact,metrics=fit_model(rows,rows)
    path=tmp_path/'model.json'; path.write_text(json.dumps(artifact))
    model=FlowRelationAdvisor(path)
    for row in rows:
        advice=model.predict(row)
        assert advice['relation']==row['label']
        assert sum(advice['probabilities'].values())==pytest.approx(1)
        assert advice['advisory_only'] is True
        assert advice['confirmed'] is False
    assert metrics['promotion_allowed'] is False
    assert metrics['external_evaluated'] is False


@pytest.mark.parametrize('verdict,code', [('CANDIDATE','box.innerHTML=location.hash;'),
    ('SAFE',"box.innerHTML='fixed';"), ('INCONCLUSIVE','box.innerHTML=unknown();')])
@pytest.mark.parametrize('relation', LABELS)
def test_advice_cannot_override_static_result(verdict,code,relation):
    original=analyze(code)
    updated=advise_review(original,{'relation':relation})
    for key in ('verdict','confirmed','requires_oracle','sinks','limitations'):
        assert updated[key]==original[key]
    assert updated['verdict']==verdict


def test_authoritative_model_artifact_refused(tmp_path):
    path=tmp_path/'model.json'
    path.write_text(json.dumps({'schema':'xss-flow-relation-v1','final_judge':True}))
    with pytest.raises(ValueError, match='authoritative'):
        FlowRelationAdvisor(path)
