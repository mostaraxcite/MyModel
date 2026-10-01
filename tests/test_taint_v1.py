import pytest

from xss_specialist.taint import analyze
from xss_specialist.taint_evaluation import audit_splits, score
from training.legacy_policy import require_supported_training


@pytest.mark.parametrize('code', [
    "box.innerHTML = 'constant';",
    "const x = 'constant'; const y=x; box.innerHTML=y;",
    "const x=location.hash; box.textContent=x;",
    "box.innerHTML = `constant`;",
    "box.innerHTML='innerHTML DOMPurify.sanitize location.hash';",
])
def test_supported_safe_sinks(code):
    assert analyze(code)['verdict'] == 'SAFE'


@pytest.mark.parametrize('source', ['location.hash','window.location.search','document.URL','req.query.name'])
def test_tainted_alias_flow(source):
    result = analyze(f'const x={source}; const y=x; box.innerHTML=y;')
    assert result['verdict'] == 'CANDIDATE'
    assert result['sinks'][0]['sources'] == [source]
    assert result['sinks'][0]['flow'] == [source, 'x', 'y', 'box.innerHTML']
    assert result['confirmed'] is False


def test_overwrite_clears_taint():
    assert analyze("let x=location.hash; x='fixed'; box.innerHTML=x;")['verdict'] == 'SAFE'


def test_branch_merge_preserves_taint():
    assert analyze("let x='fixed'; if(flag){x=location.hash;} box.innerHTML=x;")['verdict'] == 'CANDIDATE'


def test_branch_both_safe():
    assert analyze("let x=location.hash; if(flag){x='a';}else{x='b';}box.innerHTML=x;")['verdict'] == 'SAFE'


@pytest.mark.parametrize('code', [
    'const x=unknown(); box.innerHTML=x;',
    'const x=DOMPurify.sanitize(location.hash); box.innerHTML=x;',
    'const x=DOMPvrify.sanitize(location.hash); box.innerHTML=x;',
    'function f(x){box.innerHTML=x;}',
    '<div dangerouslySetInnerHTML={{__html: data}} />',
    'box.innerHTML = ;',
    "let x='safe'; for(let i=0;i<1;i++){x=location.hash;} box.innerHTML=x;",
    "let x='safe'; const obj={get v(){x=location.hash}}; obj.v; box.innerHTML=x;",
    "let x=location.hash; flag && (x='safe'); box.innerHTML=x;",
    "const location={hash:'fixed'}; box.innerHTML=location.hash;",
    'const y=DOMPurify.sanitize(location.hash, config); box.innerHTML=y;',
])
def test_unresolved_never_safe(code):
    assert analyze(code)['verdict'] == 'INCONCLUSIVE'


def test_verified_import_requires_explicit_policy():
    code="import purify from 'dompurify'; const x=location.hash; const y=purify.sanitize(x); box.innerHTML=y;"
    assert analyze(code)['verdict'] == 'INCONCLUSIVE'
    result=analyze(code, trusted_modules=('dompurify',))
    assert result['verdict']=='SAFE'
    assert result['sinks'][0]['sanitizer']=='dompurify:default-html'
    assert result['sinks'][0]['sources']==['location.hash']


def test_sanitizer_context_mismatch():
    result=analyze("import p from 'dompurify'; const y=p.sanitize(location.hash); eval(y);", trusted_modules=('dompurify',))
    assert result['verdict']=='CANDIDATE'
    assert result['sinks'][0]['sanitizer_compatible'] is False


def test_sanitizer_composition_invalidates_guarantee():
    result=analyze("import p from 'dompurify'; const y=p.sanitize(location.hash); box.innerHTML='<span>'+y;", trusted_modules=('dompurify',))
    assert result['verdict']=='CANDIDATE'


@pytest.mark.parametrize('mutation', ['p=fake;', 'p.sanitize=fake;', 'configure();'])
def test_sanitizer_identity_mutation(mutation):
    result=analyze(f"import p from 'dompurify'; {mutation} const y=p.sanitize(location.hash); box.innerHTML=y;", trusted_modules=('dompurify',))
    assert result['verdict']=='INCONCLUSIVE'


def test_model_safe_never_skips_taint():
    assert analyze('box.innerHTML=location.hash;', risk_scores={'SAFE':1.0})['verdict']=='CANDIDATE'


def test_model_xss_never_changes_safe():
    result=analyze("box.innerHTML='fixed';", risk_scores={'XSS':1.0})
    assert result['verdict']=='SAFE'
    assert result['review_priority']=='high'


def row(name, code="box.innerHTML='fixed';", label='SAFE'):
    return {'code':code, 'label':label, 'provenance':{k:name for k in ('repository','framework','template','generator')}}


def test_disjoint_audit():
    assert audit_splits({'train':[row('a')], 'dev':[row('b',"box.innerHTML='other';")]})['passed']


@pytest.mark.parametrize('key', ['repository','framework','template','generator'])
def test_overlap_rejected(key):
    a,b=row('a'),row('b',"box.innerHTML='other';")
    b['provenance'][key]='a'
    with pytest.raises(ValueError, match='overlap'):
        audit_splits({'train':[a], 'dev':[b]})


def test_exact_code_contamination_rejected():
    with pytest.raises(ValueError, match='code_sha256'):
        audit_splits({'train':[row('a')], 'dev':[row('b')]})


def test_missing_metadata_rejected():
    a=row('a'); del a['provenance']['generator']
    with pytest.raises(ValueError, match='missing'):
        audit_splits({'train':[a]})


def test_abstention_cannot_pass_gate():
    result=score([row('a','box.innerHTML=unknown();'),row('b','function f(x){box.innerHTML=x;}', 'XSS')])
    assert result['strict_xss_fnr']==1
    assert result['safe_review_rate']==1
    assert result['decision_coverage']==0
    assert result['thresholds_met'] is False
    assert result['promotion_allowed'] is False


def test_missing_class_cannot_pass_gate():
    assert score([row('a')])['thresholds_met'] is False


def test_legacy_training_stops():
    with pytest.raises(SystemExit, match='retired'):
        require_supported_training()
