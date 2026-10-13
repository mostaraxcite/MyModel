from evaluation.holdout_protocol import audit_holdout

def case(id=0,code='panel.innerHTML=window.name;',label='unsafe'):
    # Metadata examples only, not a claimed external repository or benchmark.
    return {'id':str(id),'code':code,'label':label,'family':'example',
            'provenance':{'repository':'example-source','revision':'a'*40,'path':'example.js'},
            'label_review':{'reviewer':'independent-example-reviewer','evidence_ref':'example-evidence','semantic_reason':'example semantic review','safe_by_nonexecution_only':False},
            'browser':{'executed':label=='unsafe'}}

def manifest():
    return {'evaluation_kind':'external_holdout','exposure_status':'unseen','frozen_before_engine_changes':True,'development_inventory_complete':True,'sampling_plan_ref':'example-plan','engine_authors':['example-author']}

def test_synthetic_cases_cannot_be_relabelled_external_without_required_protocol():
    r=audit_holdout([case()],[],{'evaluation_kind':'fresh_synthetic'})
    assert r['metadata_checks_passed'] is False
    assert 'dataset_is_not_external_holdout' in r['reasons']
    assert 'insufficient_cases_per_class' in r['reasons']

def test_known_code_and_repository_overlap_reject_holdout():
    development=[case()];new=case(1,'panel.innerHTML = window.name;')
    r=audit_holdout([new],development,manifest(),min_per_class=0,min_repositories=0,min_families=0)
    assert 'development_code_overlap' in r['reasons']
    assert 'development_repository_overlap' in r['reasons']

def test_negative_execution_alone_is_not_safe_ground_truth():
    c=case(label='safe');c['label_review']['safe_by_nonexecution_only']=True
    r=audit_holdout([c],[],manifest(),min_per_class=0,min_repositories=0,min_families=0)
    assert 'negative_browser_result_is_not_safe_ground_truth' in r['reasons']

def test_complete_metadata_still_does_not_certify_independence_or_promote():
    c=case();r=audit_holdout([c],[],manifest(),min_per_class=0,min_repositories=1,min_families=1)
    assert r['metadata_checks_passed'] is True
    assert r['independence_verified'] is False
    assert r['model_promotion_allowed'] is False

def test_author_review_and_absent_positive_proof_reject_protocol():
    c=case();c['label_review']['reviewer']='example-author';c['browser']['executed']=False
    r=audit_holdout([c],[],manifest(),min_per_class=0,min_repositories=0,min_families=0)
    assert 'reviewer_is_engine_author' in r['reasons']
    assert 'positive_execution_evidence_missing' in r['reasons']
