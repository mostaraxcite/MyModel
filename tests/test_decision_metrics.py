import copy
import pytest
from evaluation.decision_metrics import score_decisions,wilson95,compare_same_cases

def row(i,label,status):
    return {'id':str(i),'code':'fixture '+str(i),'label':label,'static_status':status,'family':'test'}

def test_abstention_and_untested_cases_remain_in_recall_denominator():
    result=score_decisions([row(0,'unsafe','CANDIDATE'),row(1,'unsafe','INCONCLUSIVE'),row(2,'unsafe','NOT_TESTED'),row(3,'unsafe','SAFE'),row(4,'safe','SAFE')])
    assert result['unsafe_candidate_recall']==0.25
    assert result['unsafe_candidate_miss_rate']==0.75
    assert result['unsafe_static_safe_rate']==0.25
    assert result['test_coverage']==0.8
    assert result['decision_coverage']==0.6
    assert result['model_promotion_allowed'] is False

def test_precision_and_false_positive_rate_use_different_denominators():
    rows=[row(0,'unsafe','CANDIDATE'),row(1,'safe','CANDIDATE'),row(2,'safe','SAFE'),row(3,'safe','SAFE'),row(4,'safe','INCONCLUSIVE')]
    r=score_decisions(rows)
    assert r['candidate_precision']==0.5
    assert r['safe_false_positive_rate']==0.25
    assert r['safe_abstention_rate']==0.25

def test_zero_alerts_and_missing_classes_do_not_become_perfect_scores():
    r=score_decisions([row(0,'safe','SAFE')])
    assert r['candidate_precision'] is None
    assert r['unsafe_candidate_recall'] is None
    assert r['point_gate_passed'] is False
    assert r['nominal_interval_gate_passed'] is False

def test_unadjudicated_alerts_do_not_silently_improve_precision():
    r=score_decisions([row(0,'unsafe','CANDIDATE'),row(1,'needs_review','CANDIDATE')])
    assert r['candidate_precision'] is None
    assert r['verified_alert_fraction']==0.5
    assert r['needs_review_overclaim_rate']==1

def test_twelve_perfect_unsafe_cases_do_not_prove_ninety_percent_population_recall():
    rows=[row(i,'unsafe','CANDIDATE') for i in range(12)]+[row(12+i,'safe','SAFE') for i in range(12)]
    r=score_decisions(rows,{'evaluation_kind':'fresh_synthetic'})
    assert r['point_gate_passed'] is True
    assert r['nominal_interval_gate_passed'] is False
    assert r['nominal_wilson95']['candidate_recall']['lower']==pytest.approx(0.757506,abs=1e-6)
    assert r['production_accuracy_established'] is False

def test_original_ten_of_twelve_uncertainty():
    ci=wilson95(10,12)
    assert ci['lower']==pytest.approx(0.551969,abs=1e-6)
    assert ci['upper']==pytest.approx(0.953035,abs=1e-6)

def test_more_independent_trials_narrow_only_nominal_interval():
    assert wilson95(0,100)['upper']<0.05
    assert wilson95(100,100)['lower']>0.9
    r=score_decisions([row(i,'unsafe','CANDIDATE') for i in range(100)]+[row(100+i,'safe','SAFE') for i in range(100)],{'evaluation_kind':'fresh_synthetic'})
    assert r['nominal_interval_gate_passed'] is True
    assert r['model_promotion_allowed'] is False

def test_repeated_source_is_disclosed_instead_of_presented_as_independent_samples():
    a=row(0,'unsafe','CANDIDATE');b=row(1,'unsafe','CANDIDATE');b['code']=a['code']
    r=score_decisions([a,b]);assert r['unique_code_hashes']==1
    assert list(r['repeated_code_hashes'].values())==[2]

@pytest.mark.parametrize('rows',[[],[row(0,'unsafe','BROKEN')],[row(0,'bad','SAFE')],[row(0,'safe','SAFE'),row(0,'safe','SAFE')]])
def test_invalid_cases_are_not_dropped(rows):
    with pytest.raises(ValueError):score_decisions(rows)

def test_comparison_requires_identical_frozen_partition_and_labels():
    a={'cases_sha256':'same','results':[row(0,'unsafe','INCONCLUSIVE')]}
    b=copy.deepcopy(a);b['results'][0]['static_status']='CANDIDATE'
    assert compare_same_cases(a,b)['after']['unsafe_candidate_recall']==1
    b['cases_sha256']='different'
    with pytest.raises(ValueError):compare_same_cases(a,b)
    b['cases_sha256']='same';b['results'][0]['label']='safe'
    with pytest.raises(ValueError):compare_same_cases(a,b)
