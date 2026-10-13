"""Separate discovery, false alerts, abstention and sampling uncertainty.

These are rates on supplied reviewed labels, never an automatic production
accuracy claim. Wilson intervals assume independent binomial observations;
synthetic/selected/correlated snippets do not satisfy that assumption merely
because the interval is printed. Non-execution is not a safe ground truth.
"""
from collections import Counter
import hashlib
import math

LABELS={'unsafe','safe','needs_review'}
STATUSES={'CANDIDATE','SAFE','INCONCLUSIVE','NOT_TESTED'}

def rate(k,n):
    return k/n if n else None

def wilson95(k,n):
    if n==0:return None
    if not (0<=k<=n):raise ValueError('Invalid binomial counts')
    z=1.959963984540054
    p=k/n;divisor=1+z*z/n
    center=(p+z*z/(2*n))/divisor
    radius=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/divisor
    return {'lower':max(0.0,center-radius),'upper':min(1.0,center+radius),
            'successes':k,'trials':n,'confidence':0.95,'method':'Wilson',
            'interpretation':'nominal iid-binomial interval; not proof of external validity'}

def score_decisions(rows, manifest=None):
    if not rows:raise ValueError('Empty evaluation')
    seen=set();code_hashes=Counter();families=Counter()
    matrix={label:{status:0 for status in sorted(STATUSES)} for label in sorted(LABELS)}
    for row in rows:
        identity=row.get('id')
        if not isinstance(identity,str) or not identity or identity in seen:
            raise ValueError('Missing or duplicate case id')
        seen.add(identity)
        label=row.get('label');status=row.get('static_status')
        if not isinstance(label,str) or not isinstance(status,str) or label not in LABELS or status not in STATUSES:
            raise ValueError('Invalid label or static status')
        code=row.get('code')
        if not isinstance(code,str):raise ValueError('Missing source snippet')
        matrix[label][status]+=1
        code_hashes[hashlib.sha256(code.encode()).hexdigest()]+=1
        family=row.get('family','unassigned')
        if not isinstance(family,str):raise ValueError('Invalid case family')
        families[family]+=1
    unsafe=sum(matrix['unsafe'].values());safe=sum(matrix['safe'].values());n=len(rows)
    tp=matrix['unsafe']['CANDIDATE'];fp=matrix['safe']['CANDIDATE']
    review_alerts=matrix['needs_review']['CANDIDATE']
    false_safe=matrix['unsafe']['SAFE']
    untested=sum(m['NOT_TESTED'] for m in matrix.values())
    unresolved=sum(m['INCONCLUSIVE'] for m in matrix.values())
    point_recall=rate(tp,unsafe);point_fpr=rate(fp,safe)
    gate=(manifest or {}).get('gate',{})
    point_gate_passed=(point_recall is not None and point_fpr is not None
        and point_recall>=gate.get('unsafe_candidate_recall_min',0.9)
        and point_fpr<=gate.get('safe_false_positive_rate_max',0.05)
        and false_safe<=gate.get('unsafe_static_safe_max',0))
    return {
        'counts':{'cases':n,'unsafe':unsafe,'safe':safe,'true_candidates':tp,
                  'false_candidates':fp,'dangerous_reported_safe':false_safe,
                  'alerts_without_adjudicated_label':review_alerts,
                  'inconclusive':unresolved,'not_tested':untested},
        'decision_matrix':matrix,
        'unsafe_candidate_recall':point_recall,
        'candidate_precision':None if review_alerts else rate(tp,tp+fp),
        'candidate_precision_on_adjudicated_labels':rate(tp,tp+fp),
        'verified_alert_fraction':rate(tp,tp+fp+review_alerts),
        'safe_false_positive_rate':point_fpr,
        'unsafe_static_safe':false_safe,
        'unsafe_static_safe_rate':rate(false_safe,unsafe),
        'unsafe_candidate_miss_rate':rate(unsafe-tp,unsafe),
        'unsafe_abstention_rate':rate(matrix['unsafe']['INCONCLUSIVE'],unsafe),
        'safe_abstention_rate':rate(matrix['safe']['INCONCLUSIVE'],safe),
        'needs_review_overclaim_rate':rate(matrix['needs_review']['CANDIDATE']+matrix['needs_review']['SAFE'],sum(matrix['needs_review'].values())),
        'unsafe_not_tested_rate':rate(matrix['unsafe']['NOT_TESTED'],unsafe),
        'test_coverage':rate(n-untested,n),
        'decision_coverage':rate(n-untested-unresolved,n),
        'nominal_wilson95':{'candidate_recall':wilson95(tp,unsafe),
                            'candidate_precision':wilson95(tp,tp+fp),
                            'false_positive_rate':wilson95(fp,safe)},
        'family_case_counts':dict(families),
        'unique_code_hashes':len(code_hashes),
        'repeated_code_hashes':{h:k for h,k in code_hashes.items() if k>1},
        'evaluation_kind':(manifest or {}).get('evaluation_kind','exposed_or_unspecified'),
        'point_gate_passed':point_gate_passed,
        'nominal_interval_gate_passed':(point_gate_passed
            and wilson95(tp,unsafe)['lower']>=gate.get('unsafe_candidate_recall_min',0.9)
            and wilson95(fp,safe)['upper']<=gate.get('safe_false_positive_rate_max',0.05)),
        'production_accuracy_established':False,
        'model_promotion_allowed':False,
        'limitations':[
            'Rates use all supplied labels; unsafe abstentions/not-tested cases remain recall misses.',
            'Labels must come from reviewed semantics; browser non-execution alone is not a safe label.',
            'Intervals are nominal; shared templates/repos and selected synthetic cases can invalidate iid inference.',
            'Unit-test success and a point threshold do not establish learned-model or production accuracy.',
            'Independent external reviewed cases and disjoint source groups are still required.'
        ],
    }

def compare_same_cases(before,after):
    # Percentages from rotating suites are not a before/after measurement.
    if not before.get('cases_sha256') or before.get('cases_sha256')!=after.get('cases_sha256'):
        raise ValueError('Cannot compare different case partitions')
    def inventory(report):
        return {row['id']:(row['label'],row['code']) for row in report['results']}
    if inventory(before)!=inventory(after):raise ValueError('Case labels or source changed')
    return {'cases_sha256':before['cases_sha256'],
            'before':score_decisions(before['results'],before.get('manifest')),
            'after':score_decisions(after['results'],after.get('manifest'))}
