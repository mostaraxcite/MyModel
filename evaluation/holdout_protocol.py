"""Structural checks for an external holdout; not an independence certificate.

Reviewers must verify source revisions, labels, full development/training
inventory and representative sampling outside this metadata checker.
"""
from collections import Counter
import hashlib
import re

def fingerprint(code):
    # A conservative formatting-copy check. This is not a semantic or
    # variable-renaming detector, so a clean result cannot prove no leakage.
    return hashlib.sha256(re.sub(r'\s+','',code).encode()).hexdigest()

def audit_holdout(cases,development,manifest,min_per_class=100,min_repositories=5,min_families=10):
    reasons=[];ids=set();fingerprints=set();repositories=set();families=set();counts=Counter()
    dev_fingerprints={fingerprint(c['code']) for c in development}
    dev_repositories={c.get('provenance',{}).get('repository') for c in development}
    dev_repositories.discard(None)
    if manifest.get('evaluation_kind')!='external_holdout':reasons.append('dataset_is_not_external_holdout')
    if manifest.get('exposure_status')!='unseen':reasons.append('dataset_already_exposed_or_unverified')
    if manifest.get('frozen_before_engine_changes') is not True:reasons.append('freeze_order_unverified')
    if manifest.get('development_inventory_complete') is not True:reasons.append('development_inventory_incomplete')
    if manifest.get('sampling_plan_ref') is None:reasons.append('representative_sampling_plan_missing')
    for case in cases:
        identity=case.get('id');code=case.get('code');label=case.get('label')
        if not isinstance(identity,str) or not identity or identity in ids:reasons.append('missing_or_duplicate_case_id')
        if isinstance(identity,str):ids.add(identity)
        if not isinstance(code,str) or not code:
            reasons.append('source_code_missing');continue
        h=fingerprint(code)
        if h in dev_fingerprints:reasons.append('development_code_overlap')
        if h in fingerprints:reasons.append('repeated_holdout_code')
        fingerprints.add(h)
        if not isinstance(label,str) or label not in {'unsafe','safe'}:reasons.append('label_not_adjudicated')
        else:counts[label]+=1
        source=case.get('provenance',{});repository=source.get('repository');revision=source.get('revision','')
        if not isinstance(repository,str) or not repository or not isinstance(revision,str) or not re.fullmatch(r'[0-9a-f]{40}',revision) or not source.get('path'):
            reasons.append('immutable_external_source_missing')
        if isinstance(repository,str) and repository in dev_repositories:reasons.append('development_repository_overlap')
        if isinstance(repository,str) and repository:repositories.add(repository)
        family=case.get('family')
        if family:families.add(family)
        else:reasons.append('source_family_missing')
        review=case.get('label_review',{})
        if not review.get('reviewer') or not review.get('evidence_ref') or not review.get('semantic_reason'):
            reasons.append('independent_label_review_missing')
        if review.get('reviewer') in set(manifest.get('engine_authors',[])):
            reasons.append('reviewer_is_engine_author')
        if review.get('safe_by_nonexecution_only') is not False:
            reasons.append('negative_browser_result_is_not_safe_ground_truth')
        if label=='unsafe' and case.get('browser',{}).get('executed') is not True:
            reasons.append('positive_execution_evidence_missing')
    if counts['unsafe']<min_per_class or counts['safe']<min_per_class:reasons.append('insufficient_cases_per_class')
    if len(repositories)<min_repositories:reasons.append('insufficient_disjoint_source_repositories')
    if len(families)<min_families:reasons.append('insufficient_source_families')
    return {'metadata_checks_passed':not reasons,'reasons':sorted(set(reasons)),
            'counts':dict(counts),'source_repositories':len(repositories),'families':len(families),
            'independence_verified':False,'model_promotion_allowed':False,
            'scope':'structural metadata/overlap checks only; reviewer/source/sampling assertions require external verification'}
