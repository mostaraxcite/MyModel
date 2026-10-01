"""Open-set selection policy for XSS semantic field models.

Known structural classes are scored as closed-set classification. OTHER is treated
as an abstention/open-set bucket and is never allowed to become an authoritative
vulnerability decision. This matches the deployed deterministic-primary hybrid.
"""
from __future__ import annotations
import argparse, json
from pathlib import Path

TASKS=("source","sink","defense")
OPEN_SET_LABEL="OTHER"


def score_candidate(path: Path) -> dict:
    raw=json.loads(path.read_text())
    out={"slug":raw["slug"],"tasks":{}}
    known_means=[]
    known_mins=[]
    for task in TASKS:
        per=raw[task]["per_class_f1"]
        known={k:float(v) for k,v in per.items() if k != OPEN_SET_LABEL}
        unknown=float(per.get(OPEN_SET_LABEL,0.0))
        mean=sum(known.values())/len(known)
        minimum=min(known.values())
        out["tasks"][task]={
            "known_macro_f1":mean,
            "known_min_class_f1":minimum,
            "known_per_class_f1":known,
            "open_set_other_f1_advisory":unknown,
        }
        known_means.append(mean); known_mins.append(minimum)
    out["known_mean_macro_f1"]=sum(known_means)/len(known_means)
    out["known_min_class_f1"]=min(known_mins)
    out["research_gate_passed"]=bool(
        out["tasks"]["source"]["known_macro_f1"] >= .90
        and out["tasks"]["sink"]["known_macro_f1"] >= .90
        and out["tasks"]["defense"]["known_macro_f1"] >= .90
        and out["known_min_class_f1"] >= .80
    )
    out["open_set_policy"]="OTHER is abstention/advice only; deterministic layer stays authoritative"
    out["promotion_allowed"]=False
    out["locked_hard_or_external_used"]=False
    return out


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--candidates-root",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    rows=[score_candidate(path) for path in a.candidates_root.rglob("candidate_score.json")]
    if len(rows)<1:
        raise SystemExit("no candidate scores")
    rows.sort(key=lambda r:(
        r["research_gate_passed"],
        r["known_mean_macro_f1"],
        r["tasks"]["sink"]["known_macro_f1"],
        r["tasks"]["source"]["known_macro_f1"],
    ),reverse=True)
    winner=rows[0]
    report={
        "schema":"xss-semantic-open-set-v4c-selection",
        "candidates":rows,
        "winner":winner,
        "research_gate_passed":bool(winner["research_gate_passed"]),
        "promotion_allowed":False,
        "locked_hard_or_external_used":False,
        "note":"Open-set OTHER is not a closed semantic class and cannot override deterministic abstention.",
    }
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2))
    if not report["research_gate_passed"]:
        raise SystemExit("semantic open-set research gate failed")


if __name__=="__main__":
    main()
