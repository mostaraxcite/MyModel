"""Train the field-level semantic Source/Sink/Defense advisor."""
from __future__ import annotations
import argparse, json, math, random, time
from pathlib import Path
import numpy as np
import torch
from sklearn.metrics import accuracy_score, f1_score
from torch.utils.data import Dataset, DataLoader
from transformers import AutoTokenizer, get_linear_schedule_with_warmup
from xss_specialist.dual_branch import XSSDualBranchModel, SEMANTIC_LABEL_SPACES
from xss_specialist.multitask import IGNORE_INDEX

TASKS=tuple(SEMANTIC_LABEL_SPACES)

class Rows(Dataset):
    def __init__(self,path):
        self.rows=[json.loads(x) for x in Path(path).read_text().splitlines() if x.strip()]
    def __len__(self): return len(self.rows)
    def __getitem__(self,i): return self.rows[i]

class Collator:
    def __init__(self,tok,max_length): self.tok,self.max_length=tok,max_length
    def __call__(self,rows):
        b=self.tok([r["text"] for r in rows],padding=True,truncation=True,max_length=self.max_length,return_tensors="pt")
        for t in TASKS:
            b[f"{t}_labels"]=torch.tensor([int(r[f"{t}_label"]) for r in rows],dtype=torch.long)
        return b

def class_weights(rows,task,power):
    labels=SEMANTIC_LABEL_SPACES[task]
    counts=np.zeros(len(labels),dtype=np.float64)
    for r in rows.rows:
        v=int(r[f"{task}_label"])
        if v!=IGNORE_INDEX: counts[v]+=1
    w=np.ones(len(labels),dtype=np.float32)
    present=counts>0
    if power>0 and present.any():
        w[present]=1.0/np.power(counts[present],power)
        w[present]/=w[present].mean()
    return torch.tensor(w,dtype=torch.float32),{labels[i]:{"count":int(counts[i]),"weight":float(w[i])} for i in range(len(labels))}

def evaluate(model,loader,device):
    truth={t:[] for t in TASKS}; pred={t:[] for t in TASKS}
    model.eval()
    with torch.no_grad():
        for batch in loader:
            batch={k:v.to(device) for k,v in batch.items()}
            out=model.forward_semantic(**batch)
            for t in TASKS:
                y=batch[f"{t}_labels"]; mask=y.ne(IGNORE_INDEX)
                if not mask.any(): continue
                p=out.logits[t].argmax(-1)
                truth[t].extend(y[mask].cpu().tolist()); pred[t].extend(p[mask].cpu().tolist())
    tasks={}
    for t in TASKS:
        ids=list(range(len(SEMANTIC_LABEL_SPACES[t])))
        per={}
        for i,name in enumerate(SEMANTIC_LABEL_SPACES[t]):
            per[name]=float(f1_score(truth[t],pred[t],labels=[i],average="macro",zero_division=0))
        tasks[t]={
            "macro_f1":float(f1_score(truth[t],pred[t],labels=ids,average="macro",zero_division=0)),
            "accuracy":float(accuracy_score(truth[t],pred[t])),
            "per_class_f1":per,
        }
    return {"tasks":tasks,"mean_macro_f1":float(np.mean([tasks[t]["macro_f1"] for t in TASKS]))}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--backbone",type=Path,required=True)
    p.add_argument("--train",type=Path,required=True)
    p.add_argument("--dev",type=Path,required=True)
    p.add_argument("--output-dir",type=Path,required=True)
    p.add_argument("--epochs",type=int,default=6)
    p.add_argument("--batch-size",type=int,default=48)
    p.add_argument("--max-length",type=int,default=96)
    p.add_argument("--lr",type=float,default=3e-5)
    p.add_argument("--class-power",type=float,default=.25)
    p.add_argument("--seed",type=int,default=8082)
    a=p.parse_args()
    random.seed(a.seed); np.random.seed(a.seed); torch.manual_seed(a.seed)
    tr=Rows(a.train); dv=Rows(a.dev)
    tok=AutoTokenizer.from_pretrained(a.backbone)
    model=XSSDualBranchModel(str(a.backbone))
    weight_map={}; weight_report={}
    for t in TASKS:
        w,r=class_weights(tr,t,a.class_power); weight_map[t]=w; weight_report[t]=r
    model.configure_losses(
        semantic_task_weights={"source":1.0,"sink":1.0,"defense":1.0},
        class_weights=weight_map,
    )
    coll=Collator(tok,a.max_length)
    train_loader=DataLoader(tr,batch_size=a.batch_size,shuffle=True,generator=torch.Generator().manual_seed(a.seed),collate_fn=coll)
    dev_loader=DataLoader(dv,batch_size=a.batch_size*2,shuffle=False,collate_fn=coll)
    device=torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    params=[p for p in model.semantic_parameters() if p.requires_grad]
    opt=torch.optim.AdamW(params,lr=a.lr,weight_decay=.01)
    steps=max(1,a.epochs*len(train_loader))
    sch=get_linear_schedule_with_warmup(opt,num_warmup_steps=max(1,math.ceil(steps*.08)),num_training_steps=steps)
    a.output_dir.mkdir(parents=True,exist_ok=True)
    best=-1.; history=[]; started=time.time()
    for epoch in range(1,a.epochs+1):
        model.semantic_backbone.train(); model.semantic_heads.train()
        losses=[]
        for batch in train_loader:
            batch={k:v.to(device) for k,v in batch.items()}
            opt.zero_grad(set_to_none=True)
            out=model.forward_semantic(**batch)
            if out.loss is None: continue
            out.loss.backward(); torch.nn.utils.clip_grad_norm_(params,1.0)
            opt.step(); sch.step(); losses.append(float(out.loss.detach().cpu()))
        ev=evaluate(model,dev_loader,device)
        row={"epoch":epoch,"train_loss":float(np.mean(losses)) if losses else None,"dev":ev}
        history.append(row); print(json.dumps(row,indent=2))
        if ev["mean_macro_f1"]>best:
            best=ev["mean_macro_f1"]; model.save(a.output_dir)
            tok.save_pretrained(a.output_dir/"semantic_backbone")
            tok.save_pretrained(a.output_dir/"flow_backbone")
            (a.output_dir/"best_metrics.json").write_text(json.dumps(row,indent=2)+"\n")
    report={
        "schema":"xss-semantic-field-v4-training",
        "task_formulation":"field-level masked multi-head",
        "best_mean_macro_f1":best,
        "history":history,
        "train_rows":len(tr),"dev_rows":len(dv),
        "epochs":a.epochs,"lr":a.lr,"max_length":a.max_length,
        "class_weights":weight_report,
        "locked_hard_or_external_used":False,
        "whole_snippet_classifier_loss":False,
        "final_judge":False,"promotion_allowed":False,
        "runtime_seconds":round(time.time()-started,2),
    }
    (a.output_dir/"training_report.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2))
if __name__=="__main__": main()
