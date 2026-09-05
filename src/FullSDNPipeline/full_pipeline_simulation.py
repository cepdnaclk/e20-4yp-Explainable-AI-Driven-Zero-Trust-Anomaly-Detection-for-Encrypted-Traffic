#!/usr/bin/env python3
"""
Full Two-Stage SDN Pipeline Simulation
========================================
Runs Sandaru's BCC (Stage 1) + Janith's DDL+IF (Stage 2) + XAI
on ALL labeled PCAPs from all 5 CIC-IDS-2017 days.

Stage 1: BCC v2 (28 features, Sandaru's extractor) → BENIGN or FLAG
Stage 2: DDL+IF (40 features, DDL extractor) → FORWARD or DROP
XAI:     LIME on sampled dropped flows

Usage:
    python3 full_pipeline_simulation.py              # All 5 days
    python3 full_pipeline_simulation.py --limit 5000 # Quick test
"""
import os, sys, time, pickle, argparse, json, re
import numpy as np

_THIS_DIR    = os.path.dirname(os.path.abspath(__file__))
SRC_ROOT     = os.path.dirname(_THIS_DIR)
PROJECT_ROOT = os.path.dirname(SRC_ROOT)
sys.path.insert(0, SRC_ROOT)
sys.path.insert(0, os.path.join(SRC_ROOT, 'BaseCheckClassifier'))

# Stage 1 extractor (28 features)
from sdn.extraction.feature_extractor import extract_features_extended, SENTRY_V2_FEATURES
# Stage 2 extractor (40 features)
from DDLModel.ddl_pcap_extractor import extract_ddl_features, DDL_40_FEATURES
from DDLModel.ddl_model import DeepDictionaryLearning

DATASET_ROOT = os.environ.get(
    "CIC_PCAP_ROOT", "/scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/"
)

parser = argparse.ArgumentParser()
parser.add_argument("--limit", type=int, default=0, help="Limit flows (0=all)")
parser.add_argument("--xai-sample", type=int, default=10, help="Flows to explain")
args = parser.parse_args()

print("=" * 60, flush=True)
print("FULL TWO-STAGE SDN PIPELINE SIMULATION", flush=True)
print("=" * 60, flush=True)

# Load models
print("\n[1/5] Loading models...", flush=True)
import joblib
bcc_data = joblib.load(f'{PROJECT_ROOT}/models/sentry_model_v2.pkl')
bcc_model = bcc_data['model']; bcc_features = bcc_data['feature_names']; bcc_thresh = bcc_data.get('threshold', 0.5)
ddl = DeepDictionaryLearning.load(f'{PROJECT_ROOT}/models/ddl_40feat.pkl')
if_data = joblib.load(f'{PROJECT_ROOT}/models/isolation_forest.pkl'); if_model = if_data['clf']
print(f"  SENTRY v2: {len(bcc_features)} features", flush=True)
print(f"  DDL: {ddl.n_features} features", flush=True)
print(f"  IF: {if_data['clf'].n_estimators} trees", flush=True)

# Discover PCAPs
print(f"\n[2/5] Discovering PCAPs from {DATASET_ROOT}...", flush=True)
tasks = []
for root, dirs, files in os.walk(DATASET_ROOT):
    if "packets.pcap" in files:
        folder = os.path.basename(root)
        if "_" in folder:
            label = folder.split("_", 2)[-1]  # Row_123_DDoS → DDoS
            gt = "BENIGN" if label == "BENIGN" else "ATTACK"
            tasks.append((os.path.join(root, "packets.pcap"), gt, label))
        if args.limit > 0 and len(tasks) >= args.limit:
            break

print(f"  Found {len(tasks):,} streams", flush=True)
from collections import Counter
type_counts = Counter(t[2] for t in tasks)
print(f"  Types: {dict(type_counts)}", flush=True)

# Process flows
print(f"\n[3/5] Running pipeline...", flush=True)
start_all = time.perf_counter()

# Counters
tp = tn = fp = fn = 0
bcc_pass = bcc_flag = 0
ddl_if_drop = ddl_if_fwd = 0
sparse_ddl_only = 0
errors = 0
bcc_alone_tp = bcc_alone_fn = 0

# Timing
t_bcc_ext = []; t_bcc_inf = []; t_ddl_ext = []; t_ddl_inf = []; t_if_inf = []

# XAI storage
dropped_for_xai = []

for idx, (pcap_path, gt, attack_type) in enumerate(tasks):
    is_attack = (gt == "ATTACK")

    # ── STAGE 1: BCC ──
    t0 = time.perf_counter()
    bcc_r = extract_features_extended(pcap_path)
    t_bcc_ext.append((time.perf_counter() - t0) * 1e6)

    if not bcc_r["valid"]:
        errors += 1
        continue

    bcc_vec = np.array([bcc_r["features"].get(c, 0.0) for c in bcc_features], dtype=np.float64).reshape(1, -1)
    bcc_vec = np.nan_to_num(bcc_vec, posinf=1e9, neginf=-1e9)

    t0 = time.perf_counter()
    bcc_proba = bcc_model.predict_proba(bcc_vec)[0, 1]
    bcc_pred = int(bcc_proba >= bcc_thresh)
    t_bcc_inf.append((time.perf_counter() - t0) * 1e6)

    # Track BCC standalone recall
    if is_attack:
        if bcc_pred == 1: bcc_alone_tp += 1
        else: bcc_alone_fn += 1

    if bcc_pred == 0:
        # BCC says BENIGN → FORWARD
        bcc_pass += 1
        if is_attack: fn += 1  # Leak!
        else: tn += 1
        continue

    # BCC says ATTACK → Stage 2
    bcc_flag += 1

    # ── STAGE 2: DDL+IF ──
    t0 = time.perf_counter()
    ddl_r = extract_ddl_features(pcap_path)
    t_ddl_ext.append((time.perf_counter() - t0) * 1e6)

    if not ddl_r["valid"]:
        errors += 1
        continue

    ddl_vec = np.nan_to_num(np.clip(np.array(ddl_r["ordered"], dtype=np.float64).reshape(1, -1), -1e9, 1e9))

    t0 = time.perf_counter()
    ddl_out = ddl.predict(ddl_vec)
    ddl_label = ddl_out["labels"][0]; ddl_score = ddl_out["scores"][0]
    t_ddl_inf.append((time.perf_counter() - t0) * 1e6)

    t0 = time.perf_counter()
    if_raw = if_model.predict(ddl_vec)[0]
    if_label = "Anomaly" if if_raw == -1 else "Normal"
    t_if_inf.append((time.perf_counter() - t0) * 1e6)

    # Smart consensus: Stage 1 (BCC) flagged this as highly suspicious.
    # To preserve BCC's ultra-high recall (99.9%), we DROP if *either* DDL or IF confirms it,
    # or if BCC was extremely confident (>0.99).
    n_nz = sum(1 for v in ddl_r["ordered"] if v != 0)
    drop = False
    if ddl_label == "Anomaly" or if_label == "Anomaly" or bcc_proba > 0.98:
        drop = True
        if if_label == "Normal":
            sparse_ddl_only += 1

    if drop:
        ddl_if_drop += 1
        if is_attack:
            tp += 1
        else:
            fp += 1
        # Store for XAI
        if len(dropped_for_xai) < args.xai_sample * 3:
            dropped_for_xai.append({
                "pcap": pcap_path, "gt": gt, "attack_type": attack_type,
                "bcc_proba": float(bcc_proba), "ddl_label": ddl_label,
                "ddl_score": float(ddl_score), "if_label": if_label,
                "ddl_vec": ddl_vec.copy(), "n_nz": n_nz,
            })
    else:
        ddl_if_fwd += 1
        if is_attack: fn += 1
        else: tn += 1

    if (idx + 1) % 10000 == 0:
        print(f"  {idx+1:,}/{len(tasks):,} ({(idx+1)/len(tasks)*100:.1f}%)...", flush=True)

total_time = time.perf_counter() - start_all
n = tp + tn + fp + fn

# Results
acc = (tp+tn)/max(n,1); prec_v = tp/max(tp+fp,1); rec = tp/max(tp+fn,1)
f1 = 2*prec_v*rec/max(prec_v+rec,1e-9); fpr_v = fp/max(fp+tn,1)
bcc_recall = bcc_alone_tp / max(bcc_alone_tp+bcc_alone_fn, 1)
def avg(l): return np.mean(l) if l else 0

print(f"\n{'='*60}", flush=True)
print(f"SIMULATION RESULTS ({total_time/60:.2f} minutes)", flush=True)
print(f"{'='*60}", flush=True)
print(f"Total streams: {len(tasks):,} | Valid: {n:,} | Errors: {errors:,}", flush=True)

print(f"\n--- SENTRY v2 (Stage 1) ---", flush=True)
print(f"  Passed (BENIGN): {bcc_pass:,} | Flagged (ATTACK): {bcc_flag:,}", flush=True)
print(f"  Attack recall: {bcc_recall*100:.3f}% ({bcc_alone_tp}/{bcc_alone_tp+bcc_alone_fn})", flush=True)
print(f"  Leakage (FN at BCC): {bcc_alone_fn}", flush=True)
print(f"  Timing: extract={avg(t_bcc_ext):.0f}µs + infer={avg(t_bcc_inf):.0f}µs = {avg(t_bcc_ext)+avg(t_bcc_inf):.0f}µs/flow", flush=True)

print(f"\n--- DDL+IF (Stage 2, on {bcc_flag:,} flagged) ---", flush=True)
print(f"  Forward (normal): {ddl_if_fwd:,} | DROP (anomaly): {ddl_if_drop:,} (sparse DDL-only: {sparse_ddl_only})", flush=True)
print(f"  Timing: DDL extract={avg(t_ddl_ext):.0f}µs, DDL infer={avg(t_ddl_inf):.0f}µs, IF infer={avg(t_if_inf):.0f}µs", flush=True)

print(f"\n--- FULL PIPELINE ---", flush=True)
print(f"  TP={tp:,} TN={tn:,} FP={fp:,} FN={fn:,}", flush=True)
print(f"  Accuracy={acc*100:.2f}% Precision={prec_v*100:.2f}% Recall={rec*100:.3f}% F1={f1*100:.2f}% FPR={fpr_v*100:.3f}%", flush=True)
print(f"\n  Confusion Matrix:", flush=True)
print(f"                   Predicted", flush=True)
print(f"                FORWARD    DROP", flush=True)
print(f"  Normal       {tn:>8,}  {fp:>6,}", flush=True)
print(f"  Attack       {fn:>8,}  {tp:>6,}", flush=True)

# XAI on dropped flows
print(f"\n[4/5] XAI explanations on {min(len(dropped_for_xai), args.xai_sample)} dropped flows...", flush=True)
xai_results = []
try:
    import lime.lime_tabular
    # Background data for LIME
    bg = np.array([f["ddl_vec"].flatten() for f in dropped_for_xai[:50]])
    def ddl_pred(X):
        r = ddl.predict(X); s = np.array(r["scores"])
        p = np.clip(s / (ddl.threshold_ * 3), 0, 1)
        return np.column_stack([1-p, p])
    def if_pred(X):
        s = if_model.decision_function(X)
        p = np.clip(-s * 2, 0, 1)
        return np.column_stack([1-p, p])
    exp = lime.lime_tabular.LimeTabularExplainer(bg, feature_names=DDL_40_FEATURES, class_names=["Normal","Anomaly"], mode="classification")

    for i, fl in enumerate(dropped_for_xai[:args.xai_sample]):
        vec = fl["ddl_vec"].flatten()
        t0 = time.perf_counter()
        d_exp = exp.explain_instance(vec, ddl_pred, num_features=5, labels=(1,))
        t_d = (time.perf_counter()-t0)*1000
        t0 = time.perf_counter()
        i_exp = exp.explain_instance(vec, if_pred, num_features=5, labels=(1,))
        t_i = (time.perf_counter()-t0)*1000

        d_feats = d_exp.as_list(label=1); i_feats = i_exp.as_list(label=1)
        d_top = set(f.split(" ")[0] for f,_ in d_feats[:5]); i_top = set(f.split(" ")[0] for f,_ in i_feats[:5])
        common = d_top & i_top

        print(f"\n  Flow #{i+1}: {os.path.basename(os.path.dirname(fl['pcap']))} (True: {fl['gt']}, Type: {fl['attack_type']})", flush=True)
        print(f"    BCC: {fl['bcc_proba']:.4f} | DDL: {fl['ddl_label']}({fl['ddl_score']:.2f}) | IF: {fl['if_label']} | nz={fl['n_nz']}/40", flush=True)
        print(f"    DDL-LIME ({t_d:.0f}ms): {[(f,round(w,4)) for f,w in d_feats[:3]]}", flush=True)
        print(f"    IF-LIME  ({t_i:.0f}ms): {[(f,round(w,4)) for f,w in i_feats[:3]]}", flush=True)
        if common: print(f"    ✅ Cross-validated: {common}", flush=True)

        xai_results.append({"flow": os.path.basename(os.path.dirname(fl['pcap'])), "gt": fl['gt'], "type": fl['attack_type'],
            "bcc": fl['bcc_proba'], "ddl": fl['ddl_label'], "ddl_score": fl['ddl_score'], "if": fl['if_label'],
            "ddl_lime": [(f,round(w,4)) for f,w in d_feats[:5]], "if_lime": [(f,round(w,4)) for f,w in i_feats[:5]],
            "cross": list(common), "ddl_lime_ms": round(t_d), "if_lime_ms": round(t_i)})
except Exception as e:
    print(f"  XAI error: {e}", flush=True)

# Save
print(f"\n[5/5] Saving results...", flush=True)
out_dir = f'{PROJECT_ROOT}/results/pcap_results'
os.makedirs(out_dir, exist_ok=True)
results = {
    "date": time.strftime('%Y-%m-%d %H:%M'), "total_time_min": round(total_time/60,2),
    "dataset": "CIC-IDS-2017 All 5 Days (Labeled PCAPs)", "total_streams": len(tasks), "valid": n, "errors": errors,
    "attack_types": dict(type_counts),
    "sentry": {"passed": bcc_pass, "flagged": bcc_flag, "recall_pct": round(bcc_recall*100,3), "leakage": bcc_alone_fn,
        "extract_us": round(avg(t_bcc_ext)), "infer_us": round(avg(t_bcc_inf))},
    "ddl_if": {"forward": ddl_if_fwd, "drop": ddl_if_drop, "sparse_ddl": sparse_ddl_only,
        "ddl_extract_us": round(avg(t_ddl_ext)), "ddl_infer_us": round(avg(t_ddl_inf)), "if_infer_us": round(avg(t_if_inf))},
    "pipeline": {"TP":tp,"TN":tn,"FP":fp,"FN":fn,"accuracy":round(acc,4),"precision":round(prec_v,4),"recall":round(rec,4),"f1":round(f1,4),"fpr":round(fpr_v,4)},
    "xai": xai_results,
}
with open(f'{out_dir}/full_results.json','w') as f: json.dump(results, f, indent=2)

# Generate markdown report
md = f"""# Full Two-Stage SDN Pipeline — Simulation Results
**Date:** {time.strftime('%Y-%m-%d %H:%M')}
**Dataset:** CIC-IDS-2017 All 5 Days (Labeled PCAPs)
**Streams:** {len(tasks):,} total, {n:,} valid, {errors:,} errors
**Total Time:** {total_time/60:.2f} minutes

## Attack Types
{chr(10).join(f'- **{k}**: {v:,}' for k,v in sorted(type_counts.items(), key=lambda x:-x[1]))}

## Stage 1: SENTRY v2 (BCC — 28 Features)
| Metric | Value |
|--------|:-----:|
| Passed (BENIGN) | {bcc_pass:,} |
| Flagged (ATTACK) → Stage 2 | {bcc_flag:,} |
| **Attack Recall** | **{bcc_recall*100:.3f}%** |
| Leakage (missed attacks) | {bcc_alone_fn} |
| Timing | {avg(t_bcc_ext)+avg(t_bcc_inf):.0f} µs/flow |

## Stage 2: DDL + IF (40 Features, Smart Consensus)
| Metric | Value |
|--------|:-----:|
| Forwarded (normal) | {ddl_if_fwd:,} |
| **DROPPED (anomaly)** | **{ddl_if_drop:,}** |
| Sparse DDL-only | {sparse_ddl_only:,} |
| DDL timing | {avg(t_ddl_ext)+avg(t_ddl_inf):.0f} µs/flow |
| IF timing | {avg(t_if_inf):.0f} µs/flow |

## Full Pipeline Results
| Metric | Value |
|--------|:-----:|
| **Accuracy** | **{acc*100:.2f}%** |
| **Precision** | **{prec_v*100:.2f}%** |
| **Recall** | **{rec*100:.3f}%** |
| **F1** | **{f1*100:.2f}%** |
| **FPR** | **{fpr_v*100:.3f}%** |

### Confusion Matrix
```
                   Predicted
                FORWARD    DROP
  Normal       {tn:>8,}  {fp:>6,}
  Attack       {fn:>8,}  {tp:>6,}
```

### Pipeline Flow
```
{len(tasks):,} PCAP streams
    |
    +-- Stage 1: SENTRY v2 (28 features)
    |       |
    |       +-- {bcc_pass:,} BENIGN → FORWARD ({bcc_pass/max(n,1)*100:.1f}%)
    |       +-- {bcc_flag:,} ATTACK → Stage 2 ({bcc_flag/max(n,1)*100:.1f}%)
    |
    +-- Stage 2: DDL+IF (40 features, smart consensus)
            |
            +-- {ddl_if_fwd:,} Normal → FORWARD
            +-- {ddl_if_drop:,} Anomaly → DROP + XAI

    Leakage: {fn} attacks missed (recall = {rec*100:.3f}%)
    False drops: {fp} benign blocked (FPR = {fpr_v*100:.3f}%)
```
"""

if xai_results:
    md += "\n## XAI Explanations (LIME on Dropped Flows)\n\n"
    for x in xai_results:
        md += f"### {x['flow']} (True: {x['gt']}, Type: {x['type']})\n"
        md += f"- BCC: {x['bcc']:.4f} | DDL: {x['ddl']}({x['ddl_score']:.2f}) | IF: {x['if']}\n"
        md += f"- **DDL-LIME** ({x['ddl_lime_ms']}ms): {x['ddl_lime'][:3]}\n"
        md += f"- **IF-LIME** ({x['if_lime_ms']}ms): {x['if_lime'][:3]}\n"
        if x['cross']:
            md += f"- ✅ Cross-validated features: {x['cross']}\n"
        md += "\n"

with open(f'{out_dir}/full_pipeline_results.md','w') as f: f.write(md)
print(f"\nSaved: {out_dir}/full_results.json", flush=True)
print(f"Saved: {out_dir}/full_pipeline_results.md", flush=True)
print(f"\n{'='*60}", flush=True)
print(f"DONE! Accuracy={acc*100:.2f}% Recall={rec*100:.3f}% Precision={prec_v*100:.2f}%", flush=True)
print(f"{'='*60}", flush=True)
