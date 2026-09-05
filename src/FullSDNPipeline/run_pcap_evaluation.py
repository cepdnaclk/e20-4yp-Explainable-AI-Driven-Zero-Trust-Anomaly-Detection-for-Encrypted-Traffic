#!/usr/bin/env python3
"""
Modular End-to-End PCAP Pipeline Evaluation
=============================================
Two-stage modular feature extraction:
  Stage 1: Sandaru's 28-feature extractor → BCC (always runs)
  Stage 2: DDL 40-feature extractor → DDL + IF (only on BCC-flagged flows)

Smart consensus:
  - If flow has ≥20 non-zero DDL features: require DDL AND IF consensus
  - If flow has <20 non-zero features (sparse PortScan): use DDL alone
  This handles minimal-packet flows (SYN→RST port scans with only 2 packets).
"""
import os, re, sys, json, time, argparse
import numpy as np, joblib

_THIS_DIR    = os.path.dirname(os.path.abspath(__file__))
SRC_ROOT     = os.path.dirname(_THIS_DIR)
PROJECT_ROOT = os.path.dirname(SRC_ROOT)
sys.path.insert(0, SRC_ROOT)
sys.path.insert(0, os.path.join(SRC_ROOT, 'BaseCheckClassifier'))

from sdn.extraction.feature_extractor import extract_features_extended, SENTRY_V2_FEATURES
from DDLModel.ddl_pcap_extractor import extract_ddl_features, DDL_40_FEATURES
from DDLModel.ddl_model import DeepDictionaryLearning

parser = argparse.ArgumentParser()
parser.add_argument("--pcap-dir", default=os.environ.get(
    "CIC_PCAP_DIR", "/scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/Friday"))
parser.add_argument("--max-flows", type=int, default=5000)
args = parser.parse_args()

print("Loading models...", flush=True)
bcc_data = joblib.load(f'{PROJECT_ROOT}/models/sentry_model_v2.pkl')
bcc_model = bcc_data['model']; bcc_features = bcc_data['feature_names']; bcc_thresh = bcc_data.get('threshold', 0.5)
ddl = DeepDictionaryLearning.load(f'{PROJECT_ROOT}/models/ddl_40feat.pkl')
if_data = joblib.load(f'{PROJECT_ROOT}/models/isolation_forest.pkl'); if_model = if_data['clf']

# Parse PCAP directories
pattern = re.compile(r"Row_(\d+)_(.+)")
flow_dirs = []
for d in sorted(os.listdir(args.pcap_dir)):
    m = pattern.match(d)
    if m:
        pp = os.path.join(args.pcap_dir, d, "packets.pcap")
        if os.path.exists(pp):
            flow_dirs.append({"dir": d, "label": m.group(2), "pcap": pp, "is_attack": m.group(2).upper() != "BENIGN"})

np.random.seed(42)
if args.max_flows and args.max_flows < len(flow_dirs):
    idx = np.random.choice(len(flow_dirs), args.max_flows, replace=False)
    flow_dirs = [flow_dirs[i] for i in sorted(idx)]

from collections import Counter
label_counts = Counter(f["label"] for f in flow_dirs)
n_attack = sum(1 for f in flow_dirs if f["is_attack"])
n_benign = len(flow_dirs) - n_attack
print(f"Flows: {len(flow_dirs)} ({n_benign} benign / {n_attack} attack)", flush=True)
print(f"Labels: {dict(label_counts)}", flush=True)

# Run pipeline
tp = tn = fp = fn = 0
bcc_flagged_count = dropped_count = 0
skip_bcc = skip_ddl = 0
sparse_ddl_only = 0
t_ext_bcc = []; t_bcc = []; t_ext_ddl = []; t_ddl = []; t_if = []; t_total = []

for i, flow in enumerate(flow_dirs):
    y = 1 if flow["is_attack"] else 0
    t0_total = time.perf_counter()

    # ── STAGE 1: BCC (28 features from Sandaru's extractor) ──
    t0 = time.perf_counter()
    bcc_result = extract_features_extended(flow["pcap"])
    t_ext_bcc.append((time.perf_counter() - t0) * 1e6)

    if not bcc_result["valid"]:
        skip_bcc += 1
        if y == 1: fn += 1
        else: tn += 1
        continue

    bcc_vec = np.nan_to_num(np.array([bcc_result["features"].get(c, 0.0) for c in bcc_features], dtype=np.float64).reshape(1, -1), nan=0.0, posinf=1e9, neginf=-1e9)  
    t0 = time.perf_counter()
    bcc_proba = bcc_model.predict_proba(bcc_vec)[0, 1]
    bcc_pred = int(bcc_proba >= bcc_thresh)
    t_bcc.append((time.perf_counter() - t0) * 1e6)

    final_pred = 0
    if bcc_pred == 1:
        bcc_flagged_count += 1

        # ── STAGE 2: DDL+IF (40 features from DDL extractor) ──
        t0 = time.perf_counter()
        ddl_result = extract_ddl_features(flow["pcap"])
        t_ext_ddl.append((time.perf_counter() - t0) * 1e6)

        if ddl_result["valid"]:
            ddl_vec = np.nan_to_num(np.clip(np.array(ddl_result["ordered"], dtype=np.float64).reshape(1, -1), -1e9, 1e9))

            t0 = time.perf_counter()
            ddl_out = ddl.predict(ddl_vec)
            ddl_label = ddl_out["labels"][0]
            t_ddl.append((time.perf_counter() - t0) * 1e6)

            t0 = time.perf_counter()
            if_score = if_model.predict(ddl_vec)[0]
            t_if.append((time.perf_counter() - t0) * 1e6)

            # Smart consensus: check feature richness
            n_nonzero = sum(1 for v in ddl_result["ordered"] if v != 0)
            if n_nonzero >= 20:
                # Rich features: require both DDL AND IF
                if ddl_label == "Anomaly" and if_score == -1:
                    final_pred = 1
            else:
                # Sparse features (e.g., 2-pkt PortScan): trust DDL alone
                if ddl_label == "Anomaly":
                    final_pred = 1
                    sparse_ddl_only += 1
        else:
            skip_ddl += 1

    if final_pred == 1: dropped_count += 1
    t_total.append((time.perf_counter() - t0_total) * 1e6)

    if final_pred == 1 and y == 1: tp += 1
    elif final_pred == 1 and y == 0: fp += 1
    elif final_pred == 0 and y == 1: fn += 1
    else: tn += 1

    if (i+1) % 500 == 0:
        print(f"  {i+1}/{len(flow_dirs)}...", flush=True)

n = tp + tn + fp + fn
acc = (tp+tn)/max(n,1); prec = tp/max(tp+fp,1); rec = tp/max(tp+fn,1)
f1 = 2*prec*rec/max(prec+rec,1e-9); fpr_val = fp/max(fp+tn,1)

def avg(l): return np.mean(l) if l else 0

print(f"\n{'='*60}", flush=True)
print(f"MODULAR PCAP PIPELINE RESULTS", flush=True)
print(f"{'='*60}", flush=True)
print(f"Flows: {n} (skip_bcc={skip_bcc} skip_ddl={skip_ddl})", flush=True)
print(f"Attack types: {dict(label_counts)}", flush=True)
print(f"\nBCC forwarded: {n-bcc_flagged_count}  BCC flagged: {bcc_flagged_count}", flush=True)
print(f"DDL+IF consensus DROP: {dropped_count} (DDL-only sparse: {sparse_ddl_only})", flush=True)
print(f"TP={tp} TN={tn} FP={fp} FN={fn}", flush=True)
print(f"Accuracy={acc:.4f} Precision={prec:.4f} Recall={rec:.4f} F1={f1:.4f} FPR={fpr_val:.4f}", flush=True)
print(f"\n               Predicted", flush=True)
print(f"            FORWARD    DROP", flush=True)
print(f"Normal       {tn:>6}   {fp:>5}", flush=True)
print(f"Attack       {fn:>6}   {tp:>5}", flush=True)
print(f"\nTiming:", flush=True)
print(f"  BCC extract (28f): {avg(t_ext_bcc):.0f} µs", flush=True)
print(f"  BCC inference:     {avg(t_bcc):.0f} µs", flush=True)
print(f"  DDL extract (40f): {avg(t_ext_ddl):.0f} µs (flagged only)", flush=True)
print(f"  DDL inference:     {avg(t_ddl):.0f} µs (flagged only)", flush=True)
print(f"  IF inference:      {avg(t_if):.0f} µs (flagged only)", flush=True)
print(f"  Total pipeline:    {avg(t_total):.0f} µs", flush=True)

# Save
out_dir = f'{PROJECT_ROOT}/results/pcap_results'
os.makedirs(out_dir, exist_ok=True)
summary = {
    'mode': 'Modular PCAP (BCC 28-feat → DDL+IF 40-feat, smart consensus)',
    'n_flows': n, 'skipped': skip_bcc + skip_ddl, 'attack_types': dict(label_counts),
    'pipeline': {'TP':tp,'TN':tn,'FP':fp,'FN':fn,'accuracy':round(acc,4),'precision':round(prec,4),'recall':round(rec,4),'f1':round(f1,4),'fpr':round(fpr_val,4),
        'bcc_forwarded':n-bcc_flagged_count,'bcc_flagged':bcc_flagged_count,'dropped':dropped_count,'sparse_ddl_only':sparse_ddl_only},
    'timing_us': {'bcc_extract':round(avg(t_ext_bcc)),'bcc_infer':round(avg(t_bcc)),'ddl_extract':round(avg(t_ext_ddl)),'ddl_infer':round(avg(t_ddl)),'if_infer':round(avg(t_if)),'total':round(avg(t_total))},
}
with open(f'{out_dir}/summary.json','w') as f: json.dump(summary, f, indent=2)
print(f"\nSaved to {out_dir}/", flush=True)
