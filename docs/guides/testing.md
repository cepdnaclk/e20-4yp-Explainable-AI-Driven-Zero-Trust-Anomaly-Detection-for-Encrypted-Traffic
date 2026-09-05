# Testing Guide — Real and Simulated Traffic
**Enhanced Pipeline | University of Peradeniya**

---

## Quick Test Menu

| Test | Command | Time |
|------|---------|------|
| Existing pipeline (27 tests) | `python -m tests.test_pipeline` | ~30s |
| DDL feature extractor smoke test | `python DDLModel/ddl_feature_extractor.py` | <1s |
| Timing profiler (synthetic) | `python -m profiling.timing_profiler --n_samples 200` | ~20s |
| Latency benchmark + plots | `python -m profiling.latency_benchmark --n_flows 500` | ~60s |
| Live demo mode (no switch needed) | `python LiveTraffic/live_pipeline.py --demo --duration 30` | 30s |

---

## Section 1 — Unit Tests (No Hardware Required)

### 1.1 Existing Test Suite
```bash
# Activate venv
source .venv/bin/activate

# Run all 27 existing tests
python -m tests.test_pipeline

# Expected output: 27 sub-tests, all passing
```

### 1.2 DDL Feature Extractor
```bash
python DDLModel/ddl_feature_extractor.py
# Expected: Prints 30 features with values for a synthetic benign flow
```

### 1.3 Timing Profiler
```bash
python -m profiling.timing_profiler --n_samples 200 --output profiling/results/report.json
# Expected: Table showing mean/median/p95 for all 7 pipeline stages
```

### 1.4 Latency Benchmark + Charts
```bash
python -m profiling.latency_benchmark --n_flows 500 --output profiling/results/
# Generates:
#   profiling/results/profiling_report.json
#   profiling/results/latency_cdf.png
#   profiling/results/latency_boxplot.png
```

---

## Section 2 — Training the DDL (No Dataset Required — Synthetic)

```bash
# Train on synthetic data (good for pipeline testing, poor for real anomaly detection)
python -c "
import numpy as np
from DDLModel.ddl_model import DeepDictionaryLearning

rng = np.random.default_rng(42)
X_normal = rng.normal(0, 1, (2000, 30))     # 2000 synthetic normal samples
ddl = DeepDictionaryLearning(
    n_features=30, n_atoms_l1=64, n_atoms_l2=128, n_epochs=50
)
ddl.fit(X_normal)
import os; os.makedirs('models', exist_ok=True)
ddl.save('models/ddl_40feat_synthetic.pkl')
print('Model saved to models/ddl_40feat_synthetic.pkl')
"
```

---

## Section 3 — Training on CIC-IDS-2017 (Real Dataset)

Download from: https://www.unb.ca/cic/datasets/ids-2017.html
Expected file: `data/cicids2017/Wednesday-workingHours.pcap_ISCX.csv`

```bash
python DDLModel/train_ddl_enhanced.py \
    --dataset data/cicids2017/Wednesday-workingHours.pcap_ISCX.csv \
    --output  models/ddl_40feat_real.pkl \
    --n_atoms_l1 64 \
    --n_atoms_l2 128 \
    --epochs 150 \
    --threshold f1_optimal

# Training takes 5-15 minutes depending on dataset size.
# Output: models/ddl_40feat_real.pkl
```

---

## Section 4 — Live Demo Test (Synthetic Flows, No Switch)

```bash
# Terminal 1: Start demo pipeline (generates fake flows internally)
python LiveTraffic/live_pipeline.py \
    --demo \
    --duration 60 \
    --ddl_model models/ddl_40feat_synthetic.pkl \
    --log_path  logs/demo_test.json

# Expected output every 30s:
#   Flows seen:  120
#   DDL normal:   96 (80.0%) → FORWARD
#   DDL anomaly:  24 (20.0%) → DROP
```

---

## Section 5 — Live Traffic Test (Physical Switch)

**Prerequisites:** See `docs/setup/switch-overview.md`

```bash
# Check mirror port is receiving traffic
sudo tcpdump -i eth1 -n -c 20

# Start live pipeline (60 second run)
sudo python LiveTraffic/live_pipeline.py \
    --interface  eth1 \
    --duration   60 \
    --ddl_model  models/ddl_40feat_real.pkl \
    --log_path   logs/live_test_$(date +%Y%m%d_%H%M%S).json

# Verbose: show every FORWARD/DROP decision
# Add: --no_shap for faster processing without SHAP
```

### 5.1 Generate Test Attack Traffic (from separate machine)
```bash
# On the traffic generator machine (connected to switch):
# Option A: ICMP flood (visible in tcpdump)
sudo ping -f 10.0.0.2

# Option B: Replay CIC-IDS-2017 attack PCAP
sudo tcpreplay --intf1=eth0 --multiplier=1 \
    BaseCheckClassifier/BaseCheckClassifierSimulation/attack/attack.pcap

# Option C: SYN flood simulation (requires hping3)
sudo hping3 -S --flood -V -p 80 10.0.0.2
```

---

## Section 6 — EnhancedPipeline Tests

```bash
# Test Isolation Forest voter
python -c "
import numpy as np
from EnhancedPipeline.if_second_vote import IsolationForestVoter, EnsembleVoter
from DDLModel.ddl_model import DeepDictionaryLearning

rng = np.random.default_rng(42)
X_n = rng.normal(0, 1, (500, 30))   # Normal

ddl = DeepDictionaryLearning(n_features=30, n_atoms_l1=32, n_epochs=30)
ddl.fit(X_n)

voter = IsolationForestVoter()
voter.fit(X_n)

# Test on anomaly
x_anom = rng.normal(0, 10, 30)    # Extreme outlier
r_ddl  = ddl.predict(x_anom)
r_if   = voter.predict(x_anom)
print(f'DDL: {r_ddl[\"labels\"]}  |  IF: {r_if[\"labels\"]}')

ensemble = EnsembleVoter(ddl, voter)
vote = ensemble.predict(x_anom)
print(f'Ensemble vote: {vote[\"action\"]} (confidence: {vote[\"confidence\"]})')
"

# Test timing profiler
python -m profiling.timing_profiler --n_samples 100
```

---

## Section 7 — Expected Results Summary

| Test | Expected Result | Acceptable Range |
|------|----------------|------------------|
| Existing 27 tests | All pass | 27/27 |
| DDL training (synthetic, 2000 samples, 50 epochs) | Loss converges | Final loss < 0.5 |
| DDL threshold (p95 of normal errors) | Set automatically | Any value |
| Demo mode: DDL anomaly rate (20% attack synthetic) | ~18-22% flagged | 15-30% |
| Latency: DT path (feat15 + DT) | <5ms mean | <10ms |
| Latency: DDL forward (50 ISTA iters) | 30-80ms mean | <200ms |
| SHAP on single sample | ~200-400ms | <1s |
| IF vote (100 trees) | <5ms | <20ms |
