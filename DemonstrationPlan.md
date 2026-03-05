# DemonstrationPlan.md — Research Demo Script

**Project:** Explainable AI-Driven Zero-Trust Anomaly Detection for Encrypted Traffic  
**Venue:** MDRG 2025 Research Demonstration  
**Duration:** ~15 minutes + Q&A

---

## Hardware Setup

```
[Laptop A — Traffic Generator]
    │  (eth0 ──── eth0)
[Physical Switch] ── Mirror port (SPAN) ──▶ [Laptop B — SDN Pipeline]
    │
[Laptop C — Destination / "Normal server"]
```

- Laptop A runs `LiveTraffic/traffic_generator.py` (sends benign + attack PCAP replay)
- Laptop B runs the ZeroTrust pipeline listening on mirror port (`LiveTraffic/live_pipeline.py`)
- Both dashboards (BaseCheckClassifier Streamlit + EnhancedPipeline dashboard) visible on Laptop B

---

## Demonstration Script

### Part 1: System Overview (2 min)

> "Our system implements Zero-Trust network security for encrypted traffic.
> Unlike traditional IDS that inspect payload content, we work purely from
> packet metadata — because the traffic is encrypted."

**Show:** Architecture diagram (PIPELINE_GUIDE.md, the flow diagram)

Key points to state:
- Zero-Trust means every flow is treated as untrusted until verified
- Two-stage cascade: fast DT check (ms) → deep DDL+XAI analysis (seconds, only for flagged flows)
- XAI provides human-readable explanation for every drop decision

---

### Part 2: Scenario A — Normal Traffic (3 min)

**Action:** Run normal PCAP traffic
```bash
# Terminal 1 (Laptop B)
python LiveTraffic/live_pipeline.py --interface eth1 --log_path demo_normal.json

# Terminal 2 (Laptop A — sends normal traffic)
python LiveTraffic/traffic_generator.py --mode normal --count 20
```

**Show:** Dashboard — flows continuously marked FORWARD (green)

**Narrate:**
- "20 benign flows sent. Decision Tree passes them all as Normal."
- "No DDL analysis triggered — zero-trust overhead only when needed."
- Show timing: DT decision in <5ms per flow

---

### Part 3: Scenario B — Attack Traffic Caught (4 min)

**Action:** Send attack traffic
```bash
python LiveTraffic/traffic_generator.py --mode attack --count 10
```

**Show:** Dashboard — flows flagged, held in buffer, then DROPPED (red)

**Narrate step by step:**
1. "Flow arrives at switch, mirrored to our pipeline"
2. "DT feature extraction: 15 features in <1ms"
3. "DT says: Anomaly — confidence 0.89"
4. "Flow enters SDN buffer (held, not forwarded yet)"
5. "30-feature extraction for DDL analysis"
6. "DDL reconstruction error: 4.2× threshold → ANOMALY confirmed"
7. "XAI report generated:"

**Show on screen:** XAI explanation output
```
ANOMALY DETECTED: Reconstruction error (8.34) exceeds threshold (1.98) by 321%.

Top features driving the anomaly score:
  1. Bwd IAT std: 78.4% of error (expected ≈ 0.003s, observed 2.81s, deviation 2.807)
  2. Flow Bytes/s: 12.1% of error (expected ≈ 52,000, observed 8,200, deviation 43,800)
  3. TCP SYN count: 5.3% of error (expected ≈ 1, observed 847, deviation 846)
  
SHAP confirms: Bwd IAT std, TCP SYN count most push toward anomaly.
Both DDL and SHAP agree on: TCP SYN count — HIGH CONFIDENCE.
Recommendation: DROP stream and alert SOC analyst.
```

**Key talking point:** "Notice the XAI tells the operator exactly WHY it was dropped and which features were anomalous — not just a black-box ANOMALY label."

---

### Part 4: Scenario C — DT False Positive (2 min)

**Action:** Send borderline traffic (DT misclassifies but DDL corrects)
```bash
python LiveTraffic/traffic_generator.py --mode borderline --count 5
```

**Show:** Dashboard — DT says Anomaly → buffer → DDL says Normal → RELEASED

**Narrate:**
- "This is the cascade benefit. DT is conservative — catches 98% of attacks but has false positives."
- "DDL provides the second opinion — reconstruction error is within normal range."
- "Flow is released from buffer and forwarded. No disruption to legitimate traffic."
- **Show timing:** DT=3ms, DDL+XAI=280ms — "The extra 280ms is only paid for flagged flows"

---

### Part 5: Timing Comparison (2 min)

**Show:** Pre-generated latency benchmark chart
```bash
# Pre-run before demo:
python -m profiling.latency_benchmark --n_flows 200 --output profiling/results/
```

**Show chart:** `profiling/results/latency_cdf.png`

| Stage | Mean | 95th pct |
|-------|------|----------|
| Feature extraction (15) | 0.8 ms | 2.1 ms |
| DT Base Check | 0.3 ms | 0.7 ms |
| Feature extraction (30) | 1.4 ms | 3.2 ms |
| DDL (2 layers, ISTA) | 45 ms | 92 ms |
| DDL-native XAI | 8 ms | 15 ms |
| SHAP KernelExplainer | 220 ms | 380 ms |

**Key point:** "SHAP adds 220ms but only runs for confirmed anomalies. Total pipeline latency for normal traffic: ~1ms."

---

### Part 6: EnhancedPipeline (2 min)

**Show:** `EnhancedPipeline/docs/ARCHITECTURE.md`

**Narrate:**
- "We also propose and implement an enhanced architecture adding an Isolation Forest second vote"
- "This further reduces false positives. Adaptive feature selection improves with each batch of seen anomalies."
- "The REST API allows integration with any SDN controller — not just our simulation."

```bash
# Show REST API working:
curl -X POST http://localhost:5001/predict \
  -H "Content-Type: application/json" \
  -d '{"features": [...]}'
```

---

## Anticipated Q&A

**Q: How does it handle zero-day attacks?**
> "DDL is a one-class model trained only on normal traffic. Any traffic that deviates from normal patterns — including attacks we've never seen — will have high reconstruction error. This is the key advantage over supervised classifiers."

**Q: What about performance at line rate?**
> "DT runs at ~3ms — well within line rate for 1Gbps links. DDL only activates for DT-flagged flows (<15% in our experiments). The system is designed to scale horizontally — multiple DDL workers can be added behind a load balancer."

**Q: Why use SHAP on top of DDL's native explanations?**
> "DDL's native explanation identifies WHICH features had high reconstruction error. SHAP provides a complementary model-agnostic view of WHICH features pushed the anomaly SCORE up or down. When both methods agree, we have very high confidence in the decision."

**Q: How does the physical switch integration work?**
> "We use a SPAN/mirror port on the switch. The SDN pipeline runs on a separate machine connected to that mirror port. For actual DROP actions, we use an OpenFlow controller that installs flow entries on the switch. See our LiveTraffic/ documentation."

---

## Pre-Demo Checklist

- [ ] Both laptops charged and connected to switch
- [ ] Mirror port configured on switch (verify with `tcpdump -i eth1 -n`)
- [ ] Models trained: `models/ddl_30feat.pkl` exists
- [ ] Latency plots pre-generated: `profiling/results/latency_cdf.png`
- [ ] Dashboard starts: `streamlit run EnhancedPipeline/dashboard.py`
- [ ] API server running: `python EnhancedPipeline/rest_api.py --port 5001`
- [ ] Demo PCAPs ready: `LiveTraffic/demo_pcaps/normal.pcap`, `attack.pcap`, `borderline.pcap`
- [ ] Run `python -m tests.test_pipeline` — all 27 tests pass
