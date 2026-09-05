# Live Traffic Guide — All Methods

This guide covers every method available to test the pipeline with live or
simulated traffic, from lowest-effort to highest-realism.

---

## Method 1 — Demo Mode (No Hardware, No Root)

Generates synthetic NFStream-like flow objects in Python.

**Use when:** No switch, no PCAP files, just testing the pipeline logic.

```bash
python LiveTraffic/live_pipeline.py --demo --duration 60
```

Expected output:
```
[LivePipeline] Demo mode: 120 synthetic flows (20% attacks)
[LivePipeline] Flows seen: 120
[LivePipeline] DDL normal: 96 (80.0%) → FORWARD
[LivePipeline] DDL anomaly: 24 (20.0%) → DROP
Avg DDL latency: ~45ms
```

---

## Method 2 — PCAP Replay (Labeled, Per-Flow Accuracy)

Uses labeled CIC-IDS-2017 PCAPs. NFStream processes each PCAP offline.
Ground truth available from folder names (Row_X_BENIGN, Row_X_DDoS, etc.)

**Use when:** You want to measure actual F1/Precision/Recall.

```bash
# Friday (DDoS + Bot + PortScan + BENIGN):
python LiveTraffic/pcap_replay_pipeline.py \
    --mode labeled \
    --pcap-dir /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/Friday \
    --ddl-model models/ddl_40feat.pkl \
    --output logs/test_friday.json \
    --max-files 2000

# All days (takes ~30min for full Friday's 122k flows):
for day in Monday Tuesday Wednesday Thursday Friday; do
    python LiveTraffic/pcap_replay_pipeline.py \
        --mode labeled \
        --pcap-dir /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/$day \
        --ddl-model models/ddl_40feat.pkl \
        --output logs/test_${day,,}.json
done
```

---

## Method 3 — PCAP Replay (Full-Day, Real-World Mix)

Uses the full-day PCAP files (Monday–Friday). These contain the original
mixed traffic — normal business hours traffic mixed with attacks.

**Use when:** You want to simulate what the pipeline would see in production
(no pre-sliced flows, realistic timing, mixed normal+attack).

```bash
# Friday (attacks 10:02–11:15am + normal):
python LiveTraffic/pcap_replay_pipeline.py \
    --mode fullday \
    --pcap-file /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Friday-WorkingHours.pcap \
    --ddl-model models/ddl_40feat.pkl \
    --output logs/fullday_friday.json

# Monday (all BENIGN — to verify false positive rate):
python LiveTraffic/pcap_replay_pipeline.py \
    --mode fullday \
    --pcap-file /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Monday-WorkingHours.pcap \
    --ddl-model models/ddl_40feat.pkl \
    --output logs/fullday_monday.json
```

---

## Method 4 — tcpreplay (Wire Replay with Real Packets)

Replays PCAP files on the actual network interface. The switch mirror port
will capture these packets as if they were real traffic.

**Use when:** You have the switch set up and want to replay real CIC-IDS-2017
packets over the wire.

```bash
# Prerequisites:
sudo tcpreplay --version    # must be installed: sudo apt install tcpreplay

# Replay CIC-IDS-2017 Friday PCAP at 10 Mbps:
# (run from Laptop A, capture on Laptop B via switch mirror)
sudo tcpreplay \
    --intf=eth0 \
    --mbps=10 \
    /scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Friday-WorkingHours.pcap

# Meanwhile, on Laptop B (pipeline machine):
python LiveTraffic/live_pipeline.py \
    --interface eth1 \
    --ddl_model models/ddl_40feat.pkl \
    --duration 600
```

---

## Method 5 — Synthetic Traffic Generator (scapy)

Generates crafted attack/normal/borderline PCAP files using scapy.

**Use when:** You want specific attack patterns (SYN flood, port scan) without
needing the full PCAP files. Good for demo.

```bash
# Generate PCAPs (no root needed):
python LiveTraffic/traffic_generator.py \
    --mode normal --count 30 --output /tmp/demo_normal.pcap
python LiveTraffic/traffic_generator.py \
    --mode attack --count 20 --output /tmp/demo_attack.pcap
python LiveTraffic/traffic_generator.py \
    --mode borderline --count 10 --output /tmp/demo_borderline.pcap

# View in Wireshark:
wireshark /tmp/demo_attack.pcap &

# Replay on wire (root needed, send through switch):
sudo tcpreplay -i eth0 --mbps=1 /tmp/demo_attack.pcap
```

---

## Method 6 — Live Interface Capture (Physical Switch)

The most realistic method. Traffic from the switch mirror port is captured by
NFStream in real-time and processed by the pipeline.

**Prerequisites:** See `docs/setup/switch-cisco.md` or `docs/setup/switch-hp-procurve.md`.

```bash
# Step 1: Configure switch SPAN (see switch guide)
# Step 2: Enable promiscuous mode
sudo ip link set eth1 promisc on
# Verify capture:
sudo tcpdump -i eth1 -n -c 10

# Step 3: Start pipeline on mirror port
python LiveTraffic/live_pipeline.py \
    --interface eth1 \
    --ddl_model models/ddl_40feat.pkl \
    --duration 300

# Step 4 (optional): Connect to REST API
python EnhancedPipeline/rest_api.py --port 5001 &
python LiveTraffic/live_pipeline.py \
    --interface eth1 \
    --ddl_model models/ddl_40feat.pkl \
    --api http://localhost:5001 \
    --duration 300
```

---

## Decision Matrix

| Method | Hardware needed | Ground truth | Realistic? | Recommended for |
|--------|----------------|-------------|-----------|----------------|
| 1. Demo mode | None | Synthetic | Low | Quick smoke test |
| 2. Labeled PCAP | None | ✅ Per-flow | Medium | Accuracy measurement |
| 3. Full-day PCAP | None | ❌ None | High | Demo preparation |
| 4. tcpreplay | Switch | ❌ None | Very high | Pre-demo rehearsal |
| 5. Synthetic scapy | Optional | Synthetic | Medium | Demo injection |
| 6. Live interface | Switch + mirror | ❌ None | Highest | Live demo |

**Recommendation:**
- Pre-demo: Methods 2 + 3 for accuracy metrics
- Demo day: Method 6 with Method 5 for injecting visible attack traffic
- Fallback if switch unavailable: Method 3 (fullday PCAP replay)

---

## NFStream Flow Timeout Settings

| Setting | Default | Effect |
|---------|---------|--------|
| `idle_timeout=15` | 15s | Flow closes after 15s of inactivity |
| `active_timeout=120` | 120s | Forces close of very long flows |

For DDoS testing, reduce `idle_timeout=5` to get flow decisions faster:
```bash
python LiveTraffic/live_pipeline.py \
    --interface eth1 \
    --idle_timeout 5 \
    --ddl_model models/ddl_40feat.pkl
```
