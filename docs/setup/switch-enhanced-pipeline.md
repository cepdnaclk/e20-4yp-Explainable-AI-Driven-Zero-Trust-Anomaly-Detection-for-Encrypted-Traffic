# EnhancedPipeline/docs/SWITCH_SETUP.md
# Physical Switch Setup for the Enhanced Pipeline
# Zero-Trust XAI Anomaly Detection | University of Peradeniya
# e20420Janith

# Physical Switch Setup — Enhanced Pipeline

This document describes how to wire up the physical switch so live traffic
is passively captured by the Enhanced Pipeline on a laptop.

> **Full per-switch CLI guides are in `LiveTraffic/`:**
> - `docs/setup/switch-cisco.md` — Cisco IOS/IOS-XE SPAN commands
> - `docs/setup/switch-hp-procurve.md` — HP ProCurve / Aruba mirroring commands
> - `docs/setup/switch-overview.md` — General guide for any switch

---

## Physical Topology

```
┌─────────────────────────────────────────────────────┐
│                  DEMO ENVIRONMENT                    │
│                                                      │
│  [Laptop A]──────┐                                   │
│  Traffic Source  │ (eth0 or crossover to switch)     │
│                  │                                   │
│                  ▼                                   │
│          ┌───────────────┐                           │
│          │  Cisco / HP   │                           │
│          │   L3 Switch   │                           │
│          │               │                           │
│          │  Port 1  ←── Traffic from Laptop A        │
│          │  Port 24 ──▶ Mirror/SPAN port             │
│          └──────┬────────┘                           │
│                 │ (SPAN destination)                  │
│                 ▼                                     │
│          [Laptop B — Pipeline]                        │
│            eth1 (NIC in promiscuous mode)             │
│            NFStream captures all mirrored frames      │
│                 │                                     │
│          ┌──────┴──────────────────────────────┐     │
│          │  Enhanced Pipeline running on B      │     │
│          │  - live_pipeline.py (NFStream)       │     │
│          │  - enhanced_pipeline.py (DDL+IF+XAI) │     │
│          │  - dashboard.py (Streamlit browser)  │     │
│          │  - rest_api.py  (optional)           │     │
│          └─────────────────────────────────────┘     │
│                                                      │
│  [Laptop C] ─── normal destination (optional)        │
└─────────────────────────────────────────────────────┘
```

---

## Step-by-Step Setup

### 1. Connect the Hardware

1. Connect **Laptop A** (traffic source) to Port 1 of the switch
2. Connect **Laptop B** (pipeline) to Port 24 of the switch (**this is the SPAN destination**)
3. (Optional) Connect Laptop C to another port as the normal destination

### 2. Configure the Switch

**For Cisco:**
```
enable
configure terminal
monitor session 1 source interface GigabitEthernet 0/1 both
monitor session 1 destination interface GigabitEthernet 0/24
end
write memory
```

**For HP/Aruba:**
```
configure
mirror-session 1
source interface 1/1 both
destination interface 1/24
enable
exit
write memory
```

### 3. Configure Laptop B NIC

```bash
# On Laptop B (pipeline machine):
# Identify which NIC is connected to the SPAN port
ip link show

# Enable promiscuous mode (NFStream needs this):
sudo ip link set eth1 promisc on

# Verify:
sudo tcpdump -i eth1 -n -c 5
# You should see traffic from Laptop A's port
```

### 4. Start the Enhanced Pipeline

```bash
# On Laptop B, from project root:
cd ~/e20420Janith/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/
source /scratch1/e20-fyp-xai-anomaly-detection/.venv/bin/activate

# Ensure models are trained first:
ls models/ddl_40feat.pkl          # must exist — see DDLModel/train_ddl_enhanced.py
ls models/isolation_forest.pkl    # must exist

# Terminal 1 — REST API (optional, for dashboard connection)
python EnhancedPipeline/rest_api.py --port 5001

# Terminal 2 — Live dashboard
streamlit run EnhancedPipeline/dashboard.py

# Terminal 3 — Live capture
python LiveTraffic/live_pipeline.py --interface eth1 --duration 600
```

### 5. Generate Demo Traffic (from Laptop A)

```bash
# On Laptop A:
cd ~/e20420Janith/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/
source /scratch1/e20-fyp-xai-anomaly-detection/.venv/bin/activate

# Normal traffic (should all FORWARD):
sudo python LiveTraffic/traffic_generator.py --mode normal --count 20 --interface eth0

# Attack traffic (should DROP with XAI explanation):
sudo python LiveTraffic/traffic_generator.py --mode attack --count 10 --interface eth0

# Borderline traffic (DT flags, DDL clears — shows cascade benefit):
sudo python LiveTraffic/traffic_generator.py --mode borderline --count 5 --interface eth0
```

---

## Pre-Demo Checklist

- [ ] Cisco OR HP switch SPAN session confirmed with `show monitor session 1`
- [ ] `tcpdump -i eth1 -n -c 5` shows traffic on SPAN destination port
- [ ] `models/ddl_40feat.pkl` exists (run `train_ddl_enhanced.py` first)
- [ ] `models/isolation_forest.pkl` exists
- [ ] Streamlit dashboard loads: `http://localhost:8501`
- [ ] REST API health: `curl http://localhost:5001/health` → `{"status":"ok"}`
- [ ] Timing benchmark pre-run: `profiling/results/demo/latency_cdf.png` exists
- [ ] All 3 demo PCAPs generated and ready in `/tmp/demo_{normal,attack,borderline}.pcap`
