# 🛡️ Aruba 2920-24G (J9726A) — Live Traffic Testing Guide
**Explainable AI-Driven Zero-Trust Anomaly Detection for Encrypted Traffic**
**University of Peradeniya | E/20/420 Janith | E/20/449 Sandaru | E/20/288 Chalaka**
**Date: 2026-03-10**

---

## Table of Contents
1. [Hardware Setup & Network Topology](#1-hardware-setup--network-topology)
2. [Phase 1: Factory Reset the Switch](#2-phase-1-factory-reset-the-switch)
3. [Phase 2: Basic Switch Configuration](#3-phase-2-basic-switch-configuration)
4. [Phase 3: OpenFlow SDN Configuration](#4-phase-3-openflow-sdn-configuration)
5. [Phase 4: SDN Controller Setup (Laptop)](#5-phase-4-sdn-controller-setup-laptop)
6. [Phase 5: Verify OpenFlow Connection](#6-phase-5-verify-openflow-connection)
7. [Phase 6: Generate Traffic](#7-phase-6-generate-traffic)
8. [Phase 7: Run the Full Pipeline](#8-phase-7-run-the-full-pipeline)
9. [Phase 8: Measure Speed & Collect Results](#9-phase-8-measure-speed--collect-results)
10. [Troubleshooting](#10-troubleshooting)
11. [Quick Reference Card](#11-quick-reference-card)

---

## 1. Hardware Setup & Network Topology

### Physical Connections

```
┌─────────────────────────────────────────────────────────────┐
│                    Aruba 2920-24G (J9726A)                  │
│                                                              │
│  Port 1         Port 2         Port 24       Console        │
│  ┌──┐           ┌──┐           ┌──┐          ┌──┐          │
│  │  │           │  │           │  │          │  │          │
│  └┬─┘           └┬─┘           └┬─┘          └┬─┘          │
│   │               │               │              │           │
└───┼───────────────┼───────────────┼──────────────┼───────────┘
    │               │               │              │
    │               │               │              │
┌───▼───┐     ┌────▼────┐    ┌─────▼──────┐   Console Cable
│Host A │     │ Host B  │    │ SDN Laptop │   (Serial/USB-B)
│(Benign│     │(Attack  │    │ (Controller│
│ +Atk) │     │ Target) │    │ + Pipeline)│
│       │     │         │    │            │
│10.0.0.2│    │10.0.0.3 │    │ 10.0.0.1   │
└───────┘     └─────────┘    └────────────┘
```

### What Each Machine Does

| Machine | Port | IP Address | Role |
|---------|:----:|-----------|------|
| **Host A** | Port 1 | 10.0.0.2/24 | Generate benign traffic + attack traffic |
| **Host B** | Port 2 | 10.0.0.3/24 | Target for attacks / benign traffic partner |
| **SDN Laptop** | Port 24 | 10.0.0.1/24 | OpenFlow controller + anomaly detection pipeline |
| **Console** | Console port | — | Switch management via serial cable |

### Cable Connections
1. **Ethernet cable** from Host A → Switch Port 1
2. **Ethernet cable** from Host B → Switch Port 2
3. **Ethernet cable** from SDN Laptop → Switch Port 24
4. **Console cable** (RJ45-to-USB or DB9) from Switch Console → SDN Laptop (or any machine)

---

## 2. Phase 1: Factory Reset the Switch

### Option A: CLI Reset (via Console Cable)

Connect the console cable from the switch to a machine (can be the SDN Laptop):

```bash
# On the machine connected to the console cable:
# If using USB-to-serial adapter:
sudo minicom -b 9600 -D /dev/ttyUSB0

# If using screen:
sudo screen /dev/ttyUSB0 9600

# Press Enter to get a prompt
```

Once connected to the switch CLI:

```
# Login (default: no password or username 'manager')
# Press Enter at the password prompt if never set

# Full factory reset:
switch# erase startup-config

# When prompted: "Configuration will be deleted, management 
#                  modules will be rebooted. Continue [y/n]?"
# Type: y

# The switch will reboot with factory defaults.
# Wait ~2 minutes for reboot to complete.
```

### Option B: Physical Reset (No Console Needed)

1. Locate **Reset** and **Clear** holes on the front panel
2. Insert pins into **both** holes simultaneously
3. Release **Reset** while keeping **Clear** held
4. Wait until the **Test LED blinks rapidly**
5. Release **Clear** — switch reboots to factory defaults

### Verify Factory Reset

After reboot, reconnect via console:
```
# The switch should show:
HP-2920-24G# show vlans

 Status and Counters - VLAN Information

  VLAN ID  Name          Status    Voice Jumbo
  ------- ------------- --------- ----- -----
  1       DEFAULT_VLAN  Port-based No    No

# Only VLAN 1 should exist — clean state!
```

---

## 3. Phase 2: Basic Switch Configuration

### Set IP Address and Hostname

```
HP-2920-24G# configure

# Set hostname
switch(config)# hostname ZT-SWITCH

# Assign management IP on VLAN 1
ZT-SWITCH(config)# vlan 1
ZT-SWITCH(vlan-1)# ip address 10.0.0.100 255.255.255.0
ZT-SWITCH(vlan-1)# exit

# Verify all ports are in VLAN 1 (should be by default)
ZT-SWITCH(config)# show vlans ports 1-24

# Save configuration
ZT-SWITCH(config)# write memory
```

### Verify Connectivity

On each host, set static IPs:

```bash
# On Host A:
sudo ip addr add 10.0.0.2/24 dev eth0
sudo ip link set eth0 up

# On Host B:
sudo ip addr add 10.0.0.3/24 dev eth0
sudo ip link set eth0 up

# On SDN Laptop:
sudo ip addr add 10.0.0.1/24 dev eth0    # or your NIC name
sudo ip link set eth0 up
```

Test connectivity:
```bash
# From Host A:
ping -c 3 10.0.0.3    # Should reach Host B
ping -c 3 10.0.0.1    # Should reach SDN Laptop
ping -c 3 10.0.0.100  # Should reach Switch management
```

---

## 4. Phase 3: OpenFlow SDN Configuration

### Enable OpenFlow on the Switch

```
ZT-SWITCH# configure

# Enable OpenFlow globally
ZT-SWITCH(config)# openflow

# Set the controller (SDN Laptop's IP)
ZT-SWITCH(of-cfg)# controller-id 1 ip 10.0.0.1 controller-interface vlan 1

# Configure OpenFlow instance
ZT-SWITCH(of-cfg)# instance ZeroTrust
ZT-SWITCH(of-inst-ZeroTrust)# controller-id 1
ZT-SWITCH(of-inst-ZeroTrust)# version 1.3

# Assign VLANs and ports to OpenFlow
ZT-SWITCH(of-inst-ZeroTrust)# member vlan 1
ZT-SWITCH(of-inst-ZeroTrust)# enable
ZT-SWITCH(of-inst-ZeroTrust)# exit

ZT-SWITCH(of-cfg)# exit

# IMPORTANT: Set the OpenFlow listener port (default 6633)
# The switch will connect TO the controller

# Save
ZT-SWITCH(config)# write memory
```

### Alternative: Simpler Port-Mirroring Mode

If OpenFlow is not needed (passive monitoring only):

```
ZT-SWITCH# configure

# Create mirror session — mirror ports 1-2 to port 24 (SDN Laptop)
ZT-SWITCH(config)# mirror 1 port 24
ZT-SWITCH(config)# interface 1
ZT-SWITCH(eth-1)# monitor
ZT-SWITCH(eth-1)# exit
ZT-SWITCH(config)# interface 2
ZT-SWITCH(eth-2)# monitor
ZT-SWITCH(eth-2)# exit

ZT-SWITCH(config)# write memory
```

### Verify OpenFlow Configuration

```
ZT-SWITCH# show openflow
ZT-SWITCH# show openflow controllers
ZT-SWITCH# show openflow instance ZeroTrust
ZT-SWITCH# show openflow flows
```

Expected:
```
 OpenFlow
  Admin State     : Enabled
  
  Instance "ZeroTrust"
  Controller ID 1: 10.0.0.1  Protocol: TCP  Port: 6633
  OF Version: 1.3
  Member VLANs: 1
  Admin: Enabled
  Connection: Established    ← This means it connected to your controller!
```

---

## 5. Phase 4: SDN Controller Setup (Laptop)

### Install Dependencies (on SDN Laptop)

```bash
# Navigate to the project
cd /scratch1/e20-fyp-xai-anomaly-detection/e20420Janith/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic

# Activate virtual environment
source /scratch1/e20-fyp-xai-anomaly-detection/.venv/bin/activate

# Install required packages
pip install nfstream scapy

# Install dpkt and lime to tmp
pip install --target /tmp/dpkt_pkg dpkt
pip install --target /tmp/lime_pkg lime

# Install Ryu (OpenFlow controller) — requires Python ≤ 3.10
# If your Python is > 3.10, create a separate venv:
pip install ryu 2>/dev/null || echo "If Ryu fails, use port-mirroring mode instead"
```

### Set Up Network Interface

```bash
# Find your NIC name (connected to Switch Port 24)
ip link show
# Look for the interface that is UP and connected — usually eth0, enp3s0, etc.

# Set IP (replace eth0 with your NIC)
sudo ip addr flush dev eth0
sudo ip addr add 10.0.0.1/24 dev eth0
sudo ip link set eth0 up

# Enable promiscuous mode (so we capture ALL traffic from the switch)
sudo ip link set eth0 promisc on

# Verify
ip addr show eth0 | head -5
# Should show 10.0.0.1/24 and PROMISC flag
```

---

## 6. Phase 5: Verify OpenFlow Connection

### Start the Controller

```bash
# Terminal 1: Start the OpenFlow controller
cd /scratch1/e20-fyp-xai-anomaly-detection/e20420Janith/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic

source /scratch1/e20-fyp-xai-anomaly-detection/.venv/bin/activate

python src/LiveTraffic/openflow_controller.py --cmd_port 6634

# You should see:
# "Command server listening on 127.0.0.1:6634"
# "Starting Ryu OpenFlow controller..."
# "Switch connected: dpid=0x..."   ← Switch is talking to us!
```

If Ryu is not installed, the controller will run in stub mode (logs DROP commands but doesn't install OpenFlow rules). This is fine for testing — you can still capture and classify traffic.

### Verify on Switch

```
ZT-SWITCH# show openflow controllers
# Should show: Connection = Established
```

### Quick Traffic Test

```bash
# Terminal 2 on SDN Laptop: verify you see traffic
sudo tcpdump -i eth0 -n -c 20
# Should show real packets from Host A and Host B

# From Host A, ping Host B:
ping -c 5 10.0.0.3
# You should see the ICMP packets in tcpdump on the SDN Laptop
```

---

## 7. Phase 6: Generate Traffic

### A. Benign Traffic (from Host A)

```bash
# ─── Option 1: Normal web browsing simulation ───
# On Host B, start a simple HTTP server:
python3 -m http.server 80

# On Host A, generate HTTP traffic:
for i in $(seq 1 100); do
    curl -s -o /dev/null http://10.0.0.3/
    sleep 0.$(( RANDOM % 5 + 1 ))
done

# ─── Option 2: Mixed benign traffic (DNS + HTTP + SSH) ───
# On Host A:
# DNS queries
for i in $(seq 1 50); do dig @8.8.8.8 example.com +short 2>/dev/null; sleep 0.2; done &

# HTTP downloads
for i in $(seq 1 30); do wget -q -O /dev/null http://10.0.0.3/ 2>/dev/null; sleep 0.5; done &

# SSH connections (if Host B has sshd)
# ssh -o StrictHostKeyChecking=no user@10.0.0.3 "uptime" 2>/dev/null &

# ─── Option 3: iperf bandwidth test (sustained traffic) ───
# Host B:
iperf3 -s -p 5201

# Host A:
iperf3 -c 10.0.0.3 -p 5201 -t 60 -b 10M
```

### B. Attack Traffic (from Host A → Host B)

```bash
# ─── Using our traffic generator (Scapy) ───
cd /scratch1/e20-fyp-xai-anomaly-detection/e20420Janith/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic

# SYN Flood
sudo python3 src/LiveTraffic/traffic_generator.py \
    --mode attack --count 10 --interface eth0

# Normal traffic (for comparison)
sudo python3 src/LiveTraffic/traffic_generator.py \
    --mode normal --count 20 --interface eth0

# Borderline traffic (tests DDL vs BCC disagreements)
sudo python3 src/LiveTraffic/traffic_generator.py \
    --mode borderline --count 5 --interface eth0

# ─── Using hping3 (DDoS simulation) ───
# Install: sudo apt install hping3

# SYN flood to Host B port 80:
sudo hping3 -S --flood -p 80 10.0.0.3 &
PID_FLOOD=$!
sleep 10
kill $PID_FLOOD

# Port scan:
sudo hping3 -S 10.0.0.3 --scan 1-100 -i u100

# ─── Using nmap (Port Scan) ───
# SYN scan:
sudo nmap -sS -p 1-1024 10.0.0.3

# Aggressive scan:
sudo nmap -A -T4 10.0.0.3

# ─── Using slowloris (Slow HTTP DoS) ───
pip install slowloris
slowloris 10.0.0.3 -p 80 -s 200
```

### C. Mixed Workload (Realistic Scenario)

Run benign and attack traffic simultaneously to simulate real network:

```bash
# Terminal 1 (Host A): Benign background traffic
while true; do
    curl -s -o /dev/null http://10.0.0.3/ 2>/dev/null
    sleep 0.$((RANDOM % 3 + 1))
done &
BENIGN_PID=$!

# Terminal 2 (Host A): Attack traffic after 30 seconds
sleep 30
echo "Starting attacks..."
sudo hping3 -S --flood -p 80 10.0.0.3 &
ATTACK_PID=$!
sleep 20
kill $ATTACK_PID

# Terminal 3 (Host A): Port scan
sudo nmap -sS 10.0.0.3 -p 1-100 &

# After test:
kill $BENIGN_PID
```

---

## 8. Phase 7: Run the Full Pipeline

### Option A: Live Capture Mode (Port Mirroring)

```bash
# On SDN Laptop — Terminal 1: Start the pipeline
cd /scratch1/e20-fyp-xai-anomaly-detection/e20420Janith/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic

source /scratch1/e20-fyp-xai-anomaly-detection/.venv/bin/activate
export PYTHONPATH=/tmp/dpkt_pkg:/tmp/lime_pkg:$PYTHONPATH

# Run live pipeline with DDL model (replace eth0 with your NIC)
python src/LiveTraffic/live_pipeline.py \
    --interface eth0 \
    --duration 300 \
    --ddl_model models/ddl_40feat.pkl \
    --log_path logs/live_test_$(date +%Y%m%d_%H%M).json

# The pipeline will:
#   1. Capture flows via NFStream
#   2. Extract 40 DDL features per terminated flow
#   3. Run DDL anomaly detection
#   4. Run XAI explanation on anomalies
#   5. Print results every 30 seconds
#   6. Save decision log to JSON
```

### Option B: OpenFlow Mode (Active DROP)

```bash
# Terminal 1: Start OpenFlow controller
python src/LiveTraffic/openflow_controller.py --cmd_port 6634

# Terminal 2: Start pipeline connected to controller
python src/LiveTraffic/live_pipeline.py \
    --interface eth0 \
    --duration 300 \
    --ddl_model models/ddl_40feat.pkl \
    --openflow_host 127.0.0.1 \
    --openflow_port 6634 \
    --log_path logs/live_openflow_$(date +%Y%m%d_%H%M).json

# Now when the pipeline detects an anomaly:
#   → Sends DROP command to the controller
#   → Controller installs OpenFlow DROP rule on the switch
#   → Switch physically blocks the malicious flow!
```

### Option C: Demo Mode (No Switch Needed)

```bash
# Quick test without any hardware:
python src/LiveTraffic/live_pipeline.py \
    --demo \
    --duration 60 \
    --ddl_model models/ddl_40feat.pkl \
    --log_path logs/demo_test.json
```

---

## 9. Phase 8: Measure Speed & Collect Results

### During the Test

The pipeline prints live stats every 30 seconds:
```
[14:32:00] Pipeline Status:
  Flows seen:       847
  DDL normal:       721 (85.1%) → FORWARD
  DDL anomaly:       126 (14.9%) → DROP
  Errors:            0
  Avg DDL latency:   0.15ms
```

### After the Test

```bash
# View the decision log
cat logs/live_test_*.json | python3 -m json.tool | head -50

# Extract metrics
python3 -c "
import json
with open('logs/live_test_*.json') as f:
    data = json.load(f)
s = data['stats']
print(f'Total flows: {s[\"flows_seen\"]}')
print(f'Normal (FORWARD): {s[\"ddl_normal\"]}')
print(f'Anomaly (DROP): {s[\"ddl_anomaly\"]}')
print(f'Errors: {s[\"errors\"]}')
print()
print('Timing:')
for stage, info in data['timing_profile'].items():
    print(f'  {stage}: mean={info[\"mean_ms\"]:.2f}ms, p99={info[\"p99_ms\"]:.2f}ms')
"
```

### Measure Throughput

```bash
# While pipeline is running, in a separate terminal:
# Count flows per second
watch -n 5 'wc -l /tmp/flow_count.txt 2>/dev/null || echo "Counting..."'

# Measure network throughput
iftop -i eth0 -t -s 10

# Measure CPU usage of the pipeline
top -p $(pgrep -f live_pipeline) -d 1
```

### Export Results for Documentation

```bash
# Generate a results summary
python3 << 'EOF'
import json, glob, os

log_files = sorted(glob.glob("logs/live_*.json"))
for lf in log_files:
    with open(lf) as f:
        data = json.load(f)
    s = data["stats"]
    total = s["flows_seen"]
    if total == 0: continue
    print(f"\n=== {os.path.basename(lf)} ===")
    print(f"  Flows: {total}")
    print(f"  FORWARD: {s['ddl_normal']} ({s['ddl_normal']/total*100:.1f}%)")
    print(f"  DROP: {s['ddl_anomaly']} ({s['ddl_anomaly']/total*100:.1f}%)")
    print(f"  Errors: {s['errors']}")
    
    # XAI examples
    drops = [d for d in data.get("decisions", []) if d["action"] == "DROP"]
    if drops:
        print(f"\n  Sample DROP decisions ({min(3, len(drops))}):")
        for d in drops[:3]:
            print(f"    {d['flow_id']}: score={d['ddl_score']}, XAI={d.get('xai_summary','')[:80]}")
EOF
```

---

## 10. Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| Console shows nothing | Wrong baud rate | Use 9600 baud, 8N1 |
| `erase startup-config` fails | Not in manager/enable mode | Type `enable` first |
| Switch won't connect to controller | Wrong IP or firewall | `ping 10.0.0.1` from switch; check `iptables -L` on laptop |
| OpenFlow shows "Not Connected" | Controller not running | Start `openflow_controller.py` first, then enable OpenFlow on switch |
| `tcpdump` shows no traffic | Mirroring not configured | Check `show mirror` on switch |
| NFStream sees 0 flows | Wrong interface name | Run `ip link show` to find correct NIC |
| "Permission denied" on capture | Not root | Use `sudo` for tcpdump/nfstream |
| No attack detection | DDL model not loaded | Check `--ddl_model models/ddl_40feat.pkl` path |
| Switch hangs after OpenFlow | Controller crashed | Restart controller; switch auto-reconnects |
| Ryu import error | Ryu needs Python ≤ 3.10 | Use port-mirroring mode instead |
| Hosts can't ping each other | Wrong VLAN or IP | Verify all hosts are in VLAN 1, subnet 10.0.0.0/24 |
| Port mirroring floods | Destination port in VLAN | Remove mirror port from VLAN: `no vlan 1 tagged 24` |

---

## 11. Quick Reference Card

### Switch Reset
```
enable → erase startup-config → y → wait for reboot
```

### Switch Config (Basic + OpenFlow)
```
configure
  hostname ZT-SWITCH
  vlan 1
    ip address 10.0.0.100 255.255.255.0
    exit
  openflow
    controller-id 1 ip 10.0.0.1 controller-interface vlan 1
    instance ZeroTrust
      controller-id 1
      version 1.3
      member vlan 1
      enable
      exit
    exit
  write memory
```

### Switch Config (Port Mirroring Only)
```
configure
  mirror 1 port 24
  interface 1
    monitor
    exit
  interface 2
    monitor
    exit
  write memory
```

### Controller + Pipeline
```bash
# Terminal 1: Controller
python src/LiveTraffic/openflow_controller.py --cmd_port 6634

# Terminal 2: Pipeline  
python src/LiveTraffic/live_pipeline.py --interface eth0 --duration 300 \
    --ddl_model models/ddl_40feat.pkl --openflow_host 127.0.0.1 --openflow_port 6634

# Terminal 3: Attack traffic (from Host A)
sudo hping3 -S --flood -p 80 10.0.0.3
```

### Verify Everything Works
```bash
# On switch: show openflow controllers    → Connection: Established
# On laptop: sudo tcpdump -i eth0 -c 10   → See traffic
# Pipeline output: DROP/FORWARD decisions  → Classification working
```

---

## Important Notes

1. **OpenFlow vs Port Mirroring:**
   - **OpenFlow** = Active mode. The controller can install DROP rules on the switch to physically block traffic. Requires Ryu (Python ≤ 3.10).
   - **Port Mirroring** = Passive mode. The pipeline sees all traffic but can only log decisions (cannot enforce DROP on the switch). Works with any Python version.

2. **For your demo:** Start with port mirroring (simpler, always works). Graduate to OpenFlow for the final demonstration.

3. **Timing:** In the live pipeline, feature extraction takes ~50µs (from OpenFlow PacketIN events, not PCAP files), making it much faster than the PCAP simulation timing.

4. **The full 702K PCAP simulation is running** — when it completes, the results will be at:
   ```
   results/pcap_results/full_pipeline_results.md
   results/pcap_results/full_results.json
   ```
   Check progress: `tail -5 /tmp/full_sim_all.txt`
