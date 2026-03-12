# Inline Bridge Demo — Complete Setup Guide
**Zero-Trust XAI Anomaly Detection for Encrypted Traffic**
**University of Peradeniya | E/20/420 Janith W. | E/20/449 Sandaru W. | E/20/288 Chalaka P.**

---

## Architecture Overview

```
┌─────────────┐     eth0          ┌──────────────────┐     eth1           ┌─────────────────┐
│   PC1       │ ◄── RJ45 ──────► │     PC2          │ ◄── RJ45 ────────► │     PC3         │
│  (Shooter)  │  10.0.0.2/24     │  (AI Gatekeeper) │  10.0.1.1/24      │   (Receiver)    │
│             │                  │  10.0.0.1/24     │                   │   10.0.1.2/24   │
│  Replays    │                  │                  │                   │                 │
│  .pcap      │  ─── UDP ──────► │  BCC → DDL+IF    │  ─── Scapy ─────► │  Counts arrived │
│  streams    │  ─── Scapy ────► │  + LIME XAI      │  (if clean)       │  packets        │
│             │                  │  + InfluxDB      │                   │  + InfluxDB     │
│             │  ─── UDP ─────────────────────────────── UDP ──────────► │                 │
└─────────────┘                  └──────────────────┘                   └─────────────────┘
                                        │
                                   InfluxDB v2
                                   + Grafana
                                  (Monitoring)
```

### Three-Plane Design:
| Plane | Protocol | Purpose |
|-------|----------|---------|
| **Control** | UDP:5005 | PC1 sends `START`/`END` JSON messages to PC2 & PC3 for each stream |
| **Data** | Scapy (L2) | PC1 injects raw packets → PC2 inspects → forwards clean to PC3 |
| **Telemetry** | InfluxDB v2 | All 3 PCs log timestamps, predictions, latency to centralized DB |

### Zero Trust Principle:
> **No traffic is inherently trusted.** Every flow passing through PC2 is verified by the
> AI pipeline. Clean flows are **explicitly ALLOWED** after BCC + DDL/IF verification.
> Suspicious flows are **DROPPED** and explained with LIME XAI.

---

## Prerequisites

### Hardware
| Item | Description |
|------|------------|
| PC1 (Shooter) | Any laptop with Ethernet port |
| PC2 (Gatekeeper) | Laptop with **built-in Ethernet + USB-Ethernet adapter** |
| PC3 (Receiver) | Any laptop with Ethernet port |
| Cables | 2x RJ45 Ethernet cables |

### Software (All PCs)
- Linux (Ubuntu 22.04+ recommended, Kali Linux also works)
- Python 3.8+
- Root/sudo access

---

## Step 1: Get the Files to Your Local Machine

### Option A: Clone from GitHub (if pushed)
```bash
git clone https://github.com/cepdnaclk/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic.git
cd e20-4yp-.../InlineBridgeDemo
```

### Option B: Copy from Department Server via SCP
```bash
# From your local laptop (replace IP with your server's IP):
bash scripts/copy_from_server.sh e20420@10.12.70.3

# Or manually:
scp -r e20420@10.12.70.3:/scratch1/e20-fyp-xai-anomaly-detection/e20420Janith/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/InlineBridgeDemo ~/InlineBridgeDemo

# Copy PCAP data (at minimum the Friday folder):
scp -r e20420@10.12.70.3:/scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/Friday ~/InlineBridgeDemo/pcap_data/
```

### What You Need on Each PC:

| PC | Files Needed |
|----|-------------|
| **PC1** | `pc1_shooter.py`, `scripts/setup_host_a.sh`, PCAP data folder |
| **PC2** | Entire `InlineBridgeDemo/` folder (scripts + models + lib) |
| **PC3** | `pc3_receiver.py`, `scripts/setup_host_b.sh` |

---

## Step 2: Install Dependencies

### On PC2 (Gatekeeper — full install):
```bash
cd ~/InlineBridgeDemo
bash install_dependencies.sh pc2
source .venv/bin/activate

# Verify:
python3 -c "import joblib, numpy, lime, scapy; print('All OK')"
```

### On PC1 (Shooter — minimal):
```bash
cd ~/InlineBridgeDemo  # or wherever you copied pc1_shooter.py
bash install_dependencies.sh pc1
source .venv/bin/activate
```

### On PC3 (Receiver — minimal):
```bash
cd ~/InlineBridgeDemo  # or wherever you copied pc3_receiver.py
bash install_dependencies.sh pc3
source .venv/bin/activate
```

---

## Step 3: Physical Cable Connections

```
PC1 ──[RJ45 cable]──► PC2 (built-in Ethernet port = eth0)
PC3 ──[RJ45 cable]──► PC2 (USB-Ethernet adapter   = eth1)
```

### Identify Your Interfaces on PC2:
```bash
# List all network interfaces:
ip link show

# Common names:
#   Built-in Ethernet: eth0, enp0s25, eno1
#   USB-Ethernet:      eth1, enx..., enp0s20u1
```

> **IMPORTANT:** Edit the interface names in `scripts/setup_bridge.sh` if they differ
> from `eth0`/`eth1`. Check with `ip link show` after plugging in cables.

---

## Step 4: Network Configuration

### On PC2 (Gatekeeper):
```bash
# Edit interface names if needed (default: eth0 and eth1):
sudo bash scripts/setup_bridge.sh up

# Verify:
sudo bash scripts/setup_bridge.sh status
```

### On PC1 (Shooter):
```bash
# Edit interface name if needed (default: eth0):
sudo bash scripts/setup_host_a.sh up

# Test connectivity to PC2:
ping 10.0.0.1
```

### On PC3 (Receiver):
```bash
# Edit interface name if needed (default: eth0):
sudo bash scripts/setup_host_b.sh up

# Test connectivity to PC2:
ping 10.0.1.1
```

### Verify End-to-End Connectivity:
```bash
# From PC1, ping PC3 through PC2:
ping 10.0.1.2
# This should work — packets are routed through PC2
```

---

## Step 5: Set Up InfluxDB + Grafana (on PC2)

### Install InfluxDB v2:
```bash
# Download
wget https://dl.influxdata.com/influxdb/releases/influxdb2-2.7.1_linux_amd64.tar.gz
tar xvzf influxdb2-*.tar.gz
sudo cp influxdb2-*/influxd /usr/local/bin/

# Start InfluxDB:
influxd &

# Open browser: http://localhost:8086
# Initial setup:
#   Username: admin
#   Password: password123
#   Organization: uop
#   Bucket: sdn_telemetry
#   → Copy the generated API token!
```

### Configure Environment:
```bash
# Set on ALL 3 PCs (or export before running scripts):
export INFLUXDB_URL="http://10.0.0.1:8086"   # PC2's IP (or localhost on PC2)
export INFLUXDB_TOKEN="your-api-token-here"
export INFLUXDB_ORG="uop"
export INFLUXDB_BUCKET="sdn_telemetry"
```

### Install Grafana:
```bash
# Download
wget https://dl.grafana.com/oss/release/grafana-10.2.3.linux-amd64.tar.gz
tar xvzf grafana-*.tar.gz
cd grafana-*/
./bin/grafana-server &

# Open browser: http://localhost:3000
# Login: admin / admin
```

### Configure Grafana Dashboard:
1. Go to **Configuration → Data Sources → Add data source**
2. Select **InfluxDB**
3. Settings:
   - Query Language: **Flux**
   - URL: `http://localhost:8086`
   - Organization: `uop`
   - Token: `<your-api-token>`
   - Default Bucket: `sdn_telemetry`
4. Click **Save & Test**
5. Go to **Dashboards → Import**
6. Upload `grafana/sdn_dashboard.json`
7. The dashboard auto-refreshes every 5 seconds

---

## Step 6: Run the Demo!

### Terminal 1 — PC3 (Receiver): Start first
```bash
cd ~/InlineBridgeDemo
source .venv/bin/activate
export INFLUXDB_URL="http://10.0.0.1:8086"
export INFLUXDB_TOKEN="your-token"

sudo -E python3 pc3_receiver.py --iface eth0
# → "Receiver is ACTIVE. Waiting for packets..."
```

### Terminal 2 — PC2 (Gatekeeper): Start second
```bash
cd ~/InlineBridgeDemo
source .venv/bin/activate
export INFLUXDB_URL="http://localhost:8086"
export INFLUXDB_TOKEN="your-token"

sudo -E python3 pc2_gatekeeper.py --iface-in eth0 --iface-out eth1
# → "Zero Trust Gatekeeper is ACTIVE. Waiting for traffic..."
```

### Terminal 3 — PC1 (Shooter): Start last
```bash
cd ~/InlineBridgeDemo
source .venv/bin/activate
export INFLUXDB_URL="http://10.0.0.1:8086"
export INFLUXDB_TOKEN="your-token"

# Quick test with 20 streams:
sudo -E python3 pc1_shooter.py \
    --pcap-dir ~/InlineBridgeDemo/pcap_data \
    --iface eth0 \
    --pc2-ip 10.0.0.1 \
    --pc3-ip 10.0.1.2 \
    --limit 20

# Full test with all streams:
sudo -E python3 pc1_shooter.py \
    --pcap-dir ~/InlineBridgeDemo/pcap_data \
    --iface eth0 \
    --pc2-ip 10.0.0.1 \
    --pc3-ip 10.0.1.2 \
    --limit 0
```

### Without InfluxDB (simpler):
Add `--no-influxdb` to any script to skip telemetry:
```bash
sudo python3 pc2_gatekeeper.py --iface-in eth0 --iface-out eth1 --no-influxdb
sudo python3 pc1_shooter.py --pcap-dir ./pcap_data --iface eth0 --pc2-ip 10.0.0.1 --pc3-ip 10.0.1.2 --limit 50 --no-influxdb
sudo python3 pc3_receiver.py --iface eth0 --no-influxdb
```

---

## Step 7: View Results

### PC2 Console Output (Real-Time):
```
✅ Friday_Row_471 | GT=normal | Pred=normal | Action=FORWARD | Stage=1 | BCC=0.2308 | Latency=15.2ms | ZeroTrust=VERIFIED_CLEAN
❌ Friday_Row_456 | GT=attack | Pred=attack | Action=DROP    | Stage=2 | BCC=0.9965 | Latency=1250.3ms | ZeroTrust=THREAT_DETECTED
    DDL-LIME: [('bwd_iat_std > 589233.62', 0.082), ...]
    IF-LIME:  [('pkt_len_variance > 3644055', 0.055), ...]
    DDL-SHAP: [('bwd_iat_std', 0.034), ('flow_iat_std', 0.028), ...]
    IF-SHAP:  [('pkt_len_variance', 0.061), ('bwd_pkt_len_std', 0.044), ...]
```

### Grafana Dashboard (http://localhost:3000):
- **Total Streams Processed** counter
- **Attack Detection Rate** counter
- **Pipeline Latency Over Time** graph
- **Stream Event Log** table with all predictions

### Decision Log (JSON):
```bash
cat logs/bridge_decisions.json | python3 -m json.tool | head -50
```

### PC3 Summary (Ctrl+C to see):
```
  Total streams expected:  20
  Streams with packets:    12   ← 12 clean streams forwarded
  Streams blocked (0 pkts): 8   ← 8 attack streams blocked
```

---

## Step 8: Performance Measurement

### Latency Comparison:
```bash
# Test 1: Direct forwarding (no AI pipeline)
# On PC2, just enable IP forwarding without the gatekeeper:
sudo sysctl net.ipv4.ip_forward=1
# From PC1: ping -c 100 10.0.1.2
# Record the average RTT

# Test 2: With AI pipeline active
# Start pc2_gatekeeper.py
# From PC1: ping -c 100 10.0.1.2
# Record the average RTT

# The difference = AI pipeline overhead
```

### Pipeline Timing (from decision log):
```bash
# Average pipeline latency:
python3 -c "
import json
with open('logs/bridge_decisions.json') as f:
    data = json.load(f)
lats = [d['pipeline_latency_ms'] for d in data['decisions']]
print(f'Avg: {sum(lats)/len(lats):.1f} ms')
print(f'Min: {min(lats):.1f} ms')
print(f'Max: {max(lats):.1f} ms')
print(f'Stage 1 only (BCC): {sum(1 for d in data[\"decisions\"] if d[\"stage\"]==\"1\")} flows')
print(f'Stage 2 (DDL+IF): {sum(1 for d in data[\"decisions\"] if d[\"stage\"]==\"2\")} flows')
"
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `ping 10.0.0.1` fails from PC1 | Check cable, run `ip link show`, verify interface name in setup script |
| `ping 10.0.1.2` fails from PC1 | IP forwarding not enabled on PC2, run `sudo bash scripts/setup_bridge.sh up` |
| `No module named 'scapy'` | Activate venv: `source .venv/bin/activate` |
| `Permission denied` on sniff/sendp | Must run with `sudo -E` (the `-E` preserves env vars) |
| `InfluxDB connection refused` | Start InfluxDB: `influxd &`, or use `--no-influxdb` flag |
| PC2 crash on model load | Ensure models/ folder has all 3 .pkl files |
| USB-Ethernet not showing | Check `dmesg | tail`, try `ip link set ethX up` |
| Scripts can't find interface | Run `ip link show` and update interface names in setup scripts |

---

## File Structure

```
InlineBridgeDemo/
├── pc1_shooter.py          ← PC1: replays PCAPs, sends START/END UDP
├── pc2_gatekeeper.py       ← PC2: AI pipeline + forwarding
├── pc3_receiver.py         ← PC3: counts received packets
├── install_dependencies.sh ← Automated dependency installer
├── requirements.txt        ← Python packages
├── models/
│   ├── sentry_model_v2.pkl ← BCC v2 Decision Tree (28 features)
│   ├── ddl_40feat.pkl      ← DDL 2-layer ISTA (40 features)
│   └── isolation_forest.pkl← IF 100-tree ensemble (40 features)
├── lib/
│   ├── ddl_model.py        ← DDL model class
│   ├── ddl_pcap_extractor.py ← 40-feature extractor for DDL
│   └── feature_extractor.py  ← 28-feature extractor for BCC
├── scripts/
│   ├── setup_bridge.sh     ← PC2 network config (IP forwarding)
│   ├── setup_host_a.sh     ← PC1 network config
│   ├── setup_host_b.sh     ← PC3 network config
│   └── copy_from_server.sh ← Download from dept server
├── grafana/
│   └── sdn_dashboard.json  ← Grafana dashboard template
├── logs/
│   ├── bridge_decisions.json ← PC2 decision log (auto-generated)
│   └── receiver_log.json     ← PC3 receiver log (auto-generated)
└── INLINE_BRIDGE_GUIDE.md  ← This file
```

---

## Appendix A: Windows Setup for PC1 (Shooter) and PC3 (Receiver)

> PC2 (Gatekeeper) must run **Linux** (Kali recommended). But PC1 and PC3 can run Windows.

### A.1 — Install Python on Windows

1. Download Python 3.10+ from [python.org](https://www.python.org/downloads/)
2. During install, **check "Add Python to PATH"**
3. Open **PowerShell as Administrator** and verify:
   ```powershell
   python --version
   pip --version
   ```

### A.2 — Install Npcap (Required for Scapy on Windows)

Scapy requires **Npcap** to capture/send packets on Windows:

1. Download Npcap from [npcap.com](https://npcap.com/#download)
2. Install with these options checked:
   - ✅ "Install Npcap in WinPcap API-compatible Mode"
   - ✅ "Support raw 802.11 traffic"
3. Restart your PC after installation

### A.3 — Install Python Dependencies

Open **PowerShell as Administrator**:
```powershell
# Create virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install scapy dpkt numpy

# For InfluxDB telemetry (optional):
pip install influxdb-client
```

### A.4 — Network Configuration on Windows

#### PC1 (Shooter) — Windows:
1. Open **Settings → Network & Internet → Ethernet**
2. Click on your Ethernet adapter → **Edit** (IP assignment)
3. Set to **Manual** and configure:
   - IP: `10.0.0.2`
   - Subnet mask: `255.255.255.0`
   - Gateway: `10.0.0.1`
4. Open **PowerShell as Administrator** and add route:
   ```powershell
   route add 10.0.1.0 mask 255.255.255.0 10.0.0.1
   ```
5. Test: `ping 10.0.0.1`

#### PC3 (Receiver) — Windows:
1. Open **Settings → Network & Internet → Ethernet**
2. Click on your Ethernet adapter → **Edit** (IP assignment)
3. Set to **Manual** and configure:
   - IP: `10.0.1.2`
   - Subnet mask: `255.255.255.0`
   - Gateway: `10.0.1.1`
4. Open **PowerShell as Administrator** and add route:
   ```powershell
   route add 10.0.0.0 mask 255.255.255.0 10.0.1.1
   ```
5. Test: `ping 10.0.1.1`

### A.5 — Find Your Interface Name on Windows

Scapy on Windows needs the interface name. Find it:
```powershell
# In Python:
python -c "from scapy.all import get_if_list; print(get_if_list())"
```

Or use Scapy's interactive mode:
```powershell
python -c "from scapy.all import show_interfaces; show_interfaces()"
```

Common Windows interface names look like:
`\Device\NPF_{GUID}` or `Ethernet`, `Wi-Fi`

### A.6 — Running the Scripts on Windows

#### PC1 (Shooter):
```powershell
# PowerShell as Administrator
.\venv\Scripts\Activate.ps1

# Set InfluxDB env vars (optional):
$env:INFLUXDB_URL = "http://10.0.0.1:8086"
$env:INFLUXDB_TOKEN = "your-token"

# Run shooter (use --iface with your Windows interface name):
python pc1_shooter.py --pcap-dir .\pcap_data --iface "Ethernet" --pc2-ip 10.0.0.1 --pc3-ip 10.0.1.2 --limit 20

# Without InfluxDB:
python pc1_shooter.py --pcap-dir .\pcap_data --iface "Ethernet" --pc2-ip 10.0.0.1 --pc3-ip 10.0.1.2 --limit 20 --no-influxdb
```

#### PC3 (Receiver):
```powershell
# PowerShell as Administrator
.\venv\Scripts\Activate.ps1

python pc3_receiver.py --iface "Ethernet" --no-influxdb
```

> **Note:** On Windows, you must run PowerShell **as Administrator** for Scapy to capture/send raw packets. The `--iface` argument may need the full Npcap device name.

### A.7 — Windows Firewall

If packets aren't getting through, temporarily disable Windows Firewall:
```powershell
# Disable (PowerShell as Admin):
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# Re-enable after testing:
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
```

Or add specific rules:
```powershell
# Allow UDP port 5005 (control plane):
New-NetFirewallRule -DisplayName "SDN Control" -Direction Inbound -Protocol UDP -LocalPort 5005 -Action Allow

# Allow all traffic on Ethernet interface:
New-NetFirewallRule -DisplayName "SDN Data" -Direction Inbound -InterfaceAlias "Ethernet" -Action Allow
```

### A.8 — Copying Files to Windows

From the department server to your Windows laptop:
```powershell
# Using SCP (if OpenSSH client is installed on Windows):
scp -r e20420@10.12.70.3:/scratch1/e20-fyp-xai-anomaly-detection/e20420Janith/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/InlineBridgeDemo C:\Users\YourName\InlineBridgeDemo

# Copy PCAP data:
scp -r e20420@10.12.70.3:/scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/Friday C:\Users\YourName\InlineBridgeDemo\pcap_data\

# Or use WinSCP/FileZilla for GUI-based transfer
```

