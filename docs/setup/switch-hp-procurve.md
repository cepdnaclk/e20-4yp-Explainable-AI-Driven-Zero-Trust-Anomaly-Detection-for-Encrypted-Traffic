# HP ProCurve / Aruba Switch — Port Mirroring Setup Guide

**Purpose:** Configure port mirroring on an HP ProCurve (legacy CLI) or
HPE Aruba (ArubaOS-Switch) L3 switch so traffic from monitored ports is
sent to the pipeline laptop on a dedicated mirror port.

---

## Hardware Requirements

| Item | Details |
|------|---------|
| HP / Aruba L3 switch | ProCurve 2600/2800/3800 or Aruba 2540/3810/5400 |
| Pipeline laptop | Wired NIC connected to the **mirror exit port** |
| Cable | Standard Ethernet cable |
| Console or SSH | Serial console (9600 baud) or SSH to switch management IP |

---

## Connecting to the Switch

```bash
# SSH (if configured):
ssh manager@<switch-management-ip>

# Console (serial):
minicom -b 9600 -D /dev/ttyUSB0
# Press Enter when connected, then log in with manager password
```

---

## HP ProCurve (older firmware — ProCurve Manager CLI)

### Step 1 — Check current mirroring (if any)

```
ProCurve# show mirror
```

### Step 2 — Configure mirroring

Replace:
- Port `2` → the source port(s) to monitor (e.g., uplink to router)
- Port `24` → the exit/destination port (laptop's NIC)

```
ProCurve# configure
ProCurve(config)# mirror 1 port 24             ! Exit port = port 24
ProCurve(config)# interface 2                  ! Source port
ProCurve(eth-2)# monitor                       ! Enable mirroring on port 2
ProCurve(eth-2)# exit
ProCurve(config)# write memory
ProCurve(config)# exit
```

### Step 3 — Verify

```
ProCurve# show mirror
ProCurve# show monitor
```

Expected:
```
Mirror  Exit Port  Type
------  ---------  -------
1       24         Local
```

### Step 4 — Remove mirroring

```
ProCurve# configure
ProCurve(config)# no mirror 1
ProCurve(config)# write memory
```

---

## HPE Aruba (ArubaOS-Switch — 2540, 3810, 5400 series)

### Step 1 — Verify current sessions

```
switch# show monitor session all
```

### Step 2 — Configure mirroring session

Replace:
- `1/1` → source port (uplink/monitored port)
- `1/24` → destination port (laptop)

```
switch# configure
switch(config)# mirror-session 1
switch(mirror-session-1)# source interface 1/1 both
switch(mirror-session-1)# destination interface 1/24
switch(mirror-session-1)# enable
switch(mirror-session-1)# exit
switch(config)# write memory
switch(config)# exit
```

### Step 3 — Mirror multiple source ports

```
switch(config)# mirror-session 1
switch(mirror-session-1)# source interface 1/1-1/8 both
switch(mirror-session-1)# destination interface 1/24
switch(mirror-session-1)# enable
switch(mirror-session-1)# exit
switch(config)# write memory
```

### Step 4 — Verify

```
switch# show monitor session 1
```

Expected output:
```
 Mirror Session : 1
 Admin State    : Enabled
 Source Ports   : 1/1
 Direction      : Both
 Destination    : 1/24
```

### Step 5 — Disable / delete session

```
switch(config)# no mirror-session 1
switch(config)# write memory
```

---

## Laptop NIC Setup (Both Switch Types)

After confirming mirroring on the switch:

```bash
# Identify the NIC connected to the mirror port
ip link show

# Enable promiscuous mode (needed to capture all frames)
sudo ip link set eth1 promisc on

# Verify promiscuous is active:
ip link show eth1              # Look for PROMISC in flags

# Quick test — should see raw frames from monitored traffic:
sudo tcpdump -i eth1 -n -c 10

# If you see traffic from monitored ports → mirroring is working.
```

---

## Start the Pipeline

```bash
cd ~/e20420Janith/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/
source /scratch1/e20-fyp-xai-anomaly-detection/.venv/bin/activate

# Option A: Standard pipeline
python LiveTraffic/live_pipeline.py --interface eth1 --duration 300

# Option B: Enhanced pipeline (DDL + IF + XAI)
python EnhancedPipeline/rest_api.py --port 5001 &
streamlit run EnhancedPipeline/dashboard.py &
python LiveTraffic/live_pipeline.py --interface eth1 --api http://localhost:5001
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `show mirror` shows no sessions | Not configured yet | Follow steps above |
| Mirror destination port drops link | Laptop NIC auto-negotiation fail | Force 100Mbps full-duplex on switch port |
| NFStream sees 0 flows | Wrong interface name | `ip link show` to list NICs |
| Mirror flooding back to source | Destination port in same VLAN as source | Take destination port out of all VLANs: `no vlan X tagged <port>` |
| SSH to switch broken after mirroring | You mirrored the uplink AND management on same port | Use a separate non-management port for mirror destination |

---

## ProCurve vs. Aruba Command Reference

| Action | ProCurve (older) | Aruba (ArubaOS-Switch) |
|--------|-----------------|------------------------|
| Create mirror | `mirror 1 port <exit>` | `mirror-session 1` |
| Add source | `interface X; monitor` | `source interface X both` |
| Set destination | (set at mirror level) | `destination interface Y` |
| Enable | (implicit) | `enable` |
| Verify | `show mirror` | `show monitor session 1` |
| Remove | `no mirror 1` | `no mirror-session 1` |
