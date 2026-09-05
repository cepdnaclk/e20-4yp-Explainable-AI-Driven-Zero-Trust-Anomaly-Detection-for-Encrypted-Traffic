# Physical Switch Setup for the Live Traffic Demo
**Zero-Trust Anomaly Detection | University of Peradeniya**

> This guide covers how to connect the SDN pipeline machine to a **physical switch's mirror port** to capture and process live encrypted network traffic.

---

## What is a Mirror / SPAN Port?

A **SPAN port (Switched Port Analyser)** — also called a mirror port — copies all traffic passing through one or more switch ports to a dedicated monitoring port. Our pipeline listens on that monitoring port without interfering with the actual network.

```
  [PC A] ─── port 1 ──► [SWITCH] ─── port 2 ──► [PC B]
                              │
                         mirror port (port 3)
                              │
                         [Pipeline Machine]
                         (NFStream capture)
```

---

## Section 1 — Switch-Specific Configuration

### 1A. Cisco IOS (Most Common Lab Switch)

Connect via console cable or SSH, then:

```
Switch> enable
Switch# configure terminal

! Create a monitor session (session 1)
! Source: port(s) to mirror (adjust to your port numbers)
Switch(config)# monitor session 1 source interface GigabitEthernet0/1
Switch(config)# monitor session 1 source interface GigabitEthernet0/2  (add more if needed)

! Destination: the port YOUR machine is connected to
Switch(config)# monitor session 1 destination interface GigabitEthernet0/3

Switch(config)# end
Switch# write memory

! Verify:
Switch# show monitor session 1
```

**Expected output:**
```
Session 1
---------
Type              : Local Session
Source Ports      :
    Both          : Gi0/1, Gi0/2
Destination Ports : Gi0/3
    Encapsulation : Native
          Ingress : Disabled
```

### 1B. HP Aruba / ProCurve

```
HPswitch# configure
HPswitch(config)# mirror 1 port 3     ! Port 3 = monitoring port
HPswitch(config)# interface 1         ! Port 1 = source
HPswitch(eth-1)# monitor all both mirror 1
HPswitch(eth-1)# exit
HPswitch(config)# interface 2         ! Port 2 = additional source
HPswitch(eth-2)# monitor all both mirror 1
HPswitch(eth-2)# exit
HPswitch(config)# write memory
```

### 1C. Generic OpenFlow Switch (e.g., Open vSwitch)

```bash
# Mirror port 1 and port 2 to port 3
ovs-vsctl -- set Bridge br0 mirrors=@m \
  -- --id=@src1 get Port eth1 \
  -- --id=@src2 get Port eth2 \
  -- --id=@dst  get Port eth3 \
  -- --id=@m    create Mirror name=span select-src-port=@src1,@src2 \
                              select-dst-port=@src1,@src2 output-port=@dst

# Verify
ovs-vsctl list Mirror
```

---

## Section 2 — Pipeline Machine Setup

### 2.1 Network Interface Setup

The pipeline machine should have **two network interfaces**:
- `eth0` — management (SSH, internet) 
- `eth1` — connected to switch mirror port (monitor-only)

Set `eth1` to **promiscuous mode** (receives all mirrored packets):

```bash
sudo ip link set eth1 promisc on
sudo ip link set eth1 up

# Verify promiscuous mode is active
ip link show eth1 | grep PROMISC
```

Expected output:
```
2: eth1: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP> ...
```

### 2.2 Verify Capture is Working

```bash
# Check that mirrored traffic is arriving on eth1
sudo tcpdump -i eth1 -n -c 20

# You should see traffic from the source ports, e.g.
# 10:23:14.123456 IP 192.168.1.10.54321 > 142.250.180.14.443: TCP
```

If `tcpdump` shows no packets, check:
1. Switch SPAN session is active (`show monitor session 1`)
2. `eth1` is physically connected to the SPAN destination port
3. Traffic is actively flowing on the source ports

---

## Section 3 — Running the Live Pipeline

### 3.1 Start the Pipeline

```bash
# From project root (use absolute venv path):
source /scratch1/e20-fyp-xai-anomaly-detection/.venv/bin/activate

python LiveTraffic/live_pipeline.py \
    --interface eth1 \
    --duration 300 \
    --ddl_model models/ddl_40feat.pkl \
    --log_path logs/live_run_$(date +%Y%m%d_%H%M%S).json
```

**Parameters:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--interface` | `eth0` | Network interface to capture on |
| `--duration` | `60` | Capture duration in seconds (0 = run forever) |
| `--ddl_model` | *(none)* | Path to trained DDL .pkl file |
| `--idle_timeout` | `15` | NFStream idle flow timeout (seconds) |
| `--active_timeout` | `120` | NFStream active flow timeout (seconds) |
| `--log_path` | `logs/live_pipeline.json` | Output log path |
| `--no_shap` | *(flag)* | Disable SHAP (faster, still gets DDL-native XAI) |

### 3.2 Monitor Progress

The pipeline prints a running summary every 30 seconds:

```
[10:34:52] Pipeline Status:
  Flows seen:     142
  DT passed:      128 (90.1%)
  DT flagged:      14 ( 9.9%)
  DDL cleared:     11 (78.6% of flagged)
  DDL confirmed:    3 (21.4% of flagged) → DROPPED
  Avg DT latency:   0.8ms
  Avg DDL latency:  52.3ms
```

---

## Section 4 — Simulating Attack Traffic for Demo

If real attack traffic is not available, use the traffic generator:

```bash
# Terminal 1: Start pipeline listener
python LiveTraffic/live_pipeline.py --interface eth1 --duration 120

# Terminal 2: Replay pre-recorded attack PCAPs (from another machine)
# Requires: tcpreplay installed
sudo tcpreplay --intf1=eth0 --multiplier=2 \
    BaseCheckClassifier/BaseCheckClassifierSimulation/attack/*.pcap

# Or use our simulated generator:
python LiveTraffic/traffic_generator.py \
    --mode mixed \
    --count 50 \
    --attack_ratio 0.3 \
    --interface eth0
```

---

## Section 5 — OpenFlow Integration (Optional)

If you have an OpenFlow-capable switch, the Ryu controller can install real flow entries:

```bash
# Terminal 1: Start Ryu controller
# Requires: pip install ryu
python LiveTraffic/openflow_controller.py --port 6633

# Terminal 2: Start pipeline with OpenFlow DROP support
python LiveTraffic/live_pipeline.py \
    --interface eth1 \
    --openflow_host 127.0.0.1 \
    --openflow_port 6633
```

When the pipeline drops a flow, it sends a DROP rule to the Ryu controller, which installs an OpenFlow rule on the switch to block that 5-tuple for 60 seconds.

---

## Section 6 — Troubleshooting

| Problem | Check |
|---------|-------|
| NFStream captures 0 flows | Is `eth1` in promisc mode? Is traffic flowing? |
| DDL model not found | Run `python DDLModel/train_ddl_enhanced.py` first |
| `nfstream` not installed | `pip install nfstream` or `uv pip install nfstream` |
| Ryu controller errors | `pip install ryu` — note: Python 3.10 max for Ryu |
| No packets on mirror port | Check switch SPAN configuration (`show monitor session`) |
| High CPU from SHAP | Add `--no_shap` flag; SHAP adds ~200ms per flagged flow |

---

## Appendix — NFStream Flow Objects (for feature extraction)

NFStream terminates a flow and returns an `NFFlow` object after `idle_timeout` seconds of inactivity. Key attributes we use:

| Attribute | Description |
|-----------|-------------|
| `src2dst_bytes` | Forward direction total bytes |
| `dst2src_bytes` | Backward direction total bytes |
| `bidirectional_packets` | Total packet count |
| `src2dst_mean_ps` | Forward mean packet size |
| `src2dst_stddev_ps` | Forward packet size std dev |
| `src2dst_mean_piat_ms` | Forward mean inter-arrival (ms) |
| `bidirectional_syn_packets` | Total SYN flags |
| `bidirectional_duration_ms` | Total flow duration (ms) |
| `application_name` | Application layer protocol (if detected) |
