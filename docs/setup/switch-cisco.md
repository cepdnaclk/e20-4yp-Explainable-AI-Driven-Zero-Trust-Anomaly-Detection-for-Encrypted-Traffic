# Cisco IOS/IOS-XE SPAN Port Configuration Guide

**Purpose:** Mirror all traffic from one or more switch ports to the **laptop
running the SDN pipeline**, so NFStream can capture flows without being
inline (non-intrusive, passive capture).

---

## Hardware Requirements

| Item | Details |
|------|---------|
| Cisco switch | IOS 12.2(33) or later / IOS-XE any version |
| Pipeline laptop | Wired NIC connected to the **mirror destination port** |
| Cable | Straight-through or crossover Ethernet (auto-MDIX on modern switches) |

> **Key point:** The mirror destination port does **NOT** need to be in any
> VLAN or have an IP address. It simply passes all mirrored frames to the
> laptop. Set the laptop NIC to **promiscuous mode** (see below).

---

## Cisco IOS — SPAN Session Setup

### Step 1 — Login to Switch

```bash
# SSH (preferred)
ssh admin@<switch-ip>

# Console
minicom -b 9600 -D /dev/ttyUSB0
```

### Step 2 — Configure SPAN Session

Replace:
- `Gi0/1` → port(s) you want to monitor (traffic source — e.g., uplink)
- `Gi0/24` → port connected to the pipeline laptop (destination)

```
! Enter privileged EXEC then global config
enable
configure terminal

! Create SPAN session 1
! Source: monitor GigabitEthernet 0/1 in both directions
monitor session 1 source interface GigabitEthernet 0/1 both

! Destination: send mirrored frames to Gi0/24 (laptop)
! 'encapsulation replicate' preserves 802.1Q tags if needed
monitor session 1 destination interface GigabitEthernet 0/24

! Save config
end
write memory
```

### Step 3 — Verify

```
show monitor session 1
```

Expected output:
```
Session 1
---------
Type                   : Local Session
Source Ports           :
    Both               : Gi0/1
Destination Ports      : Gi0/24
    Encapsulation      : Native
          Ingress      : Disabled
```

### Step 4 — Monitor Multiple Source Ports (Optional)

```
configure terminal
! Monitor Gi0/1 through Gi0/8
monitor session 1 source interface GigabitEthernet 0/1 - 8 both
monitor session 1 destination interface GigabitEthernet 0/24
end
write memory
```

### Step 5 — Remove SPAN Session (when done)

```
configure terminal
no monitor session 1
end
write memory
```

---

## Cisco Catalyst (older IOS — 2950/3550)

On older switches the syntax may differ slightly:

```
! Verify syntax:
switch# monitor session ?

! Older syntax uses 'port' instead of 'interface':
monitor session 1 source interface fa0/1 both
monitor session 1 destination interface fa0/24
```

---

## IOS-XE (Catalyst 9000 series) — RSPAN (Remote SPAN)

If the pipeline laptop is on a different switch, use RSPAN:

```
! On source switch:
configure terminal
vlan 999
 remote-span
 name RSPAN_VLAN
!
monitor session 1 source interface Gi1/0/1 both
monitor session 1 destination remote vlan 999
end
write memory

! On destination switch (where laptop is connected):
configure terminal
monitor session 2 source remote vlan 999
monitor session 2 destination interface Gi1/0/24
end
write memory
```

---

## Laptop NIC Setup (Pipeline Machine)

After configuring the SPAN port on the switch, set the laptop NIC to
**promiscuous mode** so it captures all mirrored frames:

```bash
# Identify your NIC (usually eth0, eth1, enp3s0, etc.)
ip link show

# Enable promiscuous mode (automatically done by NFStream, but good to verify)
sudo ip link set eth1 promisc on

# Verify
ip link show eth1 | grep PROMISC   # should show PROMISC flag

# Test capture (should see traffic from monitored ports):
sudo tcpdump -i eth1 -n -c 20
```

If you see frames from monitored ports, the SPAN session is working.

---

## Start the Pipeline on Mirror Port

```bash
cd ~/e20420Janith/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/

# Activate virtualenv (if using one):
source /scratch1/e20-fyp-xai-anomaly-detection/.venv/bin/activate

# Start live pipeline on mirror port (replace eth1 with your NIC name):
python LiveTraffic/live_pipeline.py --interface eth1 --duration 300

# Or start Enhanced Pipeline REST API and point live_pipeline at it:
python EnhancedPipeline/rest_api.py --port 5001 &
python LiveTraffic/live_pipeline.py --interface eth1 --api http://localhost:5001
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `tcpdump` shows no traffic on mirror port | SPAN session not active | Run `show monitor session 1` on switch |
| Only see broadcast/multicast, not unicast | Switch in cut-through mode | Add `monitor session 1 source vlan X both` instead of port |
| Can't reach switch via SSH after SPAN config | Destination port was the uplink | Use a separate dedicated port for SPAN destination |
| NFStream sees 0 flows | Wrong interface name | Run `ip link show` to list all NICs |
| "Operation not permitted" on capture | Not running as root | Use `sudo` or add user to `wireshark`/`netdev` group |

---

## Quick Reference Cheat Sheet

```bash
# On switch:
enable
conf t
monitor session 1 source interface Gi0/1 both
monitor session 1 destination interface Gi0/24
end
write memory
show monitor session 1

# On laptop:
sudo ip link set eth1 promisc on
sudo tcpdump -i eth1 -n -c 10           # verify capture
python LiveTraffic/live_pipeline.py --interface eth1 --duration 300
```
