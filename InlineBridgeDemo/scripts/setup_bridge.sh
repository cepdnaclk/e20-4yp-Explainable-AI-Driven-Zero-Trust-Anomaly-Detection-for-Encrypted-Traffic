#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# setup_bridge.sh — Network Configuration for PC2 (AI Gatekeeper)
# ═══════════════════════════════════════════════════════════════════
# Configures PC2 as a router between PC1 and PC3:
#   eth0 (built-in Ethernet)     → connects to PC1 (10.0.0.0/24)
#   eth1 (USB-Ethernet adapter)  → connects to PC3 (10.0.1.0/24)
#
# Usage:
#   sudo bash setup_bridge.sh up       # Configure networking
#   sudo bash setup_bridge.sh down     # Tear down
#   sudo bash setup_bridge.sh status   # Show current state
# ═══════════════════════════════════════════════════════════════════

set -e

# ── Configuration (EDIT THESE if your interfaces differ) ─────────
IFACE_IN="eth0"          # Interface facing PC1 (Shooter)
IFACE_OUT="eth1"         # Interface facing PC3 (Receiver)
IP_IN="10.0.0.1"         # PC2's IP on the PC1 side
IP_OUT="10.0.1.1"        # PC2's IP on the PC3 side
NETMASK="24"

case "${1:-up}" in
  up|start)
    echo "═══════════════════════════════════════════════════"
    echo "  PC2 Bridge Setup — Configuring networking"
    echo "═══════════════════════════════════════════════════"

    # 1. Assign static IPs
    echo "[1/4] Assigning static IPs..."
    ip addr flush dev $IFACE_IN 2>/dev/null || true
    ip addr flush dev $IFACE_OUT 2>/dev/null || true
    ip addr add ${IP_IN}/${NETMASK} dev $IFACE_IN
    ip addr add ${IP_OUT}/${NETMASK} dev $IFACE_OUT
    ip link set $IFACE_IN up
    ip link set $IFACE_OUT up
    echo "  $IFACE_IN = $IP_IN/$NETMASK"
    echo "  $IFACE_OUT = $IP_OUT/$NETMASK"

    # 2. Enable IP forwarding
    echo "[2/4] Enabling IP forwarding..."
    sysctl -w net.ipv4.ip_forward=1 > /dev/null
    echo "  net.ipv4.ip_forward = 1"

    # 3. Set up iptables — DROP all forwarding by default (Zero Trust)
    #    The Python gatekeeper explicitly forwards clean packets via sendp().
    #    Kernel must NOT forward anything on its own.
    echo "[3/4] Configuring iptables (FORWARD=DROP for Zero Trust)..."
    iptables -F FORWARD 2>/dev/null || true
    iptables -P FORWARD DROP
    echo "  FORWARD chain: DROP by default (gatekeeper controls forwarding)"

    # 4. Open UDP port for control plane
    echo "[4/4] Opening UDP port 5005 for control plane..."
    iptables -A INPUT -p udp --dport 5005 -j ACCEPT 2>/dev/null || true

    echo ""
    echo "═══════════════════════════════════════════════════"
    echo "  ✅ PC2 Bridge is READY"
    echo "═══════════════════════════════════════════════════"
    echo "  PC1 side: $IFACE_IN = $IP_IN"
    echo "  PC3 side: $IFACE_OUT = $IP_OUT"
    echo ""
    echo "  Next: run the AI gatekeeper:"
    echo "    sudo python3 pc2_gatekeeper.py --iface-in $IFACE_IN --iface-out $IFACE_OUT"
    echo ""
    ;;

  down|stop)
    echo "Tearing down PC2 bridge..."
    sysctl -w net.ipv4.ip_forward=0 > /dev/null
    iptables -F FORWARD 2>/dev/null || true
    ip addr flush dev $IFACE_IN 2>/dev/null || true
    ip addr flush dev $IFACE_OUT 2>/dev/null || true
    echo "  ✅ Bridge torn down"
    ;;

  status)
    echo "═══ PC2 Bridge Status ═══"
    echo ""
    echo "IP Forwarding: $(cat /proc/sys/net/ipv4/ip_forward)"
    echo ""
    echo "$IFACE_IN:"
    ip addr show $IFACE_IN 2>/dev/null | grep inet || echo "  (no IP assigned)"
    echo ""
    echo "$IFACE_OUT:"
    ip addr show $IFACE_OUT 2>/dev/null | grep inet || echo "  (no IP assigned)"
    echo ""
    echo "iptables FORWARD chain:"
    iptables -L FORWARD -n 2>/dev/null || echo "  (no rules)"
    ;;

  *)
    echo "Usage: sudo bash setup_bridge.sh {up|down|status}"
    exit 1
    ;;
esac
