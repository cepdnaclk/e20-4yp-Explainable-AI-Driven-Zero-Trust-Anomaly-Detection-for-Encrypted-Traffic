#!/bin/bash
# setup_host_b.sh — Network Configuration for PC3 (Receiver)
# Assigns static IP and sets PC2 as the default gateway.
#
# Usage: sudo bash setup_host_b.sh [up|down]

IFACE="eth0"              # Interface facing PC2
IP="10.0.1.2"             # PC3 IP
GATEWAY="10.0.1.1"        # PC2's IP (gateway)
NETMASK="24"

case "${1:-up}" in
  up)
    echo "Configuring PC3 (Receiver)..."
    ip addr flush dev $IFACE 2>/dev/null || true
    ip addr add ${IP}/${NETMASK} dev $IFACE
    ip link set $IFACE up
    ip route add 10.0.0.0/24 via $GATEWAY dev $IFACE 2>/dev/null || true
    echo "  ✅ $IFACE = $IP/$NETMASK, gateway = $GATEWAY"
    echo "  Test: ping $GATEWAY"
    ;;
  down)
    ip addr flush dev $IFACE 2>/dev/null || true
    ip route del 10.0.0.0/24 2>/dev/null || true
    echo "  ✅ PC3 network cleared"
    ;;
  *)
    echo "Usage: sudo bash setup_host_b.sh {up|down}"
    ;;
esac
