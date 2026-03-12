#!/bin/bash
# setup_host_a.sh — Network Configuration for PC1 (Shooter)
# Assigns static IP and sets PC2 as the default gateway.
#
# Usage: sudo bash setup_host_a.sh [up|down]

IFACE="eth0"              # Interface facing PC2
IP="10.0.0.2"             # PC1 IP
GATEWAY="10.0.0.1"        # PC2's IP (gateway)
NETMASK="24"

case "${1:-up}" in
  up)
    echo "Configuring PC1 (Shooter)..."
    ip addr flush dev $IFACE 2>/dev/null || true
    ip addr add ${IP}/${NETMASK} dev $IFACE
    ip link set $IFACE up
    ip route add 10.0.1.0/24 via $GATEWAY dev $IFACE 2>/dev/null || true
    echo "  ✅ $IFACE = $IP/$NETMASK, gateway = $GATEWAY"
    echo "  Test: ping $GATEWAY"
    ;;
  down)
    ip addr flush dev $IFACE 2>/dev/null || true
    ip route del 10.0.1.0/24 2>/dev/null || true
    echo "  ✅ PC1 network cleared"
    ;;
  *)
    echo "Usage: sudo bash setup_host_a.sh {up|down}"
    ;;
esac
