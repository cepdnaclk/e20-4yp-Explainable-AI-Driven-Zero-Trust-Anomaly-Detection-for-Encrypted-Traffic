"""
sdn_buffer_v2.py — Improved SDN Controller Buffer (OpenFlow-Correct Approach)
=============================================================================
Zero-Trust XAI Anomaly Detection | University of Peradeniya
e20420Janith

ARCHITECTURE BACKGROUND
-----------------------
In an SDN (Software-Defined Networking) environment with a Cisco/HP switch,
the switch hardware CANNOT hold packets while our Python pipeline makes a
DDL+XAI decision (the switch buffer is tiny, ~ms only).

The CORRECT architecture is:

  1. Traffic passes through the switch.
  2. The switch MIRRORS all traffic to the SDN controller via SPAN/RSPAN.
  3. NFStream on the controller assembles packets into flow statistics.
  4. DT (Stage 1) runs on flow stats → if suspicious, DDL (Stage 2) runs.
  5. While DDL+XAI runs, the controller maintains a SOFTWARE buffer
     (this module) keyed by 5-tuple (src_ip, dst_ip, src_port, dst_port, proto).
  6. Once the DDL decision is made:
     - FORWARD: Controller installs an OpenFlow ALLOW rule on the switch.
       The switch then passes all future matching packets immediately (no delay).
     - DROP:    Controller installs an OpenFlow DROP rule on the switch.
       The switch drops all future matching packets immediately (μs-level).

What the buffer holds:
  - Flow metadata (5-tuple, timestamps)
  - Feature vectors (for DDL)
  - Raw packets (optional, for future packet-capture-then-replay)
  - Decision state and timing

NOTE: In the research simulation, we generate the traffic with
LiveTraffic/traffic_generator.py or tcpreplay. The actual "buffering" of
real packets is done at the controller/mirror level by NFStream. The SDNBuffer
here tracks the LOGICAL state of buffered flows and provides timing data.

See docs/architecture/ddl-xai.md Part 4 for full architecture explanation.
"""

import time
import logging
import json
import socket
import threading
from typing import Dict, Any, Optional, List

logger = logging.getLogger("SDNBuffer")


class FlowBuffer:
    """
    Single buffered flow entry.
    Stores flow metadata, timing, feature vectors, and raw packets.
    """

    def __init__(self, flow_id: str, features: Any,
                 metadata: Optional[Dict] = None,
                 max_raw_packets: int = 100):
        self.flow_id         = flow_id
        self.features        = features          # 30-element DDL feature vector
        self.metadata        = metadata or {}    # 5-tuple, protocol, etc.
        self.buffered_at     = time.time()
        self.status          = "ANALYZING"       # ANALYZING | FORWARD | DROP | EXPIRED

        # Raw packet storage (optional, for packet-level replay after decision)
        self.raw_packets: List[bytes] = []
        self.max_raw_packets = max_raw_packets
        self.pkt_count       = 0
        self.byte_count      = 0

        # Decision tracking
        self.decision_at:   Optional[float] = None
        self.ddl_score:     Optional[float] = None
        self.xai_summary:   Optional[str]   = None

    def add_packet(self, raw_pkt: bytes):
        """Store a raw packet in the buffer (for post-decision replay)."""
        self.pkt_count  += 1
        self.byte_count += len(raw_pkt)
        if len(self.raw_packets) < self.max_raw_packets:
            self.raw_packets.append(raw_pkt)

    def hold_time_ms(self) -> float:
        """Return how long this flow has been buffered (milliseconds)."""
        end = self.decision_at if self.decision_at else time.time()
        return (end - self.buffered_at) * 1000.0

    def to_dict(self) -> Dict:
        return {
            "flow_id":       self.flow_id,
            "status":        self.status,
            "buffered_at":   self.buffered_at,
            "hold_time_ms":  round(self.hold_time_ms(), 2),
            "pkt_count":     self.pkt_count,
            "byte_count":    self.byte_count,
            "ddl_score":     self.ddl_score,
            "xai_summary":   self.xai_summary,
            "metadata":      self.metadata,
        }


class SDNBuffer:
    """
    SDN Controller Software Buffer for the Zero-Trust pipeline.

    Manages the "in-analysis" state for flows flagged by the DT classifier
    while DDL + XAI processing completes. After the decision, installs an
    OpenFlow rule on the switch via the Ryu REST API.

    One-class invariant (zero-trust default):
      - If a flow is buffered for longer than timeout_ms without a decision,
        it is automatically DROPPED (when in doubt, block).
    """

    def __init__(self,
                 max_buffer_size: int = 1000,
                 timeout_ms: float = 5000.0,
                 openflow_host: Optional[str] = None,
                 openflow_port: int = 8080,
                 openflow_dpid: str = "1"):
        """
        Args:
            max_buffer_size: Max simultaneous in-analysis flows (default 1000).
            timeout_ms:      Auto-drop timeout in milliseconds (default 5000 = 5s).
            openflow_host:   Ryu controller REST API host (None = no OpenFlow push).
            openflow_port:   Ryu REST API port (default 8080).
            openflow_dpid:   OpenFlow datapath ID of the switch (default "1").
        """
        self._lock          = threading.Lock()
        self._buffer: Dict[str, FlowBuffer] = {}
        self.max_buffer_size = max_buffer_size
        self.timeout_ms      = timeout_ms

        # OpenFlow push via Ryu REST API
        self.of_host  = openflow_host
        self.of_port  = openflow_port
        self.of_dpid  = openflow_dpid

        # Stats
        self.stats = {
            "total_buffered":  0,
            "total_released":  0,
            "total_dropped":   0,
            "total_expired":   0,
            "of_rules_pushed": 0,
        }

        # Auto-expire timer
        self._expire_timer = None
        self._start_expire_thread()

        logger.info(
            f"[SDNBuffer] Initialized — max={max_buffer_size}, "
            f"timeout={timeout_ms}ms, "
            f"OpenFlow={'enabled' if openflow_host else 'disabled'}"
        )

    # ── Buffer operations ────────────────────────────────────────────────────

    def add(self, flow_id: str, features: Any,
            metadata: Optional[Dict] = None) -> bool:
        """
        Buffer a flagged flow for DDL analysis.

        Args:
            flow_id:  5-tuple string identifier (e.g. "10.0.0.1:1234->10.0.0.2:80/TCP").
            features: 30-element DDL feature vector.
            metadata: Dict with src_ip, dst_ip, src_port, dst_port, protocol.

        Returns:
            True if buffered, False if buffer is full.
        """
        with self._lock:
            if len(self._buffer) >= self.max_buffer_size:
                logger.warning(
                    f"[SDNBuffer] FULL ({self.max_buffer_size}) — dropping {flow_id}"
                )
                return False

            entry = FlowBuffer(flow_id=flow_id, features=features, metadata=metadata)
            self._buffer[flow_id] = entry
            self.stats["total_buffered"] += 1

        logger.info(
            f"[SDNBuffer] BUFFERED {flow_id} "
            f"(buf_size={len(self._buffer)}/{self.max_buffer_size})"
        )
        return True

    def release(self, flow_id: str,
                ddl_score: Optional[float] = None,
                xai_summary: Optional[str] = None) -> Optional[Dict]:
        """
        Release a buffered flow (DDL says Normal → FORWARD).

        Installs an OpenFlow ALLOW rule on the switch via Ryu REST API.

        Returns:
            dict with action, hold_time_ms, pkt_count, byte_count (or None).
        """
        with self._lock:
            entry = self._buffer.pop(flow_id, None)

        if entry is None:
            return None

        entry.decision_at = time.time()
        entry.status      = "FORWARD"
        entry.ddl_score   = ddl_score
        entry.xai_summary = xai_summary
        self.stats["total_released"] += 1

        hold_ms = entry.hold_time_ms()
        logger.info(
            f"[SDNBuffer] RELEASED {flow_id} — hold={hold_ms:.0f}ms "
            f"ddl_score={ddl_score:.4f if ddl_score else '?'}"
        )

        # Push OpenFlow ALLOW rule
        if entry.metadata:
            self._push_openflow_rule(entry.metadata, action="ALLOW", timeout_s=120)

        return {
            "action":       "FORWARD",
            "hold_time_ms": round(hold_ms, 2),
            "pkt_count":    entry.pkt_count,
            "byte_count":   entry.byte_count,
        }

    def drop(self, flow_id: str,
             ddl_score: Optional[float] = None,
             xai_summary: Optional[str] = None) -> Optional[Dict]:
        """
        Drop a buffered flow (DDL confirms anomaly → DROP).

        Installs an OpenFlow DROP rule on the switch via Ryu REST API.

        Returns:
            dict with action, hold_time_ms, pkt_count, byte_count (or None).
        """
        with self._lock:
            entry = self._buffer.pop(flow_id, None)

        if entry is None:
            return None

        entry.decision_at = time.time()
        entry.status      = "DROP"
        entry.ddl_score   = ddl_score
        entry.xai_summary = xai_summary
        self.stats["total_dropped"] += 1

        hold_ms = entry.hold_time_ms()
        logger.warning(
            f"[SDNBuffer] DROPPED  {flow_id} — hold={hold_ms:.0f}ms "
            f"ddl_score={ddl_score:.4f if ddl_score else '?'}"
        )

        # Push OpenFlow DROP rule
        if entry.metadata:
            self._push_openflow_rule(entry.metadata, action="DROP", timeout_s=300)

        return {
            "action":       "DROP",
            "hold_time_ms": round(hold_ms, 2),
            "pkt_count":    entry.pkt_count,
            "byte_count":   entry.byte_count,
            "xai_summary":  xai_summary,
        }

    # ── OpenFlow rule push (Ryu REST API) ────────────────────────────────────

    def _push_openflow_rule(self, metadata: Dict, action: str, timeout_s: int = 120):
        """
        Push an OpenFlow flow rule to the switch via the Ryu REST API.

        Ryu exposes: POST /stats/flowentry/add
        Payload specifies: match (5-tuple) + action (OUTPUT or DROP)

        In the demo, this is called after every DDL decision for flagged flows.

        Args:
            metadata:  Dict with src_ip, dst_ip, src_port, dst_port, protocol.
            action:    "ALLOW" (output to original port) or "DROP".
            timeout_s: How long the OpenFlow rule stays active (seconds).
        """
        if not self.of_host:
            return

        proto_num = 6 if str(metadata.get("protocol", "TCP")).upper() == "TCP" else 17

        # Build OpenFlow flow entry for Ryu
        flow_entry = {
            "dpid":       int(self.of_dpid),
            "priority":   100,
            "hard_timeout": timeout_s,
            "idle_timeout": 0,
            "match": {
                "nw_src":   str(metadata.get("src_ip", "")),
                "nw_dst":   str(metadata.get("dst_ip", "")),
                "tp_src":   int(metadata.get("src_port", 0)),
                "tp_dst":   int(metadata.get("dst_port", 0)),
                "nw_proto": proto_num,
                "dl_type":  0x0800,  # IPv4
            },
            "actions": [] if action == "DROP" else [
                {"type": "OUTPUT", "port": "NORMAL"}
            ],
        }

        # Send via HTTP to Ryu REST API
        try:
            import urllib.request
            url  = f"http://{self.of_host}:{self.of_port}/stats/flowentry/add"
            body = json.dumps(flow_entry).encode()
            req  = urllib.request.Request(
                url, data=body,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=2) as resp:
                resp.read()
            self.stats["of_rules_pushed"] += 1
            logger.debug(f"[SDNBuffer] OpenFlow {action} rule pushed to {self.of_host}")
        except Exception as e:
            logger.warning(f"[SDNBuffer] OpenFlow rule push failed: {e}")

    # ── Auto-expire expired flows (zero-trust timeout) ───────────────────────

    def clear_expired(self) -> List[str]:
        """
        Auto-drop flows that have been buffered longer than timeout_ms.
        Zero-trust principle: when in doubt, drop.

        Returns list of expired flow IDs.
        """
        now     = time.time()
        expired = []

        with self._lock:
            to_expire = [
                fid for fid, entry in self._buffer.items()
                if (now - entry.buffered_at) * 1000 > self.timeout_ms
            ]
            for fid in to_expire:
                entry = self._buffer.pop(fid)
                entry.status = "EXPIRED"
                entry.decision_at = now
                expired.append(fid)
                self.stats["total_expired"] += 1
                logger.warning(
                    f"[SDNBuffer] EXPIRED {fid} after "
                    f"{entry.hold_time_ms():.0f}ms — auto-DROP (zero-trust timeout)"
                )
                # Install DROP rule for expired flows
                if entry.metadata:
                    self._push_openflow_rule(entry.metadata, action="DROP", timeout_s=60)

        return expired

    def _start_expire_thread(self):
        """Background thread that calls clear_expired() every second."""
        def _expire_loop():
            while True:
                time.sleep(1.0)
                self.clear_expired()

        t = threading.Thread(target=_expire_loop, daemon=True)
        t.start()

    # ── Inspection helpers ───────────────────────────────────────────────────

    def get_buffered_count(self) -> int:
        return len(self._buffer)

    def get_all_buffered(self) -> Dict[str, Dict]:
        with self._lock:
            return {fid: entry.to_dict() for fid, entry in self._buffer.items()}

    def get_stats(self) -> Dict:
        s = dict(self.stats)
        s["currently_buffered"] = len(self._buffer)
        return s

    def get_buffered_count(self) -> int:
        return len(self._buffer)
