"""
LiveTraffic/openflow_controller.py — Ryu-based OpenFlow Controller
==================================================================
Zero-Trust Anomaly Detection | University of Peradeniya

Receives DROP/FORWARD decisions from the live_pipeline.py via a TCP socket,
then installs OpenFlow 1.3 flow rules on the physical switch to enforce them.

PREREQUISITES
-------------
  pip install ryu
  (Note: Ryu supports Python 3.10 max. Use a separate venv if needed.)

  The physical switch must be configured to connect to this controller:
    - OpenFlow 1.3 enabled on the switch
    - Controller IP configured (the machine running this script)
    - Default controller port: 6633

CISCO IOS CONFIGURATION
------------------------
  Switch(config)# interface management0
  Switch(config-if)# ip address 192.168.1.200 255.255.255.0  ! Controller machine IP
  Switch(config)# openflow
  Switch(config-of)# pipeline 1
  Switch(config-of-pipeline)# controller ipv4 192.168.1.200 port 6633 vrf management

HP ARUBA (ProVision)
--------------------
  switch(config)# openflow
  switch(of-cfg)# controller-id 1 ip 192.168.1.200 controller-interface oobm

USAGE
-----
  python LiveTraffic/openflow_controller.py
  python LiveTraffic/openflow_controller.py --cmd_port 6634  # pipeline decision socket
  python LiveTraffic/openflow_controller.py --of_port 6633   # OpenFlow port
"""

import os
import sys
import json
import socket
import threading
import logging
import argparse
from datetime import datetime

logger = logging.getLogger("OFController")


# ── Command server (receives DROP commands from live_pipeline.py) ──────────────

class CommandServer(threading.Thread):
    """
    TCP server that listens for DROP/FORWARD commands from live_pipeline.py.
    Each command is a JSON line: {"action": "DROP", "src_ip": ..., ...}
    """

    def __init__(self, host: str, port: int, of_app):
        super().__init__(daemon=True)
        self.host  = host
        self.port  = port
        self.of_app = of_app

    def run(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(5)
        logger.info(f"Command server listening on {self.host}:{self.port}")
        while True:
            try:
                conn, addr = srv.accept()
                logger.info(f"Pipeline connected from {addr}")
                threading.Thread(target=self._handle_conn, args=(conn,), daemon=True).start()
            except Exception as e:
                logger.error(f"Command server error: {e}")

    def _handle_conn(self, conn):
        buf = b""
        with conn:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    try:
                        cmd = json.loads(line.decode())
                        self._dispatch(cmd)
                    except Exception as e:
                        logger.warning(f"Bad command: {e}  line={line[:80]}")

    def _dispatch(self, cmd: dict):
        action = cmd.get("action", "FORWARD")
        if action == "DROP":
            self.of_app.install_drop_rule(
                src_ip   = cmd.get("src_ip"),
                dst_ip   = cmd.get("dst_ip"),
                src_port = cmd.get("src_port"),
                dst_port = cmd.get("dst_port"),
                protocol = cmd.get("protocol", "TCP"),
                timeout  = cmd.get("timeout_s", 60),
            )
            logger.info(
                f"DROP rule requested: "
                f"{cmd.get('src_ip')}:{cmd.get('src_port')} → "
                f"{cmd.get('dst_ip')}:{cmd.get('dst_port')} "
                f"(timeout={cmd.get('timeout_s', 60)}s)"
            )
        else:
            logger.debug(f"FORWARD: {cmd.get('flow_id', '?')} — no rule needed")


# ── Ryu OpenFlow application ─────────────────────────────────────────────────

try:
    from ryu.base import app_manager
    from ryu.controller import ofp_event
    from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
    from ryu.ofproto import ofproto_v1_3
    from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp

    class ZeroTrustOFApp(app_manager.RyuApp):
        """
        Ryu OpenFlow 1.3 application that:
        1. Installs a default table-miss rule (send unknown flows to controller)
        2. Learns MAC/port mappings (simple L2 switch behaviour for FORWARD)
        3. Accepts DROP commands from CommandServer and installs specific DROP rules
        """

        OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.mac_to_port = {}              # dpid → {mac: port}
            self._drop_log   = []              # list of installed DROP rules
            self._datapaths  = {}              # dpid → datapath

        @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
        def _switch_features_handler(self, ev):
            """Install table-miss rule on switch connect."""
            dp      = ev.msg.datapath
            ofproto = dp.ofproto
            parser  = dp.ofproto_parser
            self._datapaths[dp.id] = dp
            logger.info(f"Switch connected: dpid={dp.id:#x}")

            # Table-miss: send to controller with low priority
            match  = parser.OFPMatch()
            action = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]
            self._add_flow(dp, 0, match, action)

        def install_drop_rule(self, src_ip: str, dst_ip: str,
                               src_port: int, dst_port: int,
                               protocol: str = "TCP", timeout: int = 60):
            """
            Install a DROP (no-action) rule on all connected switches.

            Rule matches:   src_ip:src_port → dst_ip:dst_port (TCP or UDP)
            Effect:         All matching packets are silently dropped.
            Hard timeout:   Rule expires after `timeout` seconds automatically.
            """
            for dpid, dp in self._datapaths.items():
                parser  = dp.ofproto_parser
                proto   = 6 if protocol.upper() == "TCP" else 17  # IP proto number

                match = parser.OFPMatch(
                    eth_type=0x0800,   # IPv4
                    ip_proto=proto,
                    ipv4_src=src_ip,
                    ipv4_dst=dst_ip,
                    tcp_src=src_port,
                    tcp_dst=dst_port,
                )
                # Empty action list = DROP
                self._add_flow(dp, priority=100, match=match, actions=[],
                                hard_timeout=timeout)

                self._drop_log.append({
                    "timestamp":  datetime.utcnow().isoformat() + "Z",
                    "dpid":       hex(dpid),
                    "src":        f"{src_ip}:{src_port}",
                    "dst":        f"{dst_ip}:{dst_port}",
                    "protocol":   protocol,
                    "timeout_s":  timeout,
                })
                logger.info(
                    f"[OF] DROP rule installed on switch {hex(dpid)}: "
                    f"{src_ip}:{src_port} → {dst_ip}:{dst_port} "
                    f"({protocol}, {timeout}s)"
                )

        def _add_flow(self, dp, priority, match, actions,
                       idle_timeout=0, hard_timeout=0):
            """Helper: OFPFlowMod to add a flow entry."""
            ofproto = dp.ofproto
            parser  = dp.ofproto_parser
            inst    = [parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(
                datapath=dp, priority=priority, match=match,
                instructions=inst,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout,
            )
            dp.send_msg(mod)

        @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
        def _packet_in_handler(self, ev):
            """Handle packets sent to controller (for L2 learning)."""
            msg  = ev.msg
            dp   = msg.datapath
            ofp  = dp.ofproto
            par  = dp.ofproto_parser
            in_port = msg.match["in_port"]

            pkt  = packet.Packet(msg.data)
            eth  = pkt.get_protocol(ethernet.ethernet)
            if not eth:
                return

            # Learn MAC → port
            dpid = dp.id
            self.mac_to_port.setdefault(dpid, {})
            self.mac_to_port[dpid][eth.src] = in_port

            if eth.dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][eth.dst]
            else:
                out_port = ofp.OFPP_FLOOD

            actions = [par.OFPActionOutput(out_port)]

            # Install forwarding rule if we know the port
            if out_port != ofp.OFPP_FLOOD:
                match = par.OFPMatch(in_port=in_port, eth_dst=eth.dst)
                self._add_flow(dp, 1, match, actions, idle_timeout=30)

            # Send the buffered packet
            data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
            out  = par.OFPPacketOut(
                datapath=dp, buffer_id=msg.buffer_id,
                in_port=in_port, actions=actions, data=data
            )
            dp.send_msg(out)

    RYU_AVAILABLE = True

except ImportError:
    RYU_AVAILABLE = False

    class ZeroTrustOFApp:
        """Stub when Ryu is not installed."""
        def install_drop_rule(self, **kwargs):
            logger.info(f"[STUB] DROP rule (Ryu not installed): {kwargs}")


# ── Standalone entry point ────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    parser = argparse.ArgumentParser(description="OpenFlow Controller")
    parser.add_argument("--cmd_port", type=int, default=6633,
                        help="TCP port for receiving DROP commands from live_pipeline.py")
    parser.add_argument("--cmd_host", default="127.0.0.1",
                        help="Host to bind command server (default: 127.0.0.1)")
    args = parser.parse_args()

    app = ZeroTrustOFApp()
    cmd_server = CommandServer(args.cmd_host, args.cmd_port, app)
    cmd_server.start()

    if RYU_AVAILABLE:
        from ryu.cmd import manager
        logger.info("Starting Ryu OpenFlow controller...")
        sys.argv = ["ryu-manager", "--ofp-tcp-listen-port", "6653", __file__]
        manager.main()
    else:
        logger.warning(
            "Ryu not installed — running command server only (stub DROP logging).\n"
            "Install with: pip install ryu   (requires Python ≤ 3.10)"
        )
        cmd_server.join()
