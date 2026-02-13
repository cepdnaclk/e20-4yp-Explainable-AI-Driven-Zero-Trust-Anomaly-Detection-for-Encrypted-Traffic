import pandas as pd
from nfstream import NFStreamer, NFPlugin
import logging
import numpy as np

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("FeatureExtractor")

def extract_features(pcap_path):
    """
    Extracts 15 specific features required by the Sentry Zero-Leak model.
    Maps NFStream features to CICFlowMeter equivalents (Best Effort).
    
    Args:
        pcap_path (str): Path to the PCAP file.
        
    Returns:
        """
    
    # The 15 features expected by the model (Order matters for some implementations, but dict key access is safer)
    REQUIRED_FEATURES = [
        'Packet Length Variance', 'Fwd Packet Length Max', 'Fwd Header Length',
        'Init_Win_bytes_forward', 'Bwd Header Length', 'Total Length of Fwd Packets',
        'Init_Win_bytes_backward', 'Bwd Packets/s', 'Flow IAT Min', 'Fwd IAT Min',
        'Flow Bytes/s', 'Active Min', 'Bwd IAT Total', 'Flow IAT Max', 'Flow Duration'
    ]

    def get_flow_key(src_ip, src_port, dst_ip, dst_port, proto):
        """Standardized flow key for matching."""
        # NFStream flow matching is bidirectional. We need a consistent key.
        # We will use sorted IP/Port pair to match NFStream's bidirectional behavior.
        if src_ip < dst_ip:
            return (src_ip, src_port, dst_ip, dst_port, proto)
        elif src_ip > dst_ip:
            return (dst_ip, dst_port, src_ip, src_port, proto)
        else:
            if src_port <= dst_port:
                return (src_ip, src_port, dst_ip, dst_port, proto)
            else:
                return (dst_ip, dst_port, src_ip, src_port, proto)

    # 1. Extract Handshake features using DPKT (Fast pass)
    handshake_features = {}
    try:
        import dpkt
        import socket
        
        f = open(pcap_path, 'rb')
        pcap = dpkt.pcap.Reader(f)
        
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP): continue
                ip = eth.data
                
                if ip.p != dpkt.ip.IP_PROTO_TCP: continue
                tcp = ip.data
                
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
                
                # IP Header + TCP Header
                header_len = (ip.hl * 4) + (tcp.off * 4) 

                # Check for Init Window (SYN) and Header Lengths
                # Store per direction
                exact_key = (src_ip, tcp.sport, dst_ip, tcp.dport, ip.p)

                if exact_key not in handshake_features:
                     handshake_features[exact_key] = {'win': 0, 'header_sum': 0, 'count': 0}
                
                # Check for Init Window (SYN)
                if (tcp.flags & dpkt.tcp.TH_SYN) and handshake_features[exact_key]['win'] == 0:
                     handshake_features[exact_key]['win'] = tcp.win
                
                # If just first packet seen for this direction and no SYN (mid-stream capture), take it
                if handshake_features[exact_key]['count'] == 0 and handshake_features[exact_key]['win'] == 0:
                     handshake_features[exact_key]['win'] = tcp.win

                handshake_features[exact_key]['header_sum'] += header_len
                handshake_features[exact_key]['count'] += 1

            except Exception:
                continue
        f.close()
    except Exception as e:
        logger.warning(f"DPKT Extraction failed: {e}")

    try:
        # 2. Main Extraction using NFStream
        # Set large active timeout to prevent splitting long synthetic flows
        streamer = NFStreamer(source=pcap_path, statistical_analysis=True, 
                              active_timeout=7200, idle_timeout=300)
        df = streamer.to_pandas()
        
        if df.empty:
            logger.warning(f"No flows found in {pcap_path}")
            return {"valid": False, "error": "No flows found", "features": {}}
            
        logger.info(f"NFStream found {len(df)} flows in {pcap_path}")
        flow = df.iloc[0]
        features = {}
        
        # Helper to get supplemental data
        # NFStream Flow: src_ip, src_port -> dst_ip, dst_port
        s_ip, s_port = flow.get('src_ip'), flow.get('src_port')
        d_ip, d_port = flow.get('dst_ip'), flow.get('dst_port')
        proto = 6 if flow.get('protocol') == 6 else 17 # Simplified
        
        fwd_key = (s_ip, s_port, d_ip, d_port, proto)
        bwd_key = (d_ip, d_port, s_ip, s_port, proto)
        
        fwd_data = handshake_features.get(fwd_key, {'win': 0, 'header_sum': 0})
        bwd_data = handshake_features.get(bwd_key, {'win': 0, 'header_sum': 0})

        # --- Feature Mapping ---

        # 1. Packet Length Variance
        features['Packet Length Variance'] = flow.get('bidirectional_stddev_ps', 0) ** 2

        # 2. Fwd Packet Length Max
        features['Fwd Packet Length Max'] = flow.get('src2dst_max_ps', 0)

        # 3. Fwd Header Length (From DPKT)
        features['Fwd Header Length'] = fwd_data['header_sum']

        # 4. Init_Win_bytes_forward (From DPKT)
        features['Init_Win_bytes_forward'] = fwd_data['win']

        # 5. Bwd Header Length (From DPKT)
        features['Bwd Header Length'] = bwd_data['header_sum']

        # 6. Total Length of Fwd Packets
        features['Total Length of Fwd Packets'] = flow.get('src2dst_bytes', 0)

        # 7. Init_Win_bytes_backward (From DPKT)
        features['Init_Win_bytes_backward'] = bwd_data['win']

        # 8. Bwd Packets/s
        duration_sec = flow.get('bidirectional_duration_ms', 0) / 1000.0
        if duration_sec == 0: duration_sec = 0.000001
        features['Bwd Packets/s'] = flow.get('dst2src_packets', 0) / duration_sec

        # 9. Flow IAT Min
        features['Flow IAT Min'] = flow.get('bidirectional_min_piat_ms', 0) * 1000

        # 10. Fwd IAT Min
        features['Fwd IAT Min'] = flow.get('src2dst_min_piat_ms', 0) * 1000

        # 11. Flow Bytes/s
        features['Flow Bytes/s'] = flow.get('bidirectional_bytes', 0) / duration_sec

        # 12. Active Min
        # Fallback to Flow Duration if no idle stats available
        features['Active Min'] = flow.get('bidirectional_duration_ms', 0) * 1000 

        # 13. Bwd IAT Total
        features['Bwd IAT Total'] = flow.get('dst2src_duration_ms', 0) * 1000

        # 14. Flow IAT Max
        features['Flow IAT Max'] = flow.get('bidirectional_max_piat_ms', 0) * 1000

        # 15. Flow Duration
        features['Flow Duration'] = flow.get('bidirectional_duration_ms', 0) * 1000

        # Handle numpy types
        for k, v in features.items():
            if hasattr(v, 'item'):
                features[k] = v.item()
            if np.isnan(features[k]):
                 features[k] = 0

        # Metadata
        if 'protocol_name' in flow:
            protocol = flow['protocol_name']
        elif 'application_name' in flow:
             protocol = flow['application_name']
        else:
            protocol = "Unknown"

        return {
            "valid": True,
            "features": features,
            "ordered_features": [features[k] for k in REQUIRED_FEATURES],
            "flow_id": f"{s_ip}:{s_port}->{d_ip}:{d_port}",
            "protocol": protocol
        }

    except Exception as e:
        logger.error(f"Extraction Error for {pcap_path}: {e}")
        return {"valid": False, "error": str(e), "features": {}}

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        print(extract_features(sys.argv[1]))
