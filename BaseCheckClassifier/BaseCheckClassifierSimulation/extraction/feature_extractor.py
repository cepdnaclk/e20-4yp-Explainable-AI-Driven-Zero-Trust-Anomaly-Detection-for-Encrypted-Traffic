import pandas as pd
from nfstream import NFStreamer
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
        dict: valid_features (bool), features (dict of 15 features for model input)
    """
    
    # The 15 features expected by the model (Order matters for some implementations, but dict key access is safer)
    REQUIRED_FEATURES = [
        'Packet Length Variance', 'Fwd Packet Length Max', 'Fwd Header Length',
        'Init_Win_bytes_forward', 'Bwd Header Length', 'Total Length of Fwd Packets',
        'Init_Win_bytes_backward', 'Bwd Packets/s', 'Flow IAT Min', 'Fwd IAT Min',
        'Flow Bytes/s', 'Active Min', 'Bwd IAT Total', 'Flow IAT Max', 'Flow Duration'
    ]

    try:
        # Statistical analysis=True enables feature calculation
        streamer = NFStreamer(source=pcap_path, statistical_analysis=True)
        
        # Use Pandas for robust extraction
        df = streamer.to_pandas()
        
        if df.empty:
            logger.warning(f"No flows found in {pcap_path}")
            return {"valid": False, "error": "No flows found", "features": {}}
            
        # Take the first flow (assuming pcap contains one stream or we analyze the first one)
        flow = df.iloc[0]
        
        # Mapping Logic
        features = {}
        
        # 1. Packet Length Variance (Approximate from std dev if variance not direct)
        # NFStream gives bidirectional_std_ps
        features['Packet Length Variance'] = flow.get('bidirectional_std_ps', 0) ** 2

        # 2. Fwd Packet Length Max
        features['Fwd Packet Length Max'] = flow.get('src2dst_max_ps', 0)

        # 3. Fwd Header Length (Estimate: Num packets * 20 bytes min header)
        features['Fwd Header Length'] = flow.get('src2dst_packets', 0) * 20

        # 4. Init_Win_bytes_forward (Not in NFStream basic, mock with 0 or mean)
        features['Init_Win_bytes_forward'] = 0 

        # 5. Bwd Header Length
        features['Bwd Header Length'] = flow.get('dst2src_packets', 0) * 20

        # 6. Total Length of Fwd Packets
        features['Total Length of Fwd Packets'] = flow.get('src2dst_bytes', 0)

        # 7. Init_Win_bytes_backward
        features['Init_Win_bytes_backward'] = 0

        # 8. Bwd Packets/s
        duration_sec = flow.get('bidirectional_duration_ms', 1) / 1000.0
        if duration_sec == 0: duration_sec = 0.001 # Avoid div by zero
        features['Bwd Packets/s'] = flow.get('dst2src_packets', 0) / duration_sec

        # 9. Flow IAT Min
        features['Flow IAT Min'] = flow.get('bidirectional_min_piat_ms', 0)

        # 10. Fwd IAT Min
        features['Fwd IAT Min'] = flow.get('src2dst_min_piat_ms', 0)

        # 11. Flow Bytes/s
        features['Flow Bytes/s'] = flow.get('bidirectional_bytes', 0) / duration_sec

        # 12. Active Min (Mock 0)
        features['Active Min'] = 0

        # 13. Bwd IAT Total (Estimate using duration)
        features['Bwd IAT Total'] = flow.get('dst2src_duration_ms', 0)

        # 14. Flow IAT Max
        features['Flow IAT Max'] = flow.get('bidirectional_max_piat_ms', 0)

        # 15. Flow Duration (Convert ms to microseconds as usually expected by CIC models)
        features['Flow Duration'] = flow.get('bidirectional_duration_ms', 0) * 1000

        # Handle numpy types
        for k, v in features.items():
            if hasattr(v, 'item'):
                features[k] = v.item()

        # Get metadata
        if 'protocol_name' in flow:
            protocol = flow['protocol_name']
        elif 'application_name' in flow:
             protocol = flow['application_name']
        else:
            protocol = "Unknown"

        return {
            "valid": True,
            "features": features, # Dictionary with mapped keys
            "ordered_features": [features[k] for k in REQUIRED_FEATURES], # List for model prediction
            "flow_id": f"{flow.get('src_ip')}:{flow.get('src_port')}->{flow.get('dst_ip')}:{flow.get('dst_port')}",
            "protocol": protocol
        }

    except Exception as e:
        logger.error(f"Extraction Error for {pcap_path}: {e}")
        return {"valid": False, "error": str(e), "features": {}}

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        print(extract_features(sys.argv[1]))
