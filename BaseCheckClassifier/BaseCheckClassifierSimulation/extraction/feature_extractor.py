import pandas as pd
from nfstream import NFStreamer
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("FeatureExtractor")

def extract_features(pcap_path, selected_features=None):
    """
    Extracts specific features from a PCAP file using NFStream.
    
    Args:
        pcap_path (str): Path to the PCAP file.
        selected_features (list): List of 15 feature names to extract. 
                                  If None, uses a default set for CIC-IDS-2017.
        
    Returns:
        dict: valid_features (bool), values (dict of 15 features)
    """
    
    # Default 15 features often used in CIC-IDS-2017 analysis
    if selected_features is None:
        selected_features = [
            "bidirectional_duration_ms",
            "bidirectional_packets",
            "bidirectional_bytes",
            "src2dst_packets",
            "src2dst_bytes",
            "dst2src_packets",
            "dst2src_bytes", 
            "bidirectional_min_ps", # Packet Size
            "bidirectional_max_ps",
            "bidirectional_mean_ps",
            "bidirectional_std_ps",
            "bidirectional_min_piat_ms", # Inter-arrival Time
            "bidirectional_max_piat_ms",
            "bidirectional_mean_piat_ms",
            "bidirectional_std_piat_ms"
        ]

    try:
        # Statistical analysis=True enables feature calculation
        streamer = NFStreamer(source=pcap_path, statistical_analysis=True)
        
        # Use Pandas for robust extraction
        df = streamer.to_pandas()
        
        if df.empty:
            logger.warning(f"No flows found in {pcap_path}")
            return {"valid": False, "error": "No flows found"}
            
        # Take the first flow
        first_flow = df.iloc[0]
        
        # Extract features
        features = {}
        missing = []
        
        for feature in selected_features:
            if feature in first_flow:
                features[feature] = first_flow[feature]
                # Handle numpy types for JSON serialization
                if hasattr(features[feature], 'item'):
                     features[feature] = features[feature].item()
            else:
                missing.append(feature)
                features[feature] = 0

        if missing:
            logger.warning(f"Missing features in NFStream output: {missing}")
            
        # Get metadata
        if 'protocol_name' in first_flow:
            protocol = first_flow['protocol_name']
        elif 'application_name' in first_flow:
             protocol = first_flow['application_name']
        else:
            protocol = "Unknown"

        return {
            "valid": True,
            "features": features,
            "flow_id": f"{first_flow.get('src_ip')}:{first_flow.get('src_port')}->{first_flow.get('dst_ip')}:{first_flow.get('dst_port')}",
            "protocol": protocol
        }

    except Exception as e:
        logger.error(f"Extraction Error for {pcap_path}: {e}")
        return {"valid": False, "error": str(e)}

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        print(extract_features(sys.argv[1]))
