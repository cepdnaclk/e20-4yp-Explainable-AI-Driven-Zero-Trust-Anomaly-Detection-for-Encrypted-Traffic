import os
import sys
import json
import time
import random
import logging
import joblib
from datetime import datetime, timezone
import pandas as pd

# Logic to import sibling modules
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from encryption.traffic_encryptor import simulate_encryption_and_latency
from extraction.feature_extractor import extract_features

# Setup Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SentryController")

# Configuration
DATASET_SOURCE_DIR = "/scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/Friday-WorkingHours_labeled"
MODEL_PATH = "/scratch1/e20-fyp-xai-anomaly-detection/e20449Sandaru/Models/sentry_zero_leak_v1.pkl"
OUTPUT_LOG = os.path.join(parent_dir, "simulation_log.json")
STATS_FILE = os.path.join(parent_dir, "dashboard", "live_stats.json")
SLEEP_INTERVAL = 2 # Seconds between streams to simulate "live"

# Ensure dashboard dir exists for stats
os.makedirs(os.path.dirname(STATS_FILE), exist_ok=True)

class SentrySwitch:
    def __init__(self):
        self.stats = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
        self.simulation_logs = []
        self.model = self.load_model()
        
        # Mock Topology IP Addresses
        self.topo = {
            "Firewall": "10.0.0.1",
            "Core": "10.0.0.254",
            "Edge": "10.40.18.12"
        }

    def load_model(self):
        try:
            model = joblib.load(MODEL_PATH)
            logger.info(f"Model loaded successfully from {MODEL_PATH}")
            return model
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return None

    def generate_syslog(self, action, src_ip, dst_ip, reason):
        """Generates an RFC 5424 compliant syslog message."""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        priority = "<131>" if action == "DROP" else "<134>"
        
        log_msg = (
            f"{priority} 1 {timestamp} SENTRY-EDGE sdn-controller - - - "
            f"[Security] Policy={action} Src={src_ip} Dst={dst_ip} Reason={reason}"
        )
        return log_msg

    def simulate_topology_events(self):
        """Simulates multi-hop traversal events."""
        path = ["Firewall", "Core-SW", "Edge-SW"]
        # logger.info(f"[Topology] Packet traversing: {' -> '.join(path)}")
        return path

    def process_stream(self, file_path, ground_truth_label):
        """
        Orchestrates the entire flow for a single stream.
        ground_truth_label: 'Normal' or 'Attack' (based on folder structure)
        """
        filename = os.path.basename(file_path)
        logger.info(f"--- Processing Stream: {filename} ({ground_truth_label}) ---")
        
        # 1. Encryption & Latency (Simulation)
        enc_result = simulate_encryption_and_latency(file_path)
        if not enc_result:
            return

        # 2. Topology Simulation
        topo_path = self.simulate_topology_events()
        
        # 3. Feature Extraction
        # Extract features from the "encrypted" stream/path returned by the encryptor
        ext_result = extract_features(enc_result["encrypted_path"])
                
        if not ext_result["valid"]:
            logger.error(f"Feature extraction failed for {filename}")
            return

        features_dict = ext_result["features"]
        ordered_features = ext_result["ordered_features"]
        
        # 4. Decision Logic (Using Real Model)
        prediction = "UNKNOWN"
        probability = 0.0
        
        if self.model:
            try:
                # Reshape for single sample
                X_input = [ordered_features] 
                # Predict
                pred_label = self.model.predict(X_input)[0] 
                prediction = pred_label # "Normal" or "Attack"
                
                # Try getting probability if supported
                if hasattr(self.model, "predict_proba"):
                    probs = self.model.predict_proba(X_input)
                    # Assuming classes are ['Attack', 'Normal'] or similar, grab max prob
                    probability = max(probs[0])
            except Exception as e:
                logger.error(f"Prediction Error: {e}")
                prediction = "Normal" # Fail open default
        else:
            logger.warning("No model loaded. Defaulting to Normal.")
            prediction = "Normal"

        # 5. Action
        if prediction == "Normal":
            action = "FORWARD"
            reason = "TrafficAllowed"
        else:
            action = "DROP"
            reason = "AnomalyDetected"

        # 6. Update Stats
        # Ground truth mapping: Folder names might be "Normal" or "Attack"
        # Prediction output is "Normal" or "Attack"
        
        gt_norm = ground_truth_label.lower() 
        pred_norm = prediction.lower()

        if "normal" in gt_norm:
            if "normal" in pred_norm: self.stats["TN"] += 1
            else: self.stats["FP"] += 1
        else: # Attack
            if "attack" in pred_norm: self.stats["TP"] += 1
            else: self.stats["FN"] += 1

        # 7. Generate Logs
        # Simulate IPs for log (if not present in extracted features)
        src_ip = f"192.168.1.{random.randint(2, 254)}"
        dst_ip = self.topo["Edge"]
        
        syslog_entry = self.generate_syslog(action, src_ip, dst_ip, reason)
        
        log_entry = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "stream_id": f"{src_ip} -> {dst_ip}",
            "input_file": filename,
            "topology_path": topo_path,
            "latency_ms": enc_result["latency_ms"],
            "features": features_dict,
            "ground_truth": ground_truth_label,
            "prediction": prediction,
            "confidence": f"{probability:.2f}",
            "action": action,
            "syslog_entry": syslog_entry
        }
        
        self.simulation_logs.insert(0, log_entry) # Prepend for "latest first"
        self.simulation_logs = self.simulation_logs[:100] # Keep last 100
        
        # Save to file
        with open(OUTPUT_LOG, "w") as f:
            json.dump(self.simulation_logs, f, indent=2)
            
        with open(STATS_FILE, "w") as f:
            json.dump(self.stats, f)
            
        logger.info(f"[Decision] {prediction} (Conf: {probability:.2f}) -> {action}")

    def run(self):
        logger.info(f"Starting Sentry Controller Simulation reading from {DATASET_SOURCE_DIR}...")
        
        # Recursively find all PCAP files
        pcap_files = []
        for root, dirs, files in os.walk(DATASET_SOURCE_DIR):
            for file in files:
                if file.endswith(".pcap"):
                    # Determine ground truth from folder structure
                    # Expected structure: .../Friday-WorkingHours_labeled/Normal/stream.pcap
                    # or .../Friday-WorkingHours_labeled/Attack/stream.pcap
                    path = os.path.join(root, file)
                    folder_name = os.path.basename(root)
                    
                    if "normal" in folder_name.lower():
                        ground_truth = "Normal"
                    else:
                        ground_truth = "Attack"
                        
                    pcap_files.append((path, ground_truth))
        
        if not pcap_files:
            logger.error(f"No PCAP files found in {DATASET_SOURCE_DIR}")
            return

        # Shuffle to simulate mixed traffic or sort optionally
        random.shuffle(pcap_files)
        
        logger.info(f"Found {len(pcap_files)} streams. Starting live playback...")

        try:
            for file_path, label in pcap_files:
                self.process_stream(file_path, label)
                
                # Simulate live delay
                sleep_time = random.uniform(0.5, SLEEP_INTERVAL)
                time.sleep(sleep_time)
                
        except KeyboardInterrupt:
            logger.info("Simulation stopping...")

if __name__ == "__main__":
    sentry = SentrySwitch()
    try:
        sentry.run()
    except KeyboardInterrupt:
        print("Stopping Sentry Controller...")
