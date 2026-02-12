import os
import sys
import json
import time
import random
import logging
import asyncio
from datetime import datetime

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
NORMAL_DIR = os.path.join(parent_dir, "normal")
ATTACK_DIR = os.path.join(parent_dir, "attack")
OUTPUT_LOG = os.path.join(parent_dir, "simulation_log.json")
STATS_FILE = os.path.join(parent_dir, "dashboard", "live_stats.json")

# Ensure dashboard dir exists for stats
os.makedirs(os.path.dirname(STATS_FILE), exist_ok=True)

class SentrySwitch:
    def __init__(self):
        self.stats = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
        self.simulation_logs = []
        
        # Mock Topology IP Addresses
        self.topo = {
            "Firewall": "10.0.0.1",
            "Core": "10.0.0.254",
            "Edge": "10.40.18.12"
        }

    def generate_syslog(self, action, src_ip, dst_ip, reason):
        """Generates an RFC 5424 compliant syslog message."""
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        priority = "<131>" if action == "DROP" else "<134>"
        
        log_msg = (
            f"{priority} 1 {timestamp} SENTRY-EDGE sdn-controller - - - "
            f"[Security] Policy={action} Src={src_ip} Dst={dst_ip} Reason={reason}"
        )
        return log_msg

    def simulate_topology_events(self):
        """Simulates multi-hop traversal events."""
        path = ["Firewall", "Core-SW", "Edge-SW"]
        logger.info(f"[Topology] Packet traversing: {' -> '.join(path)}")
        return path

    def process_stream(self, file_path, ground_truth):
        """
        Orchestrates the entire flow for a single stream.
        """
        filename = os.path.basename(file_path)
        logger.info(f"--- Processing Stream: {filename} ({ground_truth}) ---")
        
        # 1. Encryption & Latency
        enc_result = simulate_encryption_and_latency(file_path)
        if not enc_result:
            return

        # 2. Topology Simulation
        topo_path = self.simulate_topology_events()
        
        # 3. Feature Extraction (from "encrypted" stream)
        ext_result = extract_features(enc_result["encrypted_path"])
        if not ext_result["valid"]:
            logger.error(f"Feature extraction failed for {filename}")
            return

        features = ext_result["features"]
        
        # 4. Decision Logic (Mock Model or Load Real One)
        # TODO: Load .pkl model here. For now, use rule-based mock for demo.
        # "Mock" accuracy: 90% correct
        if random.random() > 0.1:
            prediction = ground_truth 
        else:
            prediction = "BENIGN" if ground_truth == "ATTACK" else "ATTACK"

        # 5. Action
        if prediction == "BENIGN":
            action = "FORWARD"
            reason = "TrafficAllowed"
        else:
            action = "DROP"
            reason = "AnomalyDetected"

        # 6. Update Stats
        if ground_truth == "BENIGN":
            if prediction == "BENIGN": self.stats["TN"] += 1
            else: self.stats["FP"] += 1
        else: # ATTACK
            if prediction == "ATTACK": self.stats["TP"] += 1
            else: self.stats["FN"] += 1

        # 7. Generate Logs
        # Simulate IPs for log
        src_ip = f"192.168.1.{random.randint(2, 254)}"
        dst_ip = self.topo["Edge"]
        
        syslog_entry = self.generate_syslog(action, src_ip, dst_ip, reason)
        
        log_entry = {
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "stream_id": f"{src_ip} -> {dst_ip}",
            "input_file": filename,
            "topology_path": topo_path,
            "latency_ms": enc_result["latency_ms"],
            "features": features,
            "ground_truth": ground_truth,
            "prediction": prediction,
            "action": action,
            "syslog_entry": syslog_entry
        }
        
        self.simulation_logs.insert(0, log_entry) # Prepend for "latest first"
        self.simulation_logs = self.simulation_logs[:50] # Keep last 50
        
        # Save to file
        with open(OUTPUT_LOG, "w") as f:
            json.dump(self.simulation_logs, f, indent=2)
            
        with open(STATS_FILE, "w") as f:
            json.dump(self.stats, f)
            
        logger.info(f"[Decision] {prediction} -> {action}")
        logger.info(f"[Syslog] {syslog_entry}")

    def run(self):
        logger.info("Starting Sentry Controller...")
        
        # Create directories if not exist (for demo purposes)
        os.makedirs(NORMAL_DIR, exist_ok=True)
        os.makedirs(ATTACK_DIR, exist_ok=True)
        
        while True:
            # Main Loop: Scan folders for new files or iterate existing
            # For this demo, we iterate existing files once then sleep
            
            files_found = False
            
            # Process NORMAL
            for f in os.listdir(NORMAL_DIR):
                if f.endswith(".pcap"):
                    self.process_stream(os.path.join(NORMAL_DIR, f), "BENIGN")
                    files_found = True
                    
            # Process ATTACK
            for f in os.listdir(ATTACK_DIR):
                if f.endswith(".pcap"):
                    self.process_stream(os.path.join(ATTACK_DIR, f), "ATTACK")
                    files_found = True
            
            if not files_found:
                logger.warning("No PCAP files found in normal/ or attack/ directories. Waiting...")
            
            time.sleep(5) # Wait before re-scanning or ending
            # break # Uncomment to run once

if __name__ == "__main__":
    sentry = SentrySwitch()
    try:
        sentry.run()
    except KeyboardInterrupt:
        print("Stopping Sentry Controller...")
