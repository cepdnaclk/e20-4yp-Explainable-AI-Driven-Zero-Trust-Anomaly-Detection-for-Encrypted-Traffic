import joblib
import os
import sys
import numpy as np
import pandas as pd

# Add current dir to path to find local modules
sys.path.append(os.getcwd())

from extraction.feature_extractor import extract_features

# Path to model and synthetic attack file
MODEL_PATH = "/scratch1/e20-fyp-xai-anomaly-detection/e20449Sandaru/Models/sentry_zero_leak_v1.pkl"
PCAP_PATH = "synthetic_attack.pcap"

def check_model():
    print(f"Checking model at: {MODEL_PATH}")
    if not os.path.exists(MODEL_PATH):
        print("[-] Model file not found.")
        return

    print("Attempting to load model with joblib...")
    try:
        model = joblib.load(MODEL_PATH)
        print("[+] Model loaded successfully!")
    except Exception as e:
        print(f"[-] Failed to load model: {e}")
        return

    # --- Test 1: Synthetic PCAP ---
    print(f"\n--- TEST 1: Synthetic PCAP ({PCAP_PATH}) ---")
    extraction = extract_features(PCAP_PATH)
    if extraction['valid']:
        features = extraction['features']
        print("DEBUG: Extracted Synthetic Features:")
        for k, v in features.items():
            print(f"  {k}: {v}")
        
        # Prepare input dataframe (order matters!)
        expected_features = [
            'Packet Length Variance', 'Fwd Packet Length Max', 'Fwd Header Length',
            'Init_Win_bytes_forward', 'Bwd Header Length', 'Total Length of Fwd Packets',
            'Init_Win_bytes_backward', 'Bwd Packets/s', 'Flow IAT Min', 'Fwd IAT Min',
            'Flow Bytes/s', 'Active Min', 'Bwd IAT Total', 'Flow IAT Max', 'Flow Duration'
        ]
            
        input_data = pd.DataFrame([features])
        input_data = input_data[expected_features]
            
        prediction = model.predict(input_data)[0]
        proba = model.predict_proba(input_data)
        print(f"[+] Confidence: {proba}")
    else:
        print(f"[-] Feature extraction failed: {extraction.get('error')}")

    # --- Test 2: Known Attack Vector (from Training Data) ---
    print("\n--- TEST 2: Hardcoded Known Attack Vector ---")
    # Values taken from Row 6 of TRAIN_Traffic.csv (Label: Attack)
    # Features: Packet Length Variance, Fwd Packet Length Max, Fwd Header Length, ...
    known_attack_features = {
        'Packet Length Variance': 5349395.495,
        'Fwd Packet Length Max': 391.0, 
        'Fwd Header Length': 164,
        'Init_Win_bytes_forward': 0,
        'Bwd Header Length': 232,
        'Total Length of Fwd Packets': 391.0,
        'Init_Win_bytes_backward': 235,
        'Bwd Packets/s': 0.069592989,
        'Flow IAT Min': 3.0, 
        'Fwd IAT Min': 3.0,
        'Flow Bytes/s': 119.1630807,
        'Active Min': 10000000.0,
        'Bwd IAT Total': 101000000.0, 
        'Flow IAT Max': 100000000.0, 
        'Flow Duration': 100584845
    }
    
    input_vector = pd.DataFrame([known_attack_features])
    # Ensure correct column order matches training
    input_vector = input_vector[expected_features] 
    
    prediction = model.predict(input_vector)[0]
    proba = model.predict_proba(input_vector)
    
    print(f"[+] Prediction: {prediction}")
    print(f"[+] Confidence: {proba}")
    
    if prediction == "Attack":
        print("\n[SUCCESS] The model creates correct predictions when given valid Attack features.")
    else:
        print("\n[WARNING] The model failed to predict 'Attack' even on known training data values.")

if __name__ == "__main__":
    check_model()
