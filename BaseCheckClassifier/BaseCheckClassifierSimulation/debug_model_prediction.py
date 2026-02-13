import joblib
import pandas as pd
import numpy as np

MODEL_PATH = "/scratch1/e20-fyp-xai-anomaly-detection/e20449Sandaru/Models/sentry_zero_leak_v1.pkl"

def debug_prediction():
    print(f"Loading model from {MODEL_PATH}")
    model = joblib.load(MODEL_PATH)
    
    # Features from my extraction run
    features = {
        'Packet Length Variance': 241325.1364992675, 
        'Fwd Packet Length Max': 1513, 
        'Fwd Header Length': 40124, 
        'Init_Win_bytes_forward': 8192, 
        'Bwd Header Length': 13244, 
        'Total Length of Fwd Packets': 429652, 
        'Init_Win_bytes_backward': 8192, 
        'Bwd Packets/s': 0.08071568230112362, 
        'Flow IAT Min': 0, 
        'Fwd IAT Min': 0, 
        'Flow Bytes/s': 109.13199184357056, 
        'Active Min': 4100814000, 
        'Bwd IAT Total': 4099927000, 
        'Flow IAT Max': 109965000, 
        'Flow Duration': 4100814000
    }
    
    # Ensure correct order
    feature_names = [
        'Packet Length Variance', 'Fwd Packet Length Max', 'Fwd Header Length',
        'Init_Win_bytes_forward', 'Bwd Header Length', 'Total Length of Fwd Packets',
        'Init_Win_bytes_backward', 'Bwd Packets/s', 'Flow IAT Min', 'Fwd IAT Min',
        'Flow Bytes/s', 'Active Min', 'Bwd IAT Total', 'Flow IAT Max', 'Flow Duration'
    ]
    
    X = [features[k] for k in feature_names]
    print(f"Input Features: {X}")
    
    try:
        pred = model.predict([X])
        print(f"Prediction: {pred}")
        
        probs = model.predict_proba([X])
        print(f"Probabilities: {probs}")
        
        # Check decision path if possible (DecisionTree)
        if hasattr(model, 'tree_'):
            path = model.decision_path([X])
            print("Decision Path:")
            # Get node indices
            node_indices = path.indices
            for node_id in node_indices:
                threshold = model.tree_.threshold[node_id]
                feature_idx = model.tree_.feature[node_id]
                feature_name = feature_names[feature_idx] if feature_idx >= 0 else "Leaf"
                val = X[feature_idx] if feature_idx >= 0 else None
                print(f"Node {node_id}: Feature {feature_name} ({val}) <= {threshold}?")
                
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    debug_prediction()
