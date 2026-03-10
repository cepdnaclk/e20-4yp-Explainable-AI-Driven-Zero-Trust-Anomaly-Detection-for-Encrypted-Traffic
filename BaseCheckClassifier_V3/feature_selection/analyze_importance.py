import pickle
import numpy as np

def analyze_model_importance():
    model_path = '/scratch1/e20-fyp-xai-anomaly-detection/e20449Sandaru/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/BaseCheckClassifier/sdn/training/sentry_model_v2.pkl'
    
    print(f"Loading model from {model_path}...")
    with open(model_path, 'rb') as f:
        data = pickle.load(f)
        
    print(f"Data type: {type(data)}")
    if isinstance(data, dict):
        print(f"Keys in dict: {data.keys()}")
        if 'model' in data:
            model = data['model']
            print(f"Model type: {type(model)}")
        elif 'classifier' in data:
            model = data['classifier']
            print(f"Model type: {type(model)}")
        else:
            print("Cannot find model in dict.")
            return
            
        if 'features' in data:
            features = data['features']
            print(f"Features in dict: {features}")
        else:
            features = [
                'Packet Length Variance', 'Fwd Packet Length Max', 'Fwd Header Length', 'Init_Win_bytes_forward', 
                'Bwd Header Length', 'Total Length of Fwd Packets', 'Init_Win_bytes_backward', 'Bwd Packets/s', 
                'Flow IAT Min', 'Fwd IAT Min', 'Flow Bytes/s', 'Active Min', 'Bwd IAT Total', 'Flow IAT Max', 
                'Flow Duration', 'Total Fwd Packets', 'Total Bwd Packets', 'Fwd Packet Length Mean', 
                'Bwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Flow IAT Mean', 
                'Flow IAT Std', 'Fwd IAT Total', 'Fwd Packets/s', 'Down/Up Ratio', 'SYN Flag Count', 'RST Flag Count'
            ]
    else:
        model = data
        features = [
            'Packet Length Variance', 'Fwd Packet Length Max', 'Fwd Header Length', 'Init_Win_bytes_forward', 
            'Bwd Header Length', 'Total Length of Fwd Packets', 'Init_Win_bytes_backward', 'Bwd Packets/s', 
            'Flow IAT Min', 'Fwd IAT Min', 'Flow Bytes/s', 'Active Min', 'Bwd IAT Total', 'Flow IAT Max', 
            'Flow Duration', 'Total Fwd Packets', 'Total Bwd Packets', 'Fwd Packet Length Mean', 
            'Bwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Flow IAT Mean', 
            'Flow IAT Std', 'Fwd IAT Total', 'Fwd Packets/s', 'Down/Up Ratio', 'SYN Flag Count', 'RST Flag Count'
        ]

    if hasattr(model, 'feature_importances_'):
        importances = model.feature_importances_
        print("\n--- Feature Importances ---")
        
        # Sort features by importance
        indices = np.argsort(importances)[::-1]
        
        for idx in indices:
            if idx < len(features):
                print(f"{features[idx]:30s} : {importances[idx]:.6f}")
            else:
                print(f"Feature {idx} : {importances[idx]:.6f}")
    elif hasattr(model, 'coef_'):
        importances = np.abs(model.coef_[0])
        print("\n--- Feature Importances (Absolute Coefficients) ---")
        
        # Sort features by importance
        indices = np.argsort(importances)[::-1]
        
        for idx in indices:
            if idx < len(features):
                print(f"{features[idx]:30s} : {importances[idx]:.6f}")
            else:
                print(f"Feature {idx} : {importances[idx]:.6f}")
    else:
        print("Model does not have feature_importances_ or coef_ attribute.")
        print("Available attributes:", dir(model))

if __name__ == "__main__":
    analyze_model_importance()
