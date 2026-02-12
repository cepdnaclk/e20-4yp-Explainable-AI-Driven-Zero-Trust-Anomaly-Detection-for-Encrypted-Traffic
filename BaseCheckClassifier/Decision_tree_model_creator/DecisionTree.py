import pandas as pd
import numpy as np
import os
import joblib
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

# ==========================================
# 1. ABSOLUTE PATH CONFIGURATION
# ==========================================
# Update these once you log into the server and run 'pwd'
BASE_DIR = "/home/e20449/project" 
DATA_DIR = "/scratch1/e20-fyp-xai-anomaly-detection/CICDataset/Processed-Data" 
MODEL_DIR = "/scratch1/e20-fyp-xai-anomaly-detection/e20449Sandaru/Models"

# Ensure the model directory exists
os.makedirs(MODEL_DIR, exist_ok=True)

# Define absolute file locations
TRAIN_FILE = os.path.join(DATA_DIR, 'TRAIN_Traffic.csv')
TEST_FILE = os.path.join(DATA_DIR, 'TEST_Traffic.csv')
MODEL_OUT = os.path.join(MODEL_DIR, 'sentry_zero_leak_v1.pkl')
FEAT_OUT = os.path.join(MODEL_DIR, 'sentry_features.pkl')
PLOT_OUT = os.path.join(MODEL_DIR, 'sentry_confusion_matrix.png')

# ==========================================
# 2. DATA LOADING
# ==========================================
print(f"Reading data from: {DATA_DIR}...")
train_df = pd.read_csv(TRAIN_FILE)
test_df = pd.read_csv(TEST_FILE)

# The Top 15 Behavioral Features identified during selection
selected_features = [
    'Packet Length Variance', 'Fwd Packet Length Max', 'Fwd Header Length',
    'Init_Win_bytes_forward', 'Bwd Header Length', 'Total Length of Fwd Packets',
    'Init_Win_bytes_backward', 'Bwd Packets/s', 'Flow IAT Min', 'Fwd IAT Min',
    'Flow Bytes/s', 'Active Min', 'Bwd IAT Total', 'Flow IAT Max', 'Flow Duration'
]

X_train = train_df[selected_features]
y_train = train_df['Label']
X_test = test_df[selected_features]
y_test = test_df['Label']

# ==========================================
# 3. ZERO-LEAK MODEL TRAINING
# ==========================================
# A weight of 50 for Attack means missing an attack is 50x worse than a False Positive
custom_weights = {'Normal': 1, 'Attack': 50}

sentry_model = DecisionTreeClassifier(
    criterion='entropy',
    max_depth=15,
    class_weight=custom_weights,
    random_state=42
)

print("Training Sentry Model (Zero-Leak Mode)...")
sentry_model.fit(X_train, y_train)

# ==========================================
# 4. PERSISTENCE & EVALUATION
# ==========================================
# Save the model and feature list for deployment
joblib.dump(sentry_model, MODEL_OUT)
joblib.dump(selected_features, FEAT_OUT)
print(f"✅ Success! Model saved to: {MODEL_OUT}")

# Generate Metrics
y_pred = sentry_model.predict(X_test)
print("\n🛡️ SENTRY PERFORMANCE REPORT")
print(classification_report(y_test, y_pred))

# Save Confusion Matrix as PNG for server download
cm = confusion_matrix(y_test, y_pred, labels=['Normal', 'Attack'])
plt.figure(figsize=(8,6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Reds', 
            xticklabels=['Normal', 'Attack'], 
            yticklabels=['Normal', 'Attack'])
plt.title('Zero-Trust Sentry Anomaly Audit')
plt.xlabel('Predicted Label')
plt.ylabel('Actual Label')
plt.savefig(PLOT_OUT)
print(f"📊 Visual report saved to: {PLOT_OUT}")