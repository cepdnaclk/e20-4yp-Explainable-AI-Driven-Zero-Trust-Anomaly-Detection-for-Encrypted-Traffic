# main.py
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense
from matplotlib import rcParams

from pathlib import Path

# Datasets live in ../data next to this script (see data/README.md).
DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# -----------------------------
# Step 1: Load Dataset
# -----------------------------
data_path = DATA_DIR / "bccc_darknet.csv"
data = pd.read_csv(data_path)
print("Dataset shape:", data.shape)
print("Columns:", data.columns.tolist())

# -----------------------------
# Step 2: Preprocess
# -----------------------------
features = data.select_dtypes(include=['float64', 'int64'])

# Replace inf/-inf with NaN
features.replace([np.inf, -np.inf], np.nan, inplace=True)

# Fill missing values with 0
features.fillna(0, inplace=True)

# Optional: clip extremely large values to avoid scaling overflow
features = features.clip(-1e9, 1e9)

# Scale features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(features)

# -----------------------------
# Step 3: Isolation Forest
# -----------------------------
iso_model = IsolationForest(n_estimators=200, contamination=0.05, random_state=42)
iso_model.fit(X_scaled)
iso_preds = iso_model.predict(X_scaled)
iso_anomalies = np.where(iso_preds == -1)[0]
print(f"Isolation Forest detected {len(iso_anomalies)} anomalies.")

# -----------------------------
# Step 4: Autoencoder
# -----------------------------
input_dim = X_scaled.shape[1]
input_layer = Input(shape=(input_dim,))
encoded = Dense(32, activation='relu')(input_layer)
encoded = Dense(16, activation='relu')(encoded)
decoded = Dense(32, activation='relu')(encoded)
output_layer = Dense(input_dim, activation='linear')(decoded)
autoencoder = Model(inputs=input_layer, outputs=output_layer)
autoencoder.compile(optimizer='adam', loss='mse')
autoencoder.fit(X_scaled, X_scaled, epochs=50, batch_size=256, validation_split=0.1, shuffle=True)
reconstructions = autoencoder.predict(X_scaled)
mse = np.mean(np.square(X_scaled - reconstructions), axis=1)
threshold = np.percentile(mse, 95)
ae_anomalies = np.where(mse > threshold)[0]
print(f"Autoencoder detected {len(ae_anomalies)} anomalies.")

# -----------------------------
# Step 5: Visualization
# -----------------------------
pca = PCA(n_components=2)
X_pca = pca.fit_transform(X_scaled)

# plt.figure(figsize=(8,6))
# plt.scatter(X_pca[:,0], X_pca[:,1], c='blue', label='Normal', alpha=0.5)
# plt.scatter(X_pca[iso_anomalies,0], X_pca[iso_anomalies,1], c='red', label='Anomaly (IF)', alpha=0.7)
# plt.scatter(X_pca[ae_anomalies,0], X_pca[ae_anomalies,1], c='green', label='Anomaly (AE)', alpha=0.5)
# plt.title("Anomaly Detection in BCCC Darknet Dataset")
# plt.legend()
# plt.show()

# -----------------------------
# Step 5: Visualization (Improved)
# -----------------------------

rcParams['figure.figsize'] = (10, 7)

# Reduce opacity for normal points to make anomalies visible
plt.scatter(X_pca[:, 0], X_pca[:, 1], c='blue', label='Normal', alpha=0.2)

# Plot Isolation Forest anomalies
plt.scatter(X_pca[iso_anomalies, 0], X_pca[iso_anomalies, 1],
            c='red', label=f'Anomaly (IF) [{len(iso_anomalies)}]', alpha=0.8)

# Plot Autoencoder anomalies
plt.scatter(X_pca[ae_anomalies, 0], X_pca[ae_anomalies, 1],
            c='green', label=f'Anomaly (AE) [{len(ae_anomalies)}]', alpha=0.6)

# Highlight points detected by BOTH models
overlap_anomalies = np.intersect1d(iso_anomalies, ae_anomalies)
plt.scatter(X_pca[overlap_anomalies, 0], X_pca[overlap_anomalies, 1],
            c='orange', label=f'Overlap IF+AE [{len(overlap_anomalies)}]', alpha=1, edgecolors='black', s=80)

plt.title("Anomaly Detection in BCCC Darknet Dataset (Improved)")
plt.xlabel("PCA Component 1")
plt.ylabel("PCA Component 2")
plt.legend()
plt.grid(True)
plt.show()

# Print summary
print("Number of anomalies detected by Isolation Forest:", len(iso_anomalies))
print("Number of anomalies detected by Autoencoder:", len(ae_anomalies))
print("Number of anomalies detected by both models:", len(overlap_anomalies))

