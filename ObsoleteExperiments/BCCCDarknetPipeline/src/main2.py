import pandas as pd
import numpy as np

from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense
from tensorflow.keras.optimizers import Adam

from pathlib import Path

# Datasets live in ../data next to this script (see data/README.md).
DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# ------------------------------------
# 1. Load dataset
# ------------------------------------
df = pd.read_csv(DATA_DIR / "bccc_darknet.csv")
print("Original dataset shape:", df.shape)

# ------------------------------------
# 2. Keep ONLY numeric columns
# ------------------------------------
df_numeric = df.select_dtypes(include=[np.number])

# Drop label if exists (unsupervised stage)
if 'label' in df_numeric.columns:
    df_numeric = df_numeric.drop(columns=['label'])

# ------------------------------------
# 3. CRITICAL CLEANING (THIS FIXES YOUR ERROR)
# ------------------------------------
# Replace inf with NaN
df_numeric.replace([np.inf, -np.inf], np.nan, inplace=True)

# Fill NaN with column median (better than zero)
df_numeric = df_numeric.fillna(df_numeric.median())

# Clip extreme values
df_numeric = df_numeric.clip(lower=-1e6, upper=1e6)

# ------------------------------------
# 4. Scaling
# ------------------------------------
scaler = StandardScaler()
X_scaled = scaler.fit_transform(df_numeric)

print("Scaled data shape:", X_scaled.shape)

# ------------------------------------
# 5. Isolation Forest
# ------------------------------------
iso = IsolationForest(
    n_estimators=300,
    contamination=0.05,
    random_state=42,
    n_jobs=-1
)

iso_preds = iso.fit_predict(X_scaled)
iso_labels = (iso_preds == -1).astype(int)  # 1 = anomaly

# ------------------------------------
# 6. Autoencoder
# ------------------------------------
input_dim = X_scaled.shape[1]

inputs = Input(shape=(input_dim,))
x = Dense(128, activation="relu")(inputs)
x = Dense(64, activation="relu")(x)
x = Dense(32, activation="relu")(x)
x = Dense(64, activation="relu")(x)
x = Dense(128, activation="relu")(x)
outputs = Dense(input_dim, activation="linear")(x)

autoencoder = Model(inputs, outputs)
autoencoder.compile(
    optimizer=Adam(learning_rate=0.001),
    loss="mse"
)

autoencoder.fit(
    X_scaled,
    X_scaled,
    epochs=20,
    batch_size=256,
    shuffle=True,
    validation_split=0.1,
    verbose=1
)

# ------------------------------------
# 7. Autoencoder anomaly score
# ------------------------------------
reconstructions = autoencoder.predict(X_scaled)
reconstruction_error = np.mean(np.square(X_scaled - reconstructions), axis=1)

threshold = np.percentile(reconstruction_error, 95)
ae_labels = (reconstruction_error > threshold).astype(int)

# ------------------------------------
# 8. High-confidence labeling
# ------------------------------------
high_confidence = np.where(
    (iso_labels == 1) & (ae_labels == 1), 1,
    np.where(
        (iso_labels == 0) & (ae_labels == 0), 0,
        -1
    )
)

df["pseudo_label"] = high_confidence

# ------------------------------------
# 9. Keep ONLY confident rows
# ------------------------------------
final_df = df[df["pseudo_label"] != -1]

print("High-confidence dataset shape:", final_df.shape)
print(final_df["pseudo_label"].value_counts())

# ------------------------------------
# 10. Save new dataset
# ------------------------------------
final_df.to_csv(DATA_DIR / "bcc_darknet_labeled_high_confidence.csv", index=False)

print("Saved: bcc_darknet_labeled_high_confidence.csv")
