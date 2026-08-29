import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

from pathlib import Path

# Datasets live in ../data next to this script (see data/README.md).
DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# ------------------------------------
# 1. Load dataset
# ------------------------------------
df = pd.read_csv(DATA_DIR / "bcc_darknet_labeled_high_confidence.csv")
print("Dataset shape:", df.shape)

# ------------------------------------
# 2. Separate features & label
# ------------------------------------
y = df["pseudo_label"]
X = df.drop(columns=["pseudo_label"])

# Keep numeric only
X = X.select_dtypes(include=[np.number])

# ------------------------------------
# 3. CRITICAL CLEANING (DO NOT SKIP)
# ------------------------------------
# Replace inf/-inf
X.replace([np.inf, -np.inf], np.nan, inplace=True)

# Fill NaN with median
X = X.fillna(X.median())

# Clip extreme values
X = X.clip(lower=-1e6, upper=1e6)

# ------------------------------------
# 4. Train-test split (80/20)
# ------------------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("Train size:", X_train.shape)
print("Test size:", X_test.shape)

# ------------------------------------
# 5. Scaling
# ------------------------------------
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# ------------------------------------
# 6. Random Forest Classifier
# ------------------------------------
rf = RandomForestClassifier(
    n_estimators=300,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1
)

rf.fit(X_train_scaled, y_train)

# ------------------------------------
# 7. Prediction
# ------------------------------------
y_pred = rf.predict(X_test_scaled)
y_prob = rf.predict_proba(X_test_scaled)[:, 1]

# ------------------------------------
# 8. Evaluation
# ------------------------------------
print("\n=== Classification Report ===")
print(classification_report(y_test, y_pred))

print("\n=== Confusion Matrix ===")
print(confusion_matrix(y_test, y_pred))

print("\nROC-AUC:", roc_auc_score(y_test, y_prob))
