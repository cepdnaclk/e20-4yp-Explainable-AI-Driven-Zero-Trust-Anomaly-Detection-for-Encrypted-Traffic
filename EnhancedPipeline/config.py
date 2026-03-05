"""
config.py — EnhancedPipeline Configuration
==========================================
Zero-Trust XAI Anomaly Detection | University of Peradeniya
e20420Janith

All tunable hyperparameters live here.  Import this module anywhere in
EnhancedPipeline to guarantee a single source of truth.

Usage:
    from EnhancedPipeline.config import CFG
    print(CFG.DDL_N_FEATURES)          # 30
"""

import os
from dataclasses import dataclass, field
from typing import Optional

# ── Project root (two levels up from this file) ──────────────────────────────
_EP_DIR      = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_EP_DIR)
DATASET_DIR  = os.path.join(PROJECT_ROOT, "dataset")
MODEL_DIR    = os.path.join(PROJECT_ROOT, "models")


@dataclass
class EnhancedPipelineConfig:
    """
    Single configuration object for the entire Enhanced Pipeline.

    Change values here — never scatter magic numbers through the code.
    """

    # ── Dataset paths ────────────────────────────────────────────────────────
    TRAIN_CSV: str = os.path.join(DATASET_DIR, "TRAIN_Traffic.csv")
    TEST_CSV:  str = os.path.join(DATASET_DIR, "TEST_Traffic.csv")
    LABEL_COL: str = "Label"
    NORMAL_LABEL: str = "Normal"

    # ── Model paths ──────────────────────────────────────────────────────────
    DDL_MODEL_PATH: str = os.path.join(MODEL_DIR, "ddl_30feat.pkl")
    IF_MODEL_PATH:  str = os.path.join(MODEL_DIR, "isolation_forest.pkl")

    # ── DDL hyperparameters ──────────────────────────────────────────────────
    DDL_N_FEATURES:     int   = 30          # Must match ddl_feature_extractor.py
    DDL_N_ATOMS_L1:     int   = 64          # Layer-1 dictionary atoms
    DDL_N_ATOMS_L2:     int   = 128         # Layer-2 dictionary atoms
    DDL_N_ATOMS_L3:     int   = 0           # 0 = disable 3rd layer
    DDL_SPARSITY:       float = 0.1         # ISTA sparsity weight (lambda)
    DDL_LEARNING_RATE:  float = 0.005
    DDL_EPOCHS:         int   = 150
    DDL_BATCH_SIZE:     int   = 64
    DDL_THRESHOLD_MODE: str   = "f1_optimal"  # "f1_optimal" | "percentile"
    DDL_THRESHOLD_PCT:  int   = 95            # Used only for mode="percentile"

    # ── Isolation Forest (second-opinion) ────────────────────────────────────
    IF_N_ESTIMATORS:  int   = 100
    IF_MAX_SAMPLES:   str   = "auto"
    IF_CONTAMINATION: float = 0.05          # Expected anomaly fraction

    # ── Adaptive feature selection ──────────────────────────────────────────
    TOP_K_FEATURES:   int = 25              # Number of DDL features to keep
    RETRAIN_EVERY_N:  int = 500             # Flows between MI re-ranking

    # ── XAI (SHAP + LIME) ───────────────────────────────────────────────────
    SHAP_NSAMPLES:    int = 100
    LIME_NSAMPLES:    int = 500
    LIME_KERNEL_WIDTH: float = 0.75

    # ── REST API ─────────────────────────────────────────────────────────────
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 5001

    # ── SDN Buffer ───────────────────────────────────────────────────────────
    BUFFER_MAX_SIZE:  int = 1000            # Max buffered flows
    BUFFER_TIMEOUT_MS: int = 30_000        # Drop buffer entry after 30 s

    # ── Streamlit dashboard ──────────────────────────────────────────────────
    DASHBOARD_REFRESH_SEC: int = 2
    DASHBOARD_HISTORY_N:   int = 500        # Recent flows to display

    # ── Logging / profiling ──────────────────────────────────────────────────
    LOG_LEVEL: str = "INFO"
    ENABLE_PROFILING: bool = True           # Record per-stage latency


# Singleton used everywhere
CFG = EnhancedPipelineConfig()
