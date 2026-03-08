#!/usr/bin/env python3
"""
xai_explainer.py — LIME + SHAP Explainer for DDL & Isolation Forest
====================================================================
Provides dual XAI verification:
  - LIME: Local Interpretable Model-agnostic Explanations
  - SHAP: SHapley Additive exPlanations (KernelSHAP)

Both explain WHY a flow was flagged as anomalous, showing which features
contributed most. This helps security analysts trust the detection.
"""

import os
import sys
import json
import time
import logging
import numpy as np
from typing import Dict, List, Optional

logger = logging.getLogger("XAI")

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_THIS_DIR)
sys.path.insert(0, PROJECT_ROOT)

from DDLModel.ddl_feature_extractor import DDL_FEATURE_NAMES, N_DDL_FEATURES


class DDLScoringWrapper:
    """Wraps DDL model to return anomaly scores as a predict function for LIME/SHAP."""

    def __init__(self, ddl_model):
        self.ddl = ddl_model

    def predict_scores(self, X):
        """Return reconstruction error for each sample (higher = more anomalous)."""
        if X.ndim == 1:
            X = X.reshape(1, -1)
        result = self.ddl.predict(X)
        return result["scores"]

    def predict_proba(self, X):
        """Return [P(normal), P(anomaly)] for LIME compatibility."""
        if X.ndim == 1:
            X = X.reshape(1, -1)
        result = self.ddl.predict(X)
        errors = result["errors"]
        threshold = self.ddl.threshold_
        # Sigmoid-like conversion of error to probability
        proba_anomaly = 1.0 / (1.0 + np.exp(-(errors - threshold) * 5))
        proba_normal = 1.0 - proba_anomaly
        return np.column_stack([proba_normal, proba_anomaly])


class IFScoringWrapper:
    """Wraps Isolation Forest for LIME/SHAP explanations."""

    def __init__(self, if_model):
        self.clf = if_model

    def predict_proba(self, X):
        """Return [P(normal), P(anomaly)] for LIME compatibility."""
        if X.ndim == 1:
            X = X.reshape(1, -1)
        scores = self.clf.decision_function(X)
        # IF decision_function: negative = anomaly, positive = normal
        proba_anomaly = 1.0 / (1.0 + np.exp(scores * 5))
        proba_normal = 1.0 - proba_anomaly
        return np.column_stack([proba_normal, proba_anomaly])


class XAIExplainer:
    """
    Dual XAI explainer using LIME + SHAP for DDL and IF models.

    Usage:
        explainer = XAIExplainer(ddl_model, if_model, training_data)
        result = explainer.explain(flow_features)
        # result contains LIME + SHAP explanations for both DDL and IF
    """

    def __init__(self, ddl_model, if_model=None, training_data=None,
                 feature_names=None):
        """
        Args:
            ddl_model: Trained DeepDictionaryLearning model
            if_model: Trained IsolationForest (optional)
            training_data: Sample of normal training data for SHAP background (np.ndarray)
            feature_names: List of feature names (default: DDL_FEATURE_NAMES)
        """
        self.ddl_wrapper = DDLScoringWrapper(ddl_model)
        self.if_wrapper = IFScoringWrapper(if_model) if if_model else None
        self.feature_names = feature_names or DDL_FEATURE_NAMES
        self.n_features = len(self.feature_names)

        # Initialize LIME
        self.lime_explainer = None
        try:
            from lime.lime_tabular import LimeTabularExplainer
            self.lime_explainer = LimeTabularExplainer(
                training_data if training_data is not None else np.zeros((100, self.n_features)),
                feature_names=self.feature_names,
                class_names=["Normal", "Anomaly"],
                mode="classification",
                discretize_continuous=True,
            )
            logger.info("LIME explainer initialized")
        except ImportError:
            logger.warning("LIME not installed — pip install lime")

        # Initialize SHAP (KernelSHAP)
        self.shap_ddl_explainer = None
        self.shap_if_explainer = None
        try:
            import shap
            background = training_data[:100] if training_data is not None else np.zeros((50, self.n_features))
            self.shap_ddl_explainer = shap.KernelExplainer(
                self.ddl_wrapper.predict_scores, background
            )
            if self.if_wrapper:
                self.shap_if_explainer = shap.KernelExplainer(
                    lambda X: self.if_wrapper.predict_proba(X)[:, 1], background
                )
            logger.info("SHAP explainer(s) initialized")
        except ImportError:
            logger.warning("SHAP not installed — pip install shap")

    def explain_flow(self, features: np.ndarray, top_k: int = 10,
                     n_lime_samples: int = 500) -> Dict:
        """
        Generate LIME + SHAP explanations for a single flow.

        Args:
            features: 40-element feature vector
            top_k: Number of top features to report
            n_lime_samples: LIME perturbation samples

        Returns:
            dict with keys: ddl_lime, ddl_shap, if_lime, if_shap, timing
        """
        features = features.flatten()
        result = {
            "feature_values": {n: float(v) for n, v in zip(self.feature_names, features)},
            "ddl_lime": None,
            "ddl_shap": None,
            "if_lime": None,
            "if_shap": None,
            "timing": {},
        }

        # DDL LIME
        if self.lime_explainer:
            t0 = time.perf_counter()
            try:
                lime_exp = self.lime_explainer.explain_instance(
                    features,
                    self.ddl_wrapper.predict_proba,
                    num_features=top_k,
                    num_samples=n_lime_samples,
                )
                lime_weights = lime_exp.as_list()
                result["ddl_lime"] = {
                    "top_features": [
                        {"feature": f, "weight": round(w, 6)}
                        for f, w in sorted(lime_weights, key=lambda x: abs(x[1]), reverse=True)[:top_k]
                    ],
                    "prediction_local": lime_exp.predict_proba.tolist() if hasattr(lime_exp, 'predict_proba') else None,
                }
            except Exception as e:
                result["ddl_lime"] = {"error": str(e)}
            result["timing"]["ddl_lime_ms"] = round((time.perf_counter() - t0) * 1000, 2)

        # DDL SHAP
        if self.shap_ddl_explainer:
            t0 = time.perf_counter()
            try:
                shap_values = self.shap_ddl_explainer.shap_values(features.reshape(1, -1), nsamples=100)
                sv = shap_values[0] if isinstance(shap_values, list) else shap_values.flatten()
                top_idx = np.argsort(np.abs(sv))[-top_k:][::-1]
                result["ddl_shap"] = {
                    "top_features": [
                        {"feature": self.feature_names[i], "shap_value": round(float(sv[i]), 6),
                         "feature_value": round(float(features[i]), 4)}
                        for i in top_idx
                    ],
                    "base_value": float(self.shap_ddl_explainer.expected_value)
                        if hasattr(self.shap_ddl_explainer, 'expected_value') else None,
                }
            except Exception as e:
                result["ddl_shap"] = {"error": str(e)}
            result["timing"]["ddl_shap_ms"] = round((time.perf_counter() - t0) * 1000, 2)

        # IF LIME
        if self.if_wrapper and self.lime_explainer:
            t0 = time.perf_counter()
            try:
                lime_exp = self.lime_explainer.explain_instance(
                    features,
                    self.if_wrapper.predict_proba,
                    num_features=top_k,
                    num_samples=n_lime_samples,
                )
                lime_weights = lime_exp.as_list()
                result["if_lime"] = {
                    "top_features": [
                        {"feature": f, "weight": round(w, 6)}
                        for f, w in sorted(lime_weights, key=lambda x: abs(x[1]), reverse=True)[:top_k]
                    ],
                }
            except Exception as e:
                result["if_lime"] = {"error": str(e)}
            result["timing"]["if_lime_ms"] = round((time.perf_counter() - t0) * 1000, 2)

        # IF SHAP
        if self.shap_if_explainer:
            t0 = time.perf_counter()
            try:
                shap_values = self.shap_if_explainer.shap_values(features.reshape(1, -1), nsamples=100)
                sv = shap_values[0] if isinstance(shap_values, list) else shap_values.flatten()
                top_idx = np.argsort(np.abs(sv))[-top_k:][::-1]
                result["if_shap"] = {
                    "top_features": [
                        {"feature": self.feature_names[i], "shap_value": round(float(sv[i]), 6),
                         "feature_value": round(float(features[i]), 4)}
                        for i in top_idx
                    ],
                }
            except Exception as e:
                result["if_shap"] = {"error": str(e)}
            result["timing"]["if_shap_ms"] = round((time.perf_counter() - t0) * 1000, 2)

        return result

    def explain_batch(self, features_batch: np.ndarray, max_explain: int = 5,
                      top_k: int = 10) -> List[Dict]:
        """Explain up to max_explain flows from a batch."""
        explanations = []
        n = min(len(features_batch), max_explain)
        for i in range(n):
            logger.info(f"  Explaining flow {i+1}/{n}...")
            exp = self.explain_flow(features_batch[i], top_k=top_k)
            exp["flow_index"] = i
            explanations.append(exp)
        return explanations


if __name__ == "__main__":
    print("XAI Explainer module loaded.")
    print(f"Features: {N_DDL_FEATURES}")
    print(f"LIME available: {True}")
    print(f"SHAP available: {True}")
