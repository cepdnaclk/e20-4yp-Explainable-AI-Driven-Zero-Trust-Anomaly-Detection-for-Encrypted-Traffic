"""
EnhancedPipeline/dual_xai.py — SHAP + LIME Combined Explainability
====================================================================
Zero-Trust Anomaly Detection | University of Peradeniya

WHY DUAL XAI?
-------------
SHAP and LIME are complementary explanation methods:

  SHAP KernelExplainer:
    - Game-theoretic Shapley values
    - Exact allocation of feature contributions to the anomaly score
    - Slower (O(n_background × n_perturbations))
    - Consistent across model calls

  LIME TabularExplainer:
    - Local linear approximation around the query point
    - Faster for single samples
    - Provides signed coefficients (positive = toward anomaly)

  DDL-native:
    - Per-feature reconstruction error (model-specific, not model-agnostic)
    - Zero overhead (computed during the DDL forward pass)

AGREEMENT ANALYSIS:
  When all three methods agree on the same top-3 features → HIGH CONFIDENCE
  When 2/3 agree → MEDIUM CONFIDENCE
  This corroboration signal is displayed in the XAI report.

REFERENCES:
  - Research Papers/Interpretable Anomaly Detection in Encrypted Traffic Using SHAP.pdf
  - Research Papers/XAI-IoT_An_Explainable_AI_Framework_for_Enhancing_Anomaly_Detection_in_IoT_Systems.pdf
  - Research Papers/Unveiling anomalies_ a survey on XAI-based anomaly detection for.pdf
"""

import numpy as np
import logging
import time
from typing import Optional, List, Dict, Any

logger = logging.getLogger("DualXAI")


class DualXAIExplainer:
    """
    Provides three complementary explanations for a DDL decision:
      1. DDL-native reconstruction error decomposition
      2. SHAP KernelExplainer (model-agnostic, Shapley values)
      3. LIME TabularExplainer (local linear approximation)

    Produces an agreement report showing feature confidence across methods.
    """

    def __init__(self, ddl_model, background_data: np.ndarray,
                 feature_names: List[str],
                 shap_nsamples: int = 100,
                 lime_nsamples: int = 500):
        """
        Args:
            ddl_model:       Fitted DeepDictionaryLearning instance.
            background_data: Normal traffic feature vectors (n, 30) for explainers.
            feature_names:   List of 30 feature names.
            shap_nsamples:   Perturbation samples for SHAP (more = more accurate).
            lime_nsamples:   Perturbation samples for LIME.
        """
        self.ddl          = ddl_model
        self.feature_names = feature_names
        self.background   = background_data
        self.shap_nsamples = shap_nsamples
        self.lime_nsamples = lime_nsamples
        self.n_features   = len(feature_names)

        self._shap_explainer = None
        self._lime_explainer = None

        self._init_shap()
        self._init_lime()

    def _init_shap(self):
        """Initialize SHAP KernelExplainer with background samples."""
        try:
            import shap

            bg = self.background
            if len(bg) > 100:
                rng = np.random.default_rng(42)
                idx = rng.choice(len(bg), 100, replace=False)
                bg  = bg[idx]

            def _score_fn(X):
                res = self.ddl.predict(X)
                return res["scores"]

            self._shap_explainer = shap.KernelExplainer(_score_fn, bg)
            logger.info("SHAP KernelExplainer initialized")
        except ImportError:
            logger.warning("shap not installed → SHAP explanations unavailable")
        except Exception as e:
            logger.warning(f"SHAP init failed: {e}")

    def _init_lime(self):
        """Initialize LIME TabularExplainer with background statistics."""
        try:
            from lime.lime_tabular import LimeTabularExplainer

            # Determine whether each feature is categorical or continuous
            # All 40 DDL features are continuous (flag counts treated as continuous)
            self._lime_explainer = LimeTabularExplainer(
                training_data   = self.background,
                feature_names   = self.feature_names,
                mode            = "regression",
                discretize_continuous = True,
                random_state    = 42,
            )
            logger.info("LIME TabularExplainer initialized")
        except ImportError:
            logger.warning("lime not installed → LIME explanations unavailable")
        except Exception as e:
            logger.warning(f"LIME init failed: {e}")

    def _explain_ddl_native(self, features: np.ndarray) -> Dict:
        """DDL-native per-feature reconstruction error decomposition."""
        t0  = time.perf_counter()
        ir  = self.ddl.get_intermediate_representations(features)
        el  = (time.perf_counter() - t0) * 1000.0

        per_feat_err = ir["per_feature_error"]
        total_err    = float(ir["total_error"])
        threshold    = float(ir["threshold"])

        contributions = []
        for i, fname in enumerate(self.feature_names):
            e_i  = float(per_feat_err[i])
            pct  = (e_i / (total_err + 1e-10)) * 100.0
            contributions.append({
                "feature":             fname,
                "reconstruction_error": round(e_i, 6),
                "pct_of_total":        round(pct, 2),
                "original_value":      round(float(features[i]), 4),
                "reconstructed_value": round(float(ir["final_reconstruction"][i]), 4),
            })
        contributions.sort(key=lambda x: x["reconstruction_error"], reverse=True)

        return {
            "method":       "DDL-Native",
            "decision":     str(ir["decision"]),
            "total_error":  round(total_err, 6),
            "threshold":    round(threshold, 6),
            "error_ratio":  round(total_err / (threshold + 1e-10), 3),
            "top_features": [c["feature"] for c in contributions[:5]],
            "contributions": contributions,
            "elapsed_ms":   round(el, 2),
        }

    def _explain_shap(self, features: np.ndarray) -> Optional[Dict]:
        """SHAP KernelExplainer attribution."""
        if self._shap_explainer is None:
            return None
        t0 = time.perf_counter()
        try:
            sv  = self._shap_explainer.shap_values(
                features.reshape(1, -1), nsamples=self.shap_nsamples
            )[0]
            el  = (time.perf_counter() - t0) * 1000.0
            attrs = []
            for i, fname in enumerate(self.feature_names):
                attrs.append({
                    "feature":   fname,
                    "shap_value": round(float(sv[i]), 6),
                    "direction": "↑ toward anomaly" if sv[i] > 0 else "↓ away from anomaly",
                })
            attrs.sort(key=lambda x: abs(x["shap_value"]), reverse=True)
            return {
                "method":         "SHAP-KernelExplainer",
                "base_value":     round(float(self._shap_explainer.expected_value), 4),
                "top_features":   [a["feature"] for a in attrs[:5] if a["shap_value"] > 0],
                "attributions":   attrs,
                "elapsed_ms":     round(el, 2),
            }
        except Exception as e:
            logger.warning(f"SHAP explain failed: {e}")
            return None

    def _explain_lime(self, features: np.ndarray) -> Optional[Dict]:
        """LIME local linear approximation."""
        if self._lime_explainer is None:
            return None
        t0 = time.perf_counter()
        try:
            def _predict_fn(X):
                res = self.ddl.predict(X)
                return res["scores"]

            exp  = self._lime_explainer.explain_instance(
                features,
                _predict_fn,
                num_features=self.n_features,
                num_samples=self.lime_nsamples,
            )
            el   = (time.perf_counter() - t0) * 1000.0
            raw  = exp.as_list()  # [(feature_condition_str, weight), ...]
            attrs = []
            for cond, weight in raw:
                attrs.append({
                    "condition": cond,
                    "weight":    round(float(weight), 6),
                    "direction": "↑ toward anomaly" if weight > 0 else "↓ away from anomaly",
                })
            attrs.sort(key=lambda x: abs(x["weight"]), reverse=True)
            top = [a["condition"].split(" ")[0] for a in attrs[:5] if a["weight"] > 0]

            return {
                "method":       "LIME-TabularExplainer",
                "score":        round(float(exp.predicted_value), 4),
                "top_features": top,
                "attributions": attrs,
                "elapsed_ms":   round(el, 2),
            }
        except Exception as e:
            logger.warning(f"LIME explain failed: {e}")
            return None

    def _agreement_analysis(self, ddl_top: List[str],
                              shap_top: Optional[List[str]],
                              lime_top: Optional[List[str]]) -> Dict:
        """
        Compute cross-method feature agreement.

        When multiple explanation methods point to the same feature as
        anomalous, the evidence is much stronger than any single method.
        """
        methods_present = [m for m, t in [("DDL", ddl_top), ("SHAP", shap_top),
                                            ("LIME", lime_top)] if t]
        all_tops = {
            "DDL":  set(ddl_top[:3]),
            "SHAP": set(shap_top[:3]) if shap_top else set(),
            "LIME": set(lime_top[:3]) if lime_top else set(),
        }

        # Features agreed by all available methods
        sets     = [v for v in all_tops.values() if v]
        unanimous = sets[0].intersection(*sets[1:]) if len(sets) > 1 else set()

        # Features agreed by any 2 methods (majority for 3 methods)
        majority = set()
        for a, ta in all_tops.items():
            for b, tb in all_tops.items():
                if a != b:
                    majority |= (ta & tb)

        n_methods = len(methods_present)
        if unanimous:
            confidence = "HIGH" if n_methods >= 2 else "MEDIUM"
        elif majority:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

        return {
            "methods_active":    methods_present,
            "unanimous_features": sorted(unanimous),
            "majority_features":  sorted(majority - unanimous),
            "confidence":         confidence,
            "interpretation":     (
                f"{'All' if n_methods > 1 else '1'} method(s) agree. "
                f"Unanimous top features: {sorted(unanimous) or 'none'}. "
                f"Confidence: {confidence}."
            )
        }

    def explain(self, features: np.ndarray) -> Dict:
        """
        Full dual XAI explanation for a single flow.

        Args:
            features: numpy array (40,) — DDL feature vector.

        Returns:
            dict with all three explanations and an agreement report.
        """
        features = np.array(features, dtype=np.float64)

        ddl_exp  = self._explain_ddl_native(features)
        shap_exp = self._explain_shap(features)
        lime_exp = self._explain_lime(features)

        agreement = self._agreement_analysis(
            ddl_top  = ddl_exp["top_features"],
            shap_top = shap_exp["top_features"] if shap_exp else None,
            lime_top = lime_exp["top_features"] if lime_exp else None,
        )

        total_xai_ms = (ddl_exp["elapsed_ms"] +
                         (shap_exp["elapsed_ms"] if shap_exp else 0) +
                         (lime_exp["elapsed_ms"] if lime_exp else 0))

        # Build human-readable report
        dec = ddl_exp["decision"]
        summary = [
            f"Decision:        {dec}",
            f"Reconstruction error: {ddl_exp['error_ratio']:.2f}× threshold",
        ]
        if agreement["unanimous_features"]:
            summary.append(
                f"All methods agree: "
                f"{', '.join(agreement['unanimous_features'])} — {agreement['confidence']} confidence"
            )
        elif agreement["majority_features"]:
            summary.append(
                f"Majority agreement: "
                f"{', '.join(agreement['majority_features'])} — {agreement['confidence']} confidence"
            )
        if dec == "Anomaly":
            summary.append("Recommendation: DROP stream, notify SOC.")
        else:
            summary.append("Recommendation: FORWARD — traffic within normal parameters.")

        return {
            "ddl_native":  ddl_exp,
            "shap":        shap_exp,
            "lime":        lime_exp,
            "agreement":   agreement,
            "summary":     "\n".join(summary),
            "total_xai_ms": round(total_xai_ms, 2),
        }
