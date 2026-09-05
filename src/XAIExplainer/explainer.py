"""
SHAP-based Explainability Module for DDL Pipeline
==================================================

Provides three complementary explanation strategies that run in parallel
with the DDL anomaly detection:

1. DDL-Native Explanations:
   - Per-feature reconstruction error breakdown
   - Sparse code activation analysis (which dictionary atoms activated)
   - Layer-by-layer representation diagnostics

2. SHAP KernelExplainer:
   - Model-agnostic SHAP values treating DDL.predict() as a black box
   - Feature attribution: which of the 15 features most contributed to
     the anomaly score

3. Composite Report:
   - Combines DDL internals + SHAP into a human-readable explanation
   - Suitable for SOC analyst dashboards and audit trails
"""

import numpy as np
import logging
import os
import sys

logger = logging.getLogger("XAI")

# The 15 features in order
FEATURE_NAMES = [
    'Packet Length Variance', 'Fwd Packet Length Max', 'Fwd Header Length',
    'Init_Win_bytes_forward', 'Bwd Header Length', 'Total Length of Fwd Packets',
    'Init_Win_bytes_backward', 'Bwd Packets/s', 'Flow IAT Min', 'Fwd IAT Min',
    'Flow Bytes/s', 'Active Min', 'Bwd IAT Total', 'Flow IAT Max', 'Flow Duration'
]


class DDLExplainer:
    """
    Explains DDL decisions using:
      - DDL-native intermediate representations (reconstruction error decomposition)
      - SHAP KernelExplainer for model-agnostic feature attributions
    """

    def __init__(self, ddl_model, background_data=None, feature_names=None):
        """
        Args:
            ddl_model: Fitted DeepDictionaryLearning instance.
            background_data: (n, 15) array of normal samples for SHAP background.
                             If None, SHAP explanations won't be available.
            feature_names: List of feature names (default: CIC-IDS-2017 15 features).
        """
        self.ddl = ddl_model
        self.feature_names = feature_names or FEATURE_NAMES
        self.background_data = background_data
        self.shap_explainer = None
        
        if background_data is not None:
            self._init_shap(background_data)

    def _init_shap(self, background_data):
        """Initialize SHAP KernelExplainer with background dataset."""
        try:
            import shap
            # Use a subsample of background data for efficiency
            if len(background_data) > 100:
                idx = np.random.choice(len(background_data), 100, replace=False)
                bg = background_data[idx]
            else:
                bg = background_data

            # Wrapper: DDL predict → anomaly score (scalar per sample)
            def ddl_score_fn(X):
                results = self.ddl.predict(X)
                return results["scores"]

            self.shap_explainer = shap.KernelExplainer(ddl_score_fn, bg)
            logger.info("SHAP KernelExplainer initialized")
        except ImportError:
            logger.warning("SHAP not installed. Install via: pip install shap")
            self.shap_explainer = None
        except Exception as e:
            logger.warning(f"SHAP initialization failed: {e}")
            self.shap_explainer = None

    def explain_native(self, features):
        """
        DDL-native explanation using intermediate representations.
        
        Decomposes the anomaly decision into per-feature error contributions
        and sparse code activation patterns.
        
        Args:
            features: numpy array (15,) — single sample feature vector.
            
        Returns:
            dict with explanation components.
        """
        features = np.array(features, dtype=np.float64)
        intermediates = self.ddl.get_intermediate_representations(features)

        # Per-feature reconstruction error (in normalized space)
        per_feature_error = intermediates["per_feature_error"]
        total_error = intermediates["total_error"]
        threshold = intermediates["threshold"]

        # Rank features by their contribution to total error
        feature_contributions = []
        for i, fname in enumerate(self.feature_names):
            error_i = float(per_feature_error[i])
            pct_contribution = (error_i / (total_error + 1e-10)) * 100
            
            original_val = float(features[i])
            reconstructed_val = float(intermediates["final_reconstruction"][i])
            deviation = abs(original_val - reconstructed_val)

            feature_contributions.append({
                "feature": fname,
                "reconstruction_error": round(error_i, 6),
                "pct_of_total_error": round(pct_contribution, 2),
                "original_value": round(original_val, 4),
                "reconstructed_value": round(reconstructed_val, 4),
                "deviation": round(deviation, 4),
            })

        # Sort by error contribution (highest first)
        feature_contributions.sort(key=lambda x: x["reconstruction_error"], reverse=True)

        # Sparse code analysis
        l1_active = int(intermediates["layer1_active_atoms"])
        l2_active = int(intermediates["layer2_active_atoms"])
        l1_total = self.ddl.n_atoms_l1
        l2_total = self.ddl.n_atoms_l2

        decision = str(intermediates["decision"])

        return {
            "decision": decision,
            "total_reconstruction_error": round(float(total_error), 6),
            "anomaly_threshold": round(float(threshold), 6),
            "error_ratio": round(float(total_error / (threshold + 1e-10)), 4),
            "feature_contributions": feature_contributions,
            "sparse_code_summary": {
                "layer1_active_atoms": l1_active,
                "layer1_total_atoms": l1_total,
                "layer1_sparsity": round(1 - l1_active / l1_total, 4),
                "layer2_active_atoms": l2_active,
                "layer2_total_atoms": l2_total,
                "layer2_sparsity": round(1 - l2_active / l2_total, 4),
            },
            "interpretation": self._generate_native_interpretation(
                decision, total_error, threshold, feature_contributions,
                l1_active, l1_total, l2_active, l2_total
            )
        }

    def _generate_native_interpretation(self, decision, total_error, threshold,
                                         contributions, l1_active, l1_total,
                                         l2_active, l2_total):
        """Generate human-readable interpretation of DDL internals."""
        lines = []

        if decision == "Anomaly":
            lines.append(
                f"ANOMALY DETECTED: Reconstruction error ({total_error:.4f}) "
                f"exceeds threshold ({threshold:.4f}) by "
                f"{((total_error / threshold - 1) * 100):.1f}%."
            )
        else:
            lines.append(
                f"NORMAL: Reconstruction error ({total_error:.4f}) is within "
                f"threshold ({threshold:.4f})."
            )

        # Top contributing features
        top_features = contributions[:5]
        lines.append("\nTop features driving the anomaly score:")
        for i, fc in enumerate(top_features, 1):
            lines.append(
                f"  {i}. {fc['feature']}: {fc['pct_of_total_error']:.1f}% of error "
                f"(expected ≈{fc['reconstructed_value']:.2f}, "
                f"observed {fc['original_value']:.2f}, "
                f"deviation {fc['deviation']:.2f})"
            )

        # Sparsity analysis
        lines.append(
            f"\nDictionary activation: L1 used {l1_active}/{l1_total} atoms "
            f"({l1_active/l1_total*100:.0f}%), "
            f"L2 used {l2_active}/{l2_total} atoms "
            f"({l2_active/l2_total*100:.0f}%)"
        )

        if decision == "Anomaly":
            if l1_active > l1_total * 0.5:
                lines.append(
                    "  → High L1 activation suggests the sample is fundamentally "
                    "different from learned normal patterns."
                )
            if l2_active < l2_total * 0.1:
                lines.append(
                    "  → Very sparse L2 coding indicates the fine-grained "
                    "pattern doesn't match any known normal sub-patterns."
                )

        return "\n".join(lines)

    def explain_shap(self, features, nsamples=100):
        """
        SHAP-based feature attribution for the anomaly score.
        
        Uses KernelExplainer to compute model-agnostic SHAP values,
        showing how each feature pushes the anomaly score up or down
        relative to the expected (background) score.
        
        Args:
            features: numpy array (15,) — single sample.
            nsamples: Number of evaluation samples for KernelExplainer.
            
        Returns:
            dict with SHAP values and interpretation, or None if SHAP unavailable.
        """
        if self.shap_explainer is None:
            logger.warning("SHAP explainer not available")
            return None

        features = np.array(features, dtype=np.float64).reshape(1, -1)

        try:
            shap_values = self.shap_explainer.shap_values(features, nsamples=nsamples)
            sv = shap_values[0]  # Single sample

            base_value = float(self.shap_explainer.expected_value)

            # Build feature attribution list
            attributions = []
            for i, fname in enumerate(self.feature_names):
                attributions.append({
                    "feature": fname,
                    "shap_value": round(float(sv[i]), 6),
                    "abs_shap_value": round(abs(float(sv[i])), 6),
                    "direction": "increases anomaly score" if sv[i] > 0 else "decreases anomaly score",
                    "feature_value": round(float(features[0, i]), 4),
                })

            # Sort by absolute impact
            attributions.sort(key=lambda x: x["abs_shap_value"], reverse=True)

            predicted_score = base_value + sum(sv)

            return {
                "base_value": round(base_value, 6),
                "predicted_score": round(float(predicted_score), 6),
                "attributions": attributions,
                "interpretation": self._generate_shap_interpretation(
                    base_value, predicted_score, attributions
                )
            }
        except Exception as e:
            logger.error(f"SHAP explanation failed: {e}")
            return None

    def _generate_shap_interpretation(self, base_value, predicted_score, attributions):
        """Generate human-readable SHAP interpretation."""
        lines = [
            f"SHAP Analysis (base anomaly score: {base_value:.4f} → "
            f"predicted: {predicted_score:.4f}):",
            ""
        ]

        # Top positive contributors (push toward anomaly)
        pos = [a for a in attributions if a["shap_value"] > 0]
        neg = [a for a in attributions if a["shap_value"] < 0]

        if pos:
            lines.append("Features pushing TOWARD anomaly:")
            for a in pos[:5]:
                lines.append(
                    f"  ↑ {a['feature']} = {a['feature_value']:.2f} "
                    f"(+{a['shap_value']:.4f})"
                )

        if neg:
            lines.append("\nFeatures pushing AWAY from anomaly:")
            for a in neg[:3]:
                lines.append(
                    f"  ↓ {a['feature']} = {a['feature_value']:.2f} "
                    f"({a['shap_value']:.4f})"
                )

        return "\n".join(lines)

    def explain(self, features, include_shap=True, shap_nsamples=100):
        """
        Full composite explanation combining DDL-native + SHAP.
        
        This is the primary method called by the pipeline when a stream
        is flagged as anomalous. It provides both:
          - Reconstruction-based rationale (which features couldn't be reconstructed)
          - SHAP attributions (which features most influence the score)
        
        Args:
            features: numpy array (15,) — single sample feature vector.
            include_shap: Whether to include SHAP analysis (slower but richer).
            shap_nsamples: Number of samples for SHAP computation.
            
        Returns:
            dict with complete explanation report.
        """
        report = {
            "ddl_explanation": self.explain_native(features),
            "shap_explanation": None,
            "summary": None
        }

        if include_shap and self.shap_explainer is not None:
            report["shap_explanation"] = self.explain_shap(features, shap_nsamples)

        # Generate unified summary
        ddl_exp = report["ddl_explanation"]
        decision = ddl_exp["decision"]
        error_ratio = ddl_exp["error_ratio"]
        top_features = [fc["feature"] for fc in ddl_exp["feature_contributions"][:3]]

        summary_lines = [f"Decision: {decision}"]

        if decision == "Anomaly":
            summary_lines.append(
                f"The DDL reconstruction error is {error_ratio:.2f}x the normal threshold."
            )
            summary_lines.append(
                f"Primary anomalous features: {', '.join(top_features)}"
            )

            if report["shap_explanation"]:
                shap_top = [
                    a["feature"] for a in report["shap_explanation"]["attributions"][:3]
                    if a["shap_value"] > 0
                ]
                if shap_top:
                    summary_lines.append(
                        f"SHAP confirms: {', '.join(shap_top)} most push toward anomaly."
                    )

                # Corroboration check
                overlap = set(top_features) & set(shap_top)
                if overlap:
                    summary_lines.append(
                        f"Both DDL and SHAP agree on: {', '.join(overlap)} — high confidence."
                    )

            summary_lines.append(
                "Recommendation: DROP stream and alert SOC analyst."
            )
        else:
            summary_lines.append(
                f"Reconstruction error is within normal range ({error_ratio:.2f}x threshold)."
            )
            summary_lines.append(
                "Recommendation: RELEASE buffered stream — traffic is clean."
            )

        report["summary"] = "\n".join(summary_lines)

        return report
