"""
Deep Dictionary Learning (DDL) Model for Encrypted Traffic Anomaly Detection
=============================================================================

Implements a multi-layer (2 or 3 layers) dictionary learning pipeline that
learns sparse representations of normal traffic patterns. Anomalies are
detected when a sample cannot be efficiently reconstructed from the dictionaries.

Now fully configurable: n_features can be 15 (DT features, legacy) or 30
(DDL-specific features from ddl_feature_extractor.py — recommended).

Architecture (2-layer default):
    D1 ∈ R^(n_features × k1)   — coarse patterns from raw features
    D2 ∈ R^(k1 × k2)           — fine patterns in higher-dimensional space

    Input x  →  α1 = sparse_code(D1, x)
             →  α2 = sparse_code(D2, α1)
             →  x̂  = (α2 @ D2ᵀ) @ D1ᵀ
             →  error = ||x - x̂||²  →  anomaly score

Optional 3-layer architecture (set n_atoms_l3 > 0):
    D3 ∈ R^(k2 × k3)  — deepest layer for complex pattern hierarchies
    Reconstruction: (α3 @ D3ᵀ @ D2ᵀ) @ D1ᵀ
    Based on: Tariyal et al. (2016) deep extension experiments.

Threshold calibration (recommended):
    Use calibrate_threshold() after fit() for F1-optimal anomaly threshold
    instead of a fixed percentile. This accounts for class imbalance.

References:
    - Tariyal et al., "Deep Dictionary Learning," IEEE Access, 2016
      (Research Papers/Detecting_Anomalies_in_Encrypted_Traffic_via_Deep_Dictionary_Learning.pdf)
    - Use DDLModel/ddl_feature_extractor.py for the recommended 30-feature DDL input set.
"""

import numpy as np
import logging
import os
import json
import joblib
from datetime import datetime

logger = logging.getLogger("DDL")

# ── Optional GPU (PyTorch) backend ───────────────────────────────────────────
try:
    import torch
    _TORCH_AVAILABLE = True
except ImportError:
    _TORCH_AVAILABLE = False


def _select_device(use_gpu: bool = False) -> str:
    """
    Select the best available device.
    Returns 'cuda:N' (most free GPU), 'cpu', or 'cpu' if PyTorch unavailable.
    """
    if not use_gpu or not _TORCH_AVAILABLE:
        return "cpu"
    if not torch.cuda.is_available():
        logger.warning("GPU requested but CUDA not available — falling back to CPU")
        return "cpu"
    # Pick the GPU with the most free memory
    best_gpu = 0
    best_free = 0
    for i in range(torch.cuda.device_count()):
        free, total = torch.cuda.mem_get_info(i)
        logger.info(f"  GPU {i}: {torch.cuda.get_device_name(i)}  "
                    f"free={free/1e9:.1f}GB/{total/1e9:.1f}GB")
        if free > best_free:
            best_free, best_gpu = free, i
    device = f"cuda:{best_gpu}"
    logger.info(f"Using GPU {best_gpu}: {torch.cuda.get_device_name(best_gpu)}")
    return device


def _to_torch(arr: np.ndarray, device: str):
    """Convert numpy array to torch tensor on device."""
    return torch.from_numpy(arr.astype(np.float32)).to(device)


def _to_numpy(t) -> np.ndarray:
    """Convert torch tensor to numpy (CPU)."""
    if _TORCH_AVAILABLE and isinstance(t, torch.Tensor):
        return t.detach().cpu().numpy().astype(np.float64)
    return np.asarray(t, dtype=np.float64)



class DeepDictionaryLearning:
    """
    Two-layer Deep Dictionary Learning for anomaly detection.
    
    Layer 1 learns coarse dictionaries over the raw 15-feature input.
    Layer 2 refines representations in a higher-dimensional latent space.
    Anomalies are flagged when reconstruction error exceeds a learned threshold.
    """

    def __init__(self, n_features=30, n_atoms_l1=64, n_atoms_l2=128,
                 n_atoms_l3=0,
                 sparsity_weight=0.1, learning_rate=0.001, n_epochs=100,
                 batch_size=32, threshold_percentile=95, random_state=42,
                 use_gpu=False):
        """
        Args:
            n_features: Number of input features (30 recommended for DDL).
            n_atoms_l1: Dictionary atoms in Layer 1 (default 64).
            n_atoms_l2: Dictionary atoms in Layer 2 (default 128).
            n_atoms_l3: Dictionary atoms in optional Layer 3 (0 = 2-layer mode).
            sparsity_weight: L1 regularization for ISTA (0.05–0.2).
            learning_rate: SGD step size for dictionary update.
            n_epochs: Training epochs (100 default; 150 recommended for 30-feat).
            batch_size: Mini-batch size (32 default; 256–512 for GPU).
            threshold_percentile: Anomaly threshold percentile of training errors.
            random_state: Reproducibility seed.
            use_gpu: If True, use CUDA GPU via PyTorch (auto-selects best GPU).
                     Falls back to CPU if PyTorch/CUDA unavailable.
                     Recommended: True when training on RTX 6000 Ada.
        """
        self.n_features = n_features
        self.n_atoms_l1 = n_atoms_l1
        self.n_atoms_l2 = n_atoms_l2
        self.n_atoms_l3 = n_atoms_l3
        self.sparsity_weight = sparsity_weight
        self.learning_rate = learning_rate
        self.n_epochs = n_epochs
        self.batch_size = batch_size
        self.threshold_percentile = threshold_percentile
        self.random_state = random_state
        self.use_gpu = use_gpu

        # Device selection (CPU or best available CUDA GPU)
        self.device = _select_device(use_gpu)
        self._use_torch = (self.device != "cpu" and _TORCH_AVAILABLE)
        if self._use_torch:
            logger.info(f"DDL will use GPU backend: {self.device}")
        else:
            logger.info("DDL will use CPU backend (NumPy)")

        np.random.seed(random_state)

        # Dictionaries — initialized on fit()
        self.D1 = None   # Layer 1: R^(n_features × n_atoms_l1)
        self.D2 = None   # Layer 2: R^(n_atoms_l1 × n_atoms_l2)
        self.D3 = None   # Layer 3: R^(n_atoms_l2 × n_atoms_l3)  — None when disabled

        # Normalization statistics (learned on training set)
        self.mean_ = None
        self.std_  = None

        # Anomaly threshold (learned from training errors)
        self.threshold_ = None

        # Per-call latency (seconds) — populated by predict()
        self.last_predict_ms: float = 0.0

        # Training metadata
        self.training_history_: list = []
        self.is_fitted_: bool = False

    def _normalize(self, X):
        """Z-score normalization using training statistics."""
        return (X - self.mean_) / (self.std_ + 1e-8)

    def _sparse_code(self, D, x, n_iter=50):
        """
        ISTA (Iterative Shrinkage-Thresholding Algorithm) for sparse coding.
        Solves: min_α  (1/2)||x - D @ α||² + λ||α||₁
        Supports both NumPy (CPU) and PyTorch (GPU) backends.
        """
        if self._use_torch:
            return self._sparse_code_gpu(D, x, n_iter)
        return self._sparse_code_cpu(D, x, n_iter)

    def _sparse_code_cpu(self, D, x, n_iter=50):
        """NumPy ISTA (CPU path)."""
        single = (x.ndim == 1)
        if single:
            x = x.reshape(1, -1)
        n_samples, k = x.shape[0], D.shape[1]
        L = np.linalg.norm(D.T @ D, ord=2)
        if L < 1e-10:
            L = 1.0
        step = 1.0 / L
        alpha = np.zeros((n_samples, k))
        lam   = self.sparsity_weight * step
        DtD   = D.T @ D
        Dtx   = x @ D
        for _ in range(n_iter):
            gradient = alpha @ DtD - Dtx
            alpha    = alpha - step * gradient
            alpha    = np.sign(alpha) * np.maximum(np.abs(alpha) - lam, 0)
        if single:
            return alpha[0]
        return alpha

    def _sparse_code_gpu(self, D_np, x_np, n_iter=50):
        """PyTorch ISTA (GPU path). D and x may be numpy; returned as numpy."""
        import torch
        single = (x_np.ndim == 1)
        if single:
            x_np = x_np.reshape(1, -1)
        D = _to_torch(D_np if isinstance(D_np, np.ndarray) else _to_numpy(D_np), self.device)
        x = _to_torch(x_np if isinstance(x_np, np.ndarray) else _to_numpy(x_np), self.device)
        k = D.shape[1]
        L = torch.linalg.norm(D.T @ D, ord=2).item()
        if L < 1e-10:
            L = 1.0
        step = 1.0 / L
        alpha = torch.zeros(x.shape[0], k, device=self.device, dtype=torch.float32)
        lam   = self.sparsity_weight * step
        DtD   = D.T @ D
        Dtx   = x @ D
        for _ in range(n_iter):
            gradient = alpha @ DtD - Dtx
            alpha    = alpha - step * gradient
            alpha    = torch.sign(alpha) * torch.clamp(torch.abs(alpha) - lam, min=0)
        result = _to_numpy(alpha)
        if single:
            return result[0]
        return result

    def _update_dictionary(self, D, X, alpha):
        """
        Dictionary update step using gradient descent.
        
        min_D  (1/2)||X - D @ α^T||²_F
        
        Args:
            D: Current dictionary (d × k).
            X: Input batch (n × d).
            alpha: Sparse codes (n × k).
            
        Returns:
            Updated dictionary D.
        """
        n = X.shape[0]
        if n == 0:
            return D

        # Gradient: ∂L/∂D = -(1/n)(X - D @ αᵀ) @ α  → simplified
        residual = X - alpha @ D.T  # (n × d)
        grad = -(residual.T @ alpha) / n  # (d × k)
        
        D_new = D - self.learning_rate * grad

        # Normalize columns to unit norm (prevents dictionary degeneration)
        norms = np.linalg.norm(D_new, axis=0, keepdims=True)
        norms = np.maximum(norms, 1e-8)
        D_new = D_new / norms

        return D_new

    def fit(self, X_normal):
        """
        Train DDL on normal (benign) traffic samples only.
        
        The dictionaries learn to represent normal patterns efficiently.
        Anomalous traffic will have high reconstruction error.
        
        Args:
            X_normal: numpy array of shape (n_samples, 15) — benign traffic features.
            
        Returns:
            self
        """
        X = np.array(X_normal, dtype=np.float64)

        # Learn normalization from training data
        self.mean_ = X.mean(axis=0)
        self.std_ = X.std(axis=0)
        X_norm = self._normalize(X)

        n_samples = X_norm.shape[0]

        # Initialize dictionaries with random unit-norm columns
        self.D1 = np.random.randn(self.n_features, self.n_atoms_l1)
        self.D1 /= np.linalg.norm(self.D1, axis=0, keepdims=True)

        self.D2 = np.random.randn(self.n_atoms_l1, self.n_atoms_l2)
        self.D2 /= np.linalg.norm(self.D2, axis=0, keepdims=True)

        # Optional Layer 3
        if self.n_atoms_l3 > 0:
            self.D3 = np.random.randn(self.n_atoms_l2, self.n_atoms_l3)
            self.D3 /= np.linalg.norm(self.D3, axis=0, keepdims=True)
        else:
            self.D3 = None

        # Log device
        gpu_str = f" | device={self.device}" if self._use_torch else " | device=cpu"
        layer_str = f"L1={self.n_atoms_l1}, L2={self.n_atoms_l2}"
        if self.D3 is not None:
            layer_str += f", L3={self.n_atoms_l3}"
        logger.info(f"Training DDL ({self.n_features} features, {layer_str}){gpu_str}: "
                     f"{n_samples} samples")
        if self.batch_size < 256 and self._use_torch:
            logger.info("  Tip: for GPU training, batch_size=256 or 512 is faster")

        for epoch in range(self.n_epochs):
            # Shuffle
            indices = np.random.permutation(n_samples)
            epoch_loss = 0.0
            n_batches = 0

            for start in range(0, n_samples, self.batch_size):
                batch_idx = indices[start:start + self.batch_size]
                X_batch = X_norm[batch_idx]

                # Forward — Layer 1
                alpha1 = self._sparse_code(self.D1, X_batch)  # (batch, k1)

                # Forward — Layer 2
                alpha2 = self._sparse_code(self.D2, alpha1)   # (batch, k2)

                # Forward — optional Layer 3
                if self.D3 is not None:
                    alpha3 = self._sparse_code(self.D3, alpha2)  # (batch, k3)
                    alpha2_hat = alpha3 @ self.D3.T
                    alpha1_hat = alpha2_hat @ self.D2.T
                    x_hat      = alpha1_hat @ self.D1.T
                    # Layer-wise dictionary updates (L3 → L2 → L1)
                    self.D3 = self._update_dictionary(self.D3, alpha2, alpha3)
                else:
                    alpha2_hat = None
                    alpha1_hat = alpha2 @ self.D2.T
                    x_hat      = alpha1_hat @ self.D1.T

                # End-to-end reconstruction error
                batch_error = np.mean(np.sum((X_batch - x_hat) ** 2, axis=1))
                epoch_loss += batch_error

                # Backward — update remaining dictionaries (layer-wise)
                self.D2 = self._update_dictionary(self.D2, alpha1, alpha2)
                self.D1 = self._update_dictionary(self.D1, X_batch, alpha1)

                n_batches += 1

            avg_loss = epoch_loss / max(n_batches, 1)
            self.training_history_.append(avg_loss)

            if (epoch + 1) % 20 == 0 or epoch == 0:
                logger.info(f"  Epoch {epoch+1}/{self.n_epochs} — Loss: {avg_loss:.6f}")

        # Compute threshold on training data
        errors = self._compute_errors(X_norm)
        self.threshold_ = np.percentile(errors, self.threshold_percentile)
        logger.info(f"Anomaly threshold (p{self.threshold_percentile}): {self.threshold_:.6f}")
        logger.info(f"Training error — mean: {errors.mean():.6f}, "
                     f"std: {errors.std():.6f}, max: {errors.max():.6f}")

        self.is_fitted_ = True
        return self

    def _compute_errors(self, X_norm):
        """
        Compute per-sample reconstruction errors through all layers.

        Args:
            X_norm: Normalized input (n × n_features).

        Returns:
            errors: Array of shape (n,) — reconstruction error per sample.
        """
        alpha1 = self._sparse_code(self.D1, X_norm)
        alpha2 = self._sparse_code(self.D2, alpha1)
        if self.D3 is not None:
            alpha3     = self._sparse_code(self.D3, alpha2)
            alpha2_hat = alpha3 @ self.D3.T
            alpha1_hat = alpha2_hat @ self.D2.T
        else:
            alpha1_hat = alpha2 @ self.D2.T
        x_hat  = alpha1_hat @ self.D1.T
        errors = np.sum((X_norm - x_hat) ** 2, axis=1)
        return errors

    def calibrate_threshold(self, X_normal, X_anomaly,
                             percentiles=None, metric="f1"):
        """
        Find the F1-optimal reconstruction error threshold.

        Instead of using a fixed percentile of training errors, this method
        searches a grid of candidate thresholds for the one that maximises
        F1-score on a held-out calibration set containing both normal and
        anomalous samples.

        This is important for class-imbalanced datasets (far more normal than
        attack flows) where a fixed percentile may be too conservative.

        Based on: threshold calibration strategies reviewed in the SHAP paper
        (Research Papers/Interpretable Anomaly Detection in Encrypted Traffic).

        Args:
            X_normal:  numpy array (n, n_features) — held-out normal samples.
            X_anomaly: numpy array (m, n_features) — held-out anomaly samples.
            percentiles: list of candidate threshold percentiles to search.
                         Default: range(80, 100).
            metric: Optimisation target — "f1" (default) or "balanced_accuracy".

        Returns:
            best_threshold: float — the selected threshold (also updates self.threshold_).
            calibration_report: dict — F1/precision/recall at best threshold.
        """
        if not self.is_fitted_:
            raise RuntimeError("DDL model not fitted. Call fit() first.")

        percentiles = percentiles or list(range(80, 100))

        X_norm_norm   = self._normalize(np.array(X_normal,  dtype=np.float64))
        X_anom_norm   = self._normalize(np.array(X_anomaly, dtype=np.float64))

        normal_errors = self._compute_errors(X_norm_norm)
        anom_errors   = self._compute_errors(X_anom_norm)

        all_errors  = np.concatenate([normal_errors, anom_errors])
        all_labels  = np.concatenate([
            np.zeros(len(normal_errors)),   # 0 = Normal
            np.ones(len(anom_errors)),      # 1 = Anomaly
        ])

        best_thresh, best_f1 = self.threshold_, 0.0
        best_report = {}

        # Search thresholds at given percentiles of all errors
        candidates = [np.percentile(all_errors, p) for p in percentiles]
        candidates = sorted(set(candidates))

        for t in candidates:
            preds = (all_errors > t).astype(int)
            TP = float(np.sum((preds == 1) & (all_labels == 1)))
            FP = float(np.sum((preds == 1) & (all_labels == 0)))
            FN = float(np.sum((preds == 0) & (all_labels == 1)))
            TN = float(np.sum((preds == 0) & (all_labels == 0)))

            precision = TP / (TP + FP + 1e-8)
            recall    = TP / (TP + FN + 1e-8)
            f1        = 2 * precision * recall / (precision + recall + 1e-8)
            bal_acc   = 0.5 * (TP / (TP + FN + 1e-8) + TN / (TN + FP + 1e-8))

            score = f1 if metric == "f1" else bal_acc
            if score > best_f1:
                best_f1    = score
                best_thresh = t
                best_report = {
                    "threshold": round(t, 6),
                    "f1":        round(f1, 4),
                    "precision": round(precision, 4),
                    "recall":    round(recall, 4),
                    "balanced_accuracy": round(bal_acc, 4),
                    "TP": int(TP), "FP": int(FP),
                    "FN": int(FN), "TN": int(TN),
                }

        self.threshold_ = best_thresh
        logger.info(f"Calibrated threshold → {best_thresh:.6f}  "
                     f"(F1={best_report.get('f1',0):.4f}, "
                     f"Recall={best_report.get('recall',0):.4f})")
        return best_thresh, best_report

    def predict(self, X):
        """
        Predict anomaly labels for input samples.

        Args:
            X: numpy array (n_samples, n_features) or (n_features,) for single.

        Returns:
            dict with:
                labels:          "Normal" / "Anomaly" per sample
                scores:          raw reconstruction error per sample
                threshold:       the decision boundary
                sparse_codes_l1: Layer 1 sparse codes (for XAI)
                sparse_codes_l2: Layer 2 sparse codes (for XAI)
                sparse_codes_l3: Layer 3 sparse codes (for XAI) — None if 2-layer
                reconstructions: reconstructed feature vectors (original scale)
                predict_ms:      wall-clock time for this call (milliseconds)
        """
        import time as _time
        if not self.is_fitted_:
            raise RuntimeError("DDL model not fitted. Call fit() first.")

        _t0 = _time.perf_counter()

        X = np.array(X, dtype=np.float64)
        single = (X.ndim == 1)
        if single:
            X = X.reshape(1, -1)

        X_norm = self._normalize(X)

        # Layer 1: encode into sparse codes
        alpha1 = self._sparse_code(self.D1, X_norm)

        # Layer 2: encode sparse codes deeper
        alpha2 = self._sparse_code(self.D2, alpha1)

        # Optional Layer 3
        alpha3 = None
        if self.D3 is not None:
            alpha3     = self._sparse_code(self.D3, alpha2)
            alpha2_hat = alpha3 @ self.D3.T
            alpha1_hat = alpha2_hat @ self.D2.T
        else:
            alpha1_hat = alpha2 @ self.D2.T

        x_hat_norm   = alpha1_hat @ self.D1.T
        errors       = np.sum((X_norm - x_hat_norm) ** 2, axis=1)
        labels       = np.where(errors > self.threshold_, "Anomaly", "Normal")
        x_hat_denorm = x_hat_norm * (self.std_ + 1e-8) + self.mean_

        elapsed_ms = (_time.perf_counter() - _t0) * 1000.0
        self.last_predict_ms = elapsed_ms

        result = {
            "labels":          labels,
            "scores":          errors,
            "threshold":       self.threshold_,
            "sparse_codes_l1": alpha1,
            "sparse_codes_l2": alpha2,
            "sparse_codes_l3": alpha3,
            "reconstructions": x_hat_denorm,
            "predict_ms":      round(elapsed_ms, 3),
        }

        if single:
            result["labels"]          = labels[0]
            result["scores"]          = errors[0]
            result["sparse_codes_l1"] = alpha1[0]
            result["sparse_codes_l2"] = alpha2[0]
            result["sparse_codes_l3"] = alpha3[0] if alpha3 is not None else None
            result["reconstructions"] = x_hat_denorm[0]

        return result

    def get_intermediate_representations(self, X):
        """
        Get all intermediate results for XAI analysis.
        
        Returns the full computational graph for a given input:
            input → normalized → L1 sparse code → L1 reconstruction →
            L2 sparse code → final reconstruction → error → decision
            
        Args:
            X: Single sample (15,) or batch (n, 15).
            
        Returns:
            dict with all intermediate tensors and the decision.
        """
        if not self.is_fitted_:
            raise RuntimeError("DDL model not fitted.")

        X = np.array(X, dtype=np.float64)
        single = (X.ndim == 1)
        if single:
            X = X.reshape(1, -1)

        X_norm = self._normalize(X)

        # Layer 1: encode into sparse codes
        alpha1 = self._sparse_code(self.D1, X_norm)
        h1 = alpha1 @ self.D1.T  # L1 reconstruction (for reporting only)

        # Layer 2: encode sparse codes deeper
        alpha2 = self._sparse_code(self.D2, alpha1)

        # Reconstruct back to input space
        alpha1_hat = alpha2 @ self.D2.T  # Reconstructed L1 sparse codes
        x_hat_norm = alpha1_hat @ self.D1.T  # Back to input space

        # Errors
        per_feature_error = (X_norm - x_hat_norm) ** 2
        total_error = np.sum(per_feature_error, axis=1)

        # Denormalize
        x_hat = x_hat_norm * (self.std_ + 1e-8) + self.mean_

        # Active atoms (non-zero sparse codes)
        l1_active = np.abs(alpha1) > 1e-6
        l2_active = np.abs(alpha2) > 1e-6

        labels = np.where(total_error > self.threshold_, "Anomaly", "Normal")

        result = {
            "input_raw": X,
            "input_normalized": X_norm,
            "layer1_sparse_codes": alpha1,
            "layer1_active_atoms": l1_active.sum(axis=1) if not single else l1_active.sum(),
            "layer1_reconstruction": h1,
            "layer2_sparse_codes": alpha2,
            "layer2_active_atoms": l2_active.sum(axis=1) if not single else l2_active.sum(),
            "reconstructed_l1_codes": alpha1_hat,
            "final_reconstruction_normalized": x_hat_norm,
            "final_reconstruction": x_hat,
            "per_feature_error": per_feature_error,
            "total_error": total_error,
            "threshold": self.threshold_,
            "decision": labels
        }

        if single:
            for k, v in result.items():
                if isinstance(v, np.ndarray) and v.ndim > 0 and v.shape[0] == 1:
                    result[k] = v[0]

        return result

    def save(self, path):
        """Save model to disk (all layers + metadata)."""
        state = {
            "D1": self.D1,
            "D2": self.D2,
            "D3": self.D3,
            "mean_": self.mean_,
            "std_": self.std_,
            "threshold_": self.threshold_,
            "n_features": self.n_features,
            "n_atoms_l1": self.n_atoms_l1,
            "n_atoms_l2": self.n_atoms_l2,
            "n_atoms_l3": self.n_atoms_l3,
            "sparsity_weight": self.sparsity_weight,
            "training_history_": self.training_history_,
            "is_fitted_": self.is_fitted_,
            "use_gpu": self.use_gpu,
        }
        joblib.dump(state, path)
        logger.info(f"DDL model saved to {path}")

    @classmethod
    def load(cls, path):
        """Load model from disk (supports both 2-layer and 3-layer checkpoints)."""
        state = joblib.load(path)
        model = cls(
            n_features    = state["n_features"],
            n_atoms_l1    = state["n_atoms_l1"],
            n_atoms_l2    = state["n_atoms_l2"],
            n_atoms_l3    = state.get("n_atoms_l3", 0),
            sparsity_weight = state["sparsity_weight"],
            use_gpu       = state.get("use_gpu", False),  # preserve training device pref
        )
        # Loaded models always run inference on CPU (safe across machines)
        model.device     = "cpu"
        model._use_torch = False
        model.D1 = state["D1"]
        model.D2 = state["D2"]
        model.D3 = state.get("D3", None)
        model.mean_             = state["mean_"]
        model.std_              = state["std_"]
        model.threshold_        = state["threshold_"]
        model.training_history_ = state["training_history_"]
        model.is_fitted_        = state["is_fitted_"]
        logger.info(f"DDL model loaded from {path}  "
                     f"({model.n_features} features, "
                     f"{'3' if model.D3 is not None else '2'}-layer, inference on CPU)")
        return model
