"""
Deep Dictionary Learning (DDL) Model for Encrypted Traffic Anomaly Detection
=============================================================================

Implements a multi-layer dictionary learning pipeline that learns sparse
representations of normal traffic patterns. Anomalies are detected when
a sample cannot be efficiently reconstructed from the learned dictionaries.

Architecture:
    Layer 1 (Coarse):  D1 ∈ R^(15×64)  — captures broad flow patterns
    Layer 2 (Fine):    D2 ∈ R^(64×128) — captures subtle micro-patterns
    
    Input x  →  α1 = sparse_code(D1, x)
             →  h1 = D1 @ α1
             →  α2 = sparse_code(D2, h1)
             →  x̂  = D2 @ α2   (reconstruction)
             →  error = ||x - x̂||²  →  anomaly score

References:
    - Tariyal et al., "Deep Dictionary Learning," IEEE Access, 2016
    - CIC-IDS-2017 dataset (15 behavioral features)
"""

import numpy as np
import logging
import os
import json
import joblib
from datetime import datetime

logger = logging.getLogger("DDL")


class DeepDictionaryLearning:
    """
    Two-layer Deep Dictionary Learning for anomaly detection.
    
    Layer 1 learns coarse dictionaries over the raw 15-feature input.
    Layer 2 refines representations in a higher-dimensional latent space.
    Anomalies are flagged when reconstruction error exceeds a learned threshold.
    """

    def __init__(self, n_features=15, n_atoms_l1=64, n_atoms_l2=128,
                 sparsity_weight=0.1, learning_rate=0.001, n_epochs=100,
                 batch_size=32, threshold_percentile=95, random_state=42):
        """
        Args:
            n_features: Number of input features (15 for CIC-IDS-2017).
            n_atoms_l1: Dictionary atoms in Layer 1 (coarse patterns).
            n_atoms_l2: Dictionary atoms in Layer 2 (fine patterns).
            sparsity_weight: L1 regularization strength for sparse coding (λ).
            learning_rate: SGD learning rate for dictionary update.
            n_epochs: Training epochs.
            batch_size: Mini-batch size.
            threshold_percentile: Percentile of training error to set as anomaly threshold.
            random_state: Reproducibility seed.
        """
        self.n_features = n_features
        self.n_atoms_l1 = n_atoms_l1
        self.n_atoms_l2 = n_atoms_l2
        self.sparsity_weight = sparsity_weight
        self.learning_rate = learning_rate
        self.n_epochs = n_epochs
        self.batch_size = batch_size
        self.threshold_percentile = threshold_percentile
        self.random_state = random_state

        np.random.seed(random_state)

        # Dictionaries (initialized on fit)
        self.D1 = None  # Layer 1: R^(n_features × n_atoms_l1)
        self.D2 = None  # Layer 2: R^(n_atoms_l1 × n_atoms_l2)

        # Normalization params
        self.mean_ = None
        self.std_ = None

        # Anomaly threshold (learned from training data)
        self.threshold_ = None
        
        # Training metadata
        self.training_history_ = []
        self.is_fitted_ = False

    def _normalize(self, X):
        """Z-score normalization using training statistics."""
        return (X - self.mean_) / (self.std_ + 1e-8)

    def _sparse_code(self, D, x, n_iter=50):
        """
        ISTA (Iterative Shrinkage-Thresholding Algorithm) for sparse coding.
        
        Solves: min_α  (1/2)||x - D @ α||² + λ||α||₁
        
        Args:
            D: Dictionary matrix (d × k).
            x: Input vector or batch (d,) or (n, d).
            n_iter: Number of ISTA iterations.
            
        Returns:
            α: Sparse coefficients (k,) or (n, k).
        """
        single = (x.ndim == 1)
        if single:
            x = x.reshape(1, -1)

        n_samples = x.shape[0]
        k = D.shape[1]

        # Lipschitz constant (step size)
        L = np.linalg.norm(D.T @ D, ord=2)
        if L < 1e-10:
            L = 1.0
        step = 1.0 / L

        # Initialize
        alpha = np.zeros((n_samples, k))
        lam = self.sparsity_weight * step

        DtD = D.T @ D
        Dtx = x @ D  # (n, k)

        for _ in range(n_iter):
            # Gradient step
            gradient = alpha @ DtD - Dtx
            alpha = alpha - step * gradient
            # Soft thresholding (proximal operator for L1)
            alpha = np.sign(alpha) * np.maximum(np.abs(alpha) - lam, 0)

        if single:
            return alpha[0]
        return alpha

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

        self.training_history_ = []
        logger.info(f"Training DDL: {n_samples} samples, "
                     f"L1={self.n_atoms_l1} atoms, L2={self.n_atoms_l2} atoms")

        for epoch in range(self.n_epochs):
            # Shuffle
            indices = np.random.permutation(n_samples)
            epoch_loss = 0.0
            n_batches = 0

            for start in range(0, n_samples, self.batch_size):
                batch_idx = indices[start:start + self.batch_size]
                X_batch = X_norm[batch_idx]

                # Forward pass — Layer 1: encode input into sparse codes
                alpha1 = self._sparse_code(self.D1, X_batch)  # (batch, k1)

                # Forward pass — Layer 2: encode L1 sparse codes deeper
                alpha2 = self._sparse_code(self.D2, alpha1)  # (batch, k2)

                # Reconstruction: chain both layers back to input space
                # alpha1_hat = alpha2 @ D2.T → (batch, k1)
                # x_hat = alpha1_hat @ D1.T → (batch, n_features)
                alpha1_hat = alpha2 @ self.D2.T
                x_hat = alpha1_hat @ self.D1.T

                # End-to-end reconstruction error
                batch_error = np.mean(np.sum((X_batch - x_hat) ** 2, axis=1))
                epoch_loss += batch_error

                # Backward — update dictionaries (layer-wise)
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
        Compute per-sample reconstruction errors through both layers.
        
        Args:
            X_norm: Normalized input (n × 15).
            
        Returns:
            errors: Array of shape (n,) — reconstruction error per sample.
        """
        alpha1 = self._sparse_code(self.D1, X_norm)
        alpha2 = self._sparse_code(self.D2, alpha1)
        alpha1_hat = alpha2 @ self.D2.T
        x_hat = alpha1_hat @ self.D1.T
        errors = np.sum((X_norm - x_hat) ** 2, axis=1)
        return errors

    def predict(self, X):
        """
        Predict anomaly labels for input samples.
        
        Args:
            X: numpy array (n_samples, 15) or (15,) for single sample.
            
        Returns:
            dict with:
                labels:   array of "Normal" / "Anomaly" strings
                scores:   raw reconstruction errors
                threshold: the learned threshold value
                sparse_codes_l1: Layer 1 sparse codes (for XAI)
                sparse_codes_l2: Layer 2 sparse codes (for XAI)
                reconstructions: reconstructed feature vectors
        """
        if not self.is_fitted_:
            raise RuntimeError("DDL model not fitted. Call fit() first.")

        X = np.array(X, dtype=np.float64)
        single = (X.ndim == 1)
        if single:
            X = X.reshape(1, -1)

        X_norm = self._normalize(X)

        # Layer 1: encode into sparse codes
        alpha1 = self._sparse_code(self.D1, X_norm)

        # Layer 2: encode sparse codes deeper
        alpha2 = self._sparse_code(self.D2, alpha1)

        # Reconstruct back to input space
        alpha1_hat = alpha2 @ self.D2.T
        x_hat_norm = alpha1_hat @ self.D1.T

        errors = np.sum((X_norm - x_hat_norm) ** 2, axis=1)
        labels = np.where(errors > self.threshold_, "Anomaly", "Normal")

        # Denormalize reconstruction for interpretability
        x_hat_denorm = x_hat_norm * (self.std_ + 1e-8) + self.mean_

        result = {
            "labels": labels,
            "scores": errors,
            "threshold": self.threshold_,
            "sparse_codes_l1": alpha1,
            "sparse_codes_l2": alpha2,
            "reconstructions": x_hat_denorm
        }

        if single:
            result["labels"] = labels[0]
            result["scores"] = errors[0]
            result["sparse_codes_l1"] = alpha1[0]
            result["sparse_codes_l2"] = alpha2[0]
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
        """Save model to disk."""
        state = {
            "D1": self.D1,
            "D2": self.D2,
            "mean_": self.mean_,
            "std_": self.std_,
            "threshold_": self.threshold_,
            "n_features": self.n_features,
            "n_atoms_l1": self.n_atoms_l1,
            "n_atoms_l2": self.n_atoms_l2,
            "sparsity_weight": self.sparsity_weight,
            "training_history_": self.training_history_,
            "is_fitted_": self.is_fitted_,
        }
        joblib.dump(state, path)
        logger.info(f"DDL model saved to {path}")

    @classmethod
    def load(cls, path):
        """Load model from disk."""
        state = joblib.load(path)
        model = cls(
            n_features=state["n_features"],
            n_atoms_l1=state["n_atoms_l1"],
            n_atoms_l2=state["n_atoms_l2"],
            sparsity_weight=state["sparsity_weight"],
        )
        model.D1 = state["D1"]
        model.D2 = state["D2"]
        model.mean_ = state["mean_"]
        model.std_ = state["std_"]
        model.threshold_ = state["threshold_"]
        model.training_history_ = state["training_history_"]
        model.is_fitted_ = state["is_fitted_"]
        logger.info(f"DDL model loaded from {path}")
        return model
