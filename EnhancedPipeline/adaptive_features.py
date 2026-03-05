"""
adaptive_features.py — MI-Based Adaptive Feature Selection
===========================================================
Zero-Trust XAI Anomaly Detection | University of Peradeniya
e20420Janith

Periodically re-ranks the 30 DDL features by Mutual Information (MI) with
the anomaly/normal labels observed in the last N flows. Then retrains the
DDL on the top-K features if the ranking changes significantly.

Usage:
    from EnhancedPipeline.adaptive_features import AdaptiveFeatureSelector
    selector = AdaptiveFeatureSelector(k=25, retrain_every=500)
    selector.update(features, label)            # call per flow
    selected = selector.get_selected_features() # array indices to use
"""

import numpy as np
import logging
from collections import deque
from typing import List, Optional, Tuple
from sklearn.feature_selection import mutual_info_classif

from DDLModel.ddl_feature_extractor import DDL_FEATURE_NAMES, N_DDL_FEATURES
from EnhancedPipeline.config import CFG

logger = logging.getLogger("EP.AdaptiveFeatures")


class AdaptiveFeatureSelector:
    """
    Maintains a sliding window of (feature_vector, label) observations and
    re-ranks features by MI score every `retrain_every` flows.

    Parameters
    ----------
    k : int
        Number of top features to keep (default 25 from config).
    retrain_every : int
        Re-rank and optionally retrain after this many new flows.
    window_size : int
        Max number of past flows to keep in the sliding window.
    """

    def __init__(
        self,
        k: int = CFG.TOP_K_FEATURES,
        retrain_every: int = CFG.RETRAIN_EVERY_N,
        window_size: int = 2000,
    ):
        self.k = k
        self.retrain_every = retrain_every
        self.window_size = window_size

        # Sliding window: deque of (np.ndarray(30,), int) where label 0=normal, 1=anomaly
        self._window_X: deque = deque(maxlen=window_size)
        self._window_y: deque = deque(maxlen=window_size)

        # Current selected feature indices (start with all 30 features)
        self._selected_indices: List[int] = list(range(N_DDL_FEATURES))
        self._mi_scores: np.ndarray = np.ones(N_DDL_FEATURES)

        # Flow counter since last re-rank
        self._flows_since_update: int = 0
        self._total_flows: int = 0

    # ─────────────────────────────────────────────────────────────────────────

    def update(self, features: np.ndarray, label: int) -> bool:
        """
        Add a new observation and trigger re-ranking if threshold reached.

        Parameters
        ----------
        features : np.ndarray, shape (30,)
            The 30 DDL features for this flow.
        label : int
            0 = Normal, 1 = Anomaly.

        Returns
        -------
        bool
            True if re-ranking was triggered this call.
        """
        self._window_X.append(features.copy())
        self._window_y.append(int(label))
        self._flows_since_update += 1
        self._total_flows += 1

        if self._flows_since_update >= self.retrain_every:
            self._rerank()
            self._flows_since_update = 0
            return True
        return False

    # ─────────────────────────────────────────────────────────────────────────

    def _rerank(self) -> None:
        """Recompute MI scores and update selected feature indices."""
        X = np.array(self._window_X, dtype=np.float64)   # (N, 30)
        y = np.array(self._window_y, dtype=int)           # (N,)

        # Need at least 10 anomaly + 10 normal samples for meaningful MI
        n_anomaly = np.sum(y == 1)
        n_normal  = np.sum(y == 0)
        if n_anomaly < 5 or n_normal < 5:
            logger.warning(
                f"Not enough label diversity for MI: {n_normal} normal, {n_anomaly} anomaly. "
                "Keeping current feature set."
            )
            return

        try:
            scores = mutual_info_classif(X, y, discrete_features=False, random_state=42)
        except Exception as exc:
            logger.error(f"MI computation failed: {exc}")
            return

        old_top_k = set(self._selected_indices[:self.k])
        new_top_indices = list(np.argsort(scores)[::-1][: self.k])
        new_top_k = set(new_top_indices)

        change_pct = len(old_top_k.symmetric_difference(new_top_k)) / self.k
        self._mi_scores = scores
        self._selected_indices = new_top_indices

        logger.info(
            f"MI re-rank complete | top-{self.k} feature set changed {change_pct*100:.1f}% | "
            f"window={len(X)} flows"
        )
        if change_pct > 0:
            top3 = [(DDL_FEATURE_NAMES[i], float(scores[i])) for i in new_top_indices[:3]]
            logger.info(f"  Top-3 features: {top3}")

    # ─────────────────────────────────────────────────────────────────────────

    def get_selected_indices(self) -> List[int]:
        """Return list of feature indices to use (sorted by MI score desc)."""
        return list(self._selected_indices)

    def get_selected_features(self, feature_vector: np.ndarray) -> np.ndarray:
        """
        Slice the top-K features from a 30-element feature vector.

        Parameters
        ----------
        feature_vector : np.ndarray, shape (30,)

        Returns
        -------
        np.ndarray, shape (K,)
        """
        return feature_vector[self._selected_indices]

    def get_mi_scores(self) -> List[Tuple[str, float]]:
        """Return named MI scores for all 30 features, sorted descending."""
        pairs = list(zip(DDL_FEATURE_NAMES, self._mi_scores.tolist()))
        return sorted(pairs, key=lambda x: -x[1])

    def get_top_feature_names(self) -> List[str]:
        """Return names of currently selected top-K features."""
        return [DDL_FEATURE_NAMES[i] for i in self._selected_indices]

    @property
    def stats(self) -> dict:
        """Summary dict for dashboard / logging."""
        return {
            "total_flows_seen": self._total_flows,
            "flows_since_last_rerank": self._flows_since_update,
            "rerank_every": self.retrain_every,
            "k": self.k,
            "selected_features": self.get_top_feature_names(),
            "window_size": len(self._window_X),
        }
