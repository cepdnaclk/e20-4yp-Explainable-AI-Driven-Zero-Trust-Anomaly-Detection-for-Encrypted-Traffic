# XAI Explainer — SHAP + DDL-Native Explanations

This module provides **explainability** for DDL anomaly detection decisions, producing human-readable rationales suitable for SOC analyst dashboards and audit trails.

## Explanation Strategies

### 1. DDL-Native Explanations
- **Per-feature reconstruction error breakdown**: Shows which of the 15 features the DDL couldn't reconstruct well
- **Sparse code activation analysis**: How many dictionary atoms activated per layer
- **Layer-by-layer diagnostics**: Intermediate representations through both DDL layers

### 2. SHAP KernelExplainer
- Model-agnostic SHAP values treating `DDL.predict()` as a black box
- Feature attribution: which features push the anomaly score up or down
- Requires background data (normal traffic samples)

### 3. Composite Report
- Combines DDL internals + SHAP into a unified explanation
- Cross-validates findings (features flagged by both methods → high confidence)
- Generates actionable recommendations (DROP/RELEASE)

## Files

| File | Description |
|------|-------------|
| `explainer.py` | `DDLExplainer` class — explain_native(), explain_shap(), explain() |
| `__init__.py` | Package init, exports `DDLExplainer` |

## Usage

```python
from DDLModel.ddl_model import DeepDictionaryLearning
from XAIExplainer.explainer import DDLExplainer

# Load a trained DDL model
ddl = DeepDictionaryLearning.load("models/ddl_model.pkl")

# Create explainer (with SHAP background data for full explanations)
explainer = DDLExplainer(ddl, background_data=X_normal)

# Full explanation for a sample
report = explainer.explain(sample_features, include_shap=True)
print(report["summary"])

# DDL-native only (faster, no SHAP dependency)
native = explainer.explain_native(sample_features)
print(native["interpretation"])
```

## Dependencies

- `numpy`
- `shap` (optional — for SHAP explanations)
