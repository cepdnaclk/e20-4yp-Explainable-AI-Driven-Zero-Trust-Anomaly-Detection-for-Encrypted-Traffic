"""
Integration Tests for the Zero-Trust Pipeline
==============================================

Tests the full pipeline: Feature extraction → Decision Tree → DDL → SHAP XAI

Run (from project root):
    python -m tests.test_pipeline
"""

import os
import sys
import json
import numpy as np
import logging

# ── Path setup ──
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_THIS_DIR)
sys.path.insert(0, PROJECT_ROOT)

# Friend's modules
BASECHK_SIM = os.path.join(PROJECT_ROOT, "BaseCheckClassifier", "BaseCheckClassifierSimulation")
sys.path.insert(0, BASECHK_SIM)

from DDLModel.ddl_model import DeepDictionaryLearning
from XAIExplainer.explainer import DDLExplainer, FEATURE_NAMES
from SDNBuffer.sdn_buffer import SDNBuffer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TestPipeline")

# ──────────────────────────────────────────────
# Synthetic test data (15 CIC-IDS-2017 features)
# ──────────────────────────────────────────────
# Typical benign traffic patterns
BENIGN_SAMPLES = np.array([
    [  200,  100,  2000, 65535, 1800,  5000, 65535,  10, 50000, 50000, 1000, 100000,  80000, 200000,  300000],
    [  180,  120,  2200, 65535, 1900,  5500, 65535,  12, 45000, 48000, 1100, 110000,  85000, 210000,  320000],
    [  220,   90,  1800, 65535, 1700,  4800, 65535,   8, 55000, 52000,  900,  95000,  75000, 190000,  280000],
    [  190,  110,  2100, 65535, 1850,  5200, 65535,  11, 48000, 49000, 1050, 105000,  82000, 205000,  310000],
    [  210,   95,  1900, 65535, 1750,  4900, 65535,   9, 52000, 51000,  950,  98000,  78000, 195000,  290000],
    [  195,  105,  2050, 65535, 1820,  5100, 65535,  10, 49000, 50000, 1020, 102000,  80000, 200000,  305000],
    [  205,   98,  1950, 65535, 1780,  4950, 65535,   9, 51000, 50500,  980, 100000,  79000, 198000,  295000],
    [  185,  115,  2150, 65535, 1880,  5300, 65535,  11, 46000, 47000, 1080, 108000,  83000, 208000,  315000],
    [  215,   92,  1850, 65535, 1720,  4850, 65535,   8, 53000, 52500,  920,  96000,  76000, 192000,  285000],
    [  198,  108,  2080, 65535, 1830,  5150, 65535,  10, 49500, 50200, 1040, 103000,  81000, 202000,  308000],
], dtype=np.float64)

# Attack traffic patterns (DDoS-like: high variance, high packet rate, extreme values)
ATTACK_SAMPLES = np.array([
    [50000,  1460, 50000,   256, 40000, 200000,   128, 5000,   100,   100, 500000,  5000000, 4500000, 400000, 5400000],
    [60000,  1400, 55000,   512, 45000, 250000,   256, 6000,    50,    50, 600000,  6000000, 5000000, 350000, 6000000],
    [45000,  1460, 48000,   128, 38000, 180000,    64, 4500,   200,   150, 450000,  4800000, 4200000, 420000, 5000000],
], dtype=np.float64)


class TestResult:
    """Simple test result tracker."""
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []

    def ok(self, name):
        self.passed += 1
        print(f"  ✓ {name}")

    def fail(self, name, reason=""):
        self.failed += 1
        self.errors.append(f"{name}: {reason}")
        print(f"  ✗ {name} — {reason}")

    def summary(self):
        total = self.passed + self.failed
        print(f"\n{'='*50}")
        print(f"Results: {self.passed}/{total} passed, {self.failed} failed")
        if self.errors:
            print("Failures:")
            for e in self.errors:
                print(f"  - {e}")
        print('='*50)
        return self.failed == 0


def test_ddl_model(results):
    """Test DDL model training, prediction, and save/load."""
    print("\n─── Test: DDL Model ───")

    # Train on benign data
    ddl = DeepDictionaryLearning(
        n_features=15, n_atoms_l1=32, n_atoms_l2=64,
        sparsity_weight=0.05, learning_rate=0.005,
        n_epochs=50, batch_size=4, threshold_percentile=95,
    )
    ddl.fit(BENIGN_SAMPLES)

    if ddl.is_fitted_:
        results.ok("DDL training completes")
    else:
        results.fail("DDL training completes", "is_fitted_ is False")
        return None

    # Check that dictionaries have correct shapes
    if ddl.D1.shape == (15, 32) and ddl.D2.shape == (32, 64):
        results.ok("Dictionary shapes correct")
    else:
        results.fail("Dictionary shapes", f"D1={ddl.D1.shape}, D2={ddl.D2.shape}")

    # Threshold should be set
    if ddl.threshold_ is not None and ddl.threshold_ > 0:
        results.ok(f"Threshold learned: {ddl.threshold_:.6f}")
    else:
        results.fail("Threshold learning", f"threshold={ddl.threshold_}")

    # Predict on benign — most should be Normal
    pred_benign = ddl.predict(BENIGN_SAMPLES)
    benign_normal = np.sum(pred_benign["labels"] == "Normal")
    if benign_normal >= len(BENIGN_SAMPLES) * 0.7:
        results.ok(f"Benign samples: {benign_normal}/{len(BENIGN_SAMPLES)} classified Normal")
    else:
        results.fail("Benign classification",
                     f"Only {benign_normal}/{len(BENIGN_SAMPLES)} classified Normal")

    # Predict on attack — should have higher error scores
    pred_attack = ddl.predict(ATTACK_SAMPLES)
    mean_benign_score = np.mean(pred_benign["scores"])
    mean_attack_score = np.mean(pred_attack["scores"])

    if mean_attack_score > mean_benign_score:
        results.ok(f"Attack scores ({mean_attack_score:.4f}) > benign ({mean_benign_score:.4f})")
    else:
        results.fail("Attack vs benign scores",
                     f"Attack={mean_attack_score:.4f}, Benign={mean_benign_score:.4f}")

    # Single sample prediction
    pred_single = ddl.predict(ATTACK_SAMPLES[0])
    if isinstance(pred_single["labels"], str):
        results.ok(f"Single sample prediction: {pred_single['labels']}")
    else:
        results.fail("Single sample prediction", "Expected string label")

    # Save and reload
    model_path = os.path.join(_THIS_DIR, "models", "test_ddl.pkl")
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    ddl.save(model_path)
    ddl2 = DeepDictionaryLearning.load(model_path)

    pred2 = ddl2.predict(ATTACK_SAMPLES[0])
    if pred2["labels"] == pred_single["labels"] and abs(pred2["scores"] - pred_single["scores"]) < 1e-6:
        results.ok("Save/load preserves predictions")
    else:
        results.fail("Save/load", "Predictions differ after reload")

    return ddl


def test_intermediate_representations(ddl, results):
    """Test DDL intermediate representation extraction."""
    print("\n─── Test: Intermediate Representations ───")

    if ddl is None:
        results.fail("Intermediate reps", "DDL model not available")
        return

    intermediates = ddl.get_intermediate_representations(ATTACK_SAMPLES[0])

    required_keys = [
        "input_raw", "input_normalized", "layer1_sparse_codes",
        "layer1_active_atoms", "layer1_reconstruction",
        "layer2_sparse_codes", "layer2_active_atoms",
        "final_reconstruction", "per_feature_error",
        "total_error", "threshold", "decision"
    ]

    missing = [k for k in required_keys if k not in intermediates]
    if not missing:
        results.ok("All intermediate keys present")
    else:
        results.fail("Intermediate keys", f"Missing: {missing}")

    # Per-feature error should sum to total error (approximately)
    pfe_sum = np.sum(intermediates["per_feature_error"])
    total = intermediates["total_error"]
    if abs(pfe_sum - total) < 1e-6:
        results.ok("Per-feature errors sum to total error")
    else:
        results.fail("Error sum", f"Sum={pfe_sum:.6f}, Total={total:.6f}")


def test_xai_explainer(ddl, results):
    """Test the XAI explainer."""
    print("\n─── Test: XAI Explainer ───")

    if ddl is None:
        results.fail("XAI", "DDL model not available")
        return

    # DDL-native explanation (no SHAP needed)
    explainer = DDLExplainer(ddl, background_data=None, feature_names=FEATURE_NAMES)

    native_exp = explainer.explain_native(ATTACK_SAMPLES[0])

    if native_exp["decision"] in ("Normal", "Anomaly"):
        results.ok(f"Native explanation decision: {native_exp['decision']}")
    else:
        results.fail("Native decision", f"Got: {native_exp['decision']}")

    if len(native_exp["feature_contributions"]) == 15:
        results.ok("All 15 features in contribution list")
    else:
        results.fail("Feature contributions",
                     f"Got {len(native_exp['feature_contributions'])} features")

    # Check contributions are sorted by error
    contribs = native_exp["feature_contributions"]
    errors = [c["reconstruction_error"] for c in contribs]
    if errors == sorted(errors, reverse=True):
        results.ok("Feature contributions sorted by error (desc)")
    else:
        results.fail("Contribution sorting", "Not sorted descending")

    # Check sparse code summary
    scs = native_exp["sparse_code_summary"]
    if 0 <= scs["layer1_sparsity"] <= 1 and 0 <= scs["layer2_sparsity"] <= 1:
        results.ok(f"Sparsity L1={scs['layer1_sparsity']:.2f}, L2={scs['layer2_sparsity']:.2f}")
    else:
        results.fail("Sparsity values", f"L1={scs['layer1_sparsity']}, L2={scs['layer2_sparsity']}")

    # Check interpretation is non-empty
    if len(native_exp["interpretation"]) > 50:
        results.ok("Human-readable interpretation generated")
    else:
        results.fail("Interpretation", "Too short or empty")

    # Full explanation (without SHAP, since we don't require it for basic test)
    full_exp = explainer.explain(ATTACK_SAMPLES[0], include_shap=False)
    if full_exp["summary"] and "Decision:" in full_exp["summary"]:
        results.ok("Full explanation summary generated")
    else:
        results.fail("Full explanation", "Summary missing or malformed")


def test_xai_with_shap(ddl, results):
    """Test SHAP integration (if shap is installed)."""
    print("\n─── Test: SHAP Integration ───")

    if ddl is None:
        results.fail("SHAP", "DDL model not available")
        return

    try:
        import shap
        shap_available = True
    except ImportError:
        shap_available = False
        print("  (SHAP not installed — skipping SHAP-specific tests)")

    if not shap_available:
        results.ok("SHAP import check (not installed — OK for basic tests)")
        return

    explainer = DDLExplainer(ddl, background_data=BENIGN_SAMPLES, feature_names=FEATURE_NAMES)

    if explainer.shap_explainer is not None:
        results.ok("SHAP KernelExplainer initialized")
    else:
        results.fail("SHAP init", "shap_explainer is None despite SHAP being available")
        return

    shap_exp = explainer.explain_shap(ATTACK_SAMPLES[0], nsamples=50)

    if shap_exp is not None:
        results.ok("SHAP explanation computed")
        if len(shap_exp["attributions"]) == 15:
            results.ok("SHAP produced 15 feature attributions")
        else:
            results.fail("SHAP attributions", f"Got {len(shap_exp['attributions'])}")

        if shap_exp.get("interpretation"):
            results.ok("SHAP interpretation text generated")
    else:
        results.fail("SHAP explanation", "Returned None")


def test_pipeline_flow(ddl, results):
    """Test the full pipeline with synthetic pcaps (if available)."""
    print("\n─── Test: Pipeline Flow ───")

    # Check if synthetic pcaps exist (in friend's directory)
    attack_pcap = os.path.join(BASECHK_SIM, "synthetic_attack.pcap")
    benign_pcap = os.path.join(BASECHK_SIM, "synthetic_benign.pcap")
    small_attack = os.path.join(BASECHK_SIM, "attack", "bot_1.pcap")
    small_benign = os.path.join(BASECHK_SIM, "normal", "benign_1.pcap")

    pcap_files = []
    for path, label in [(attack_pcap, "Attack"), (benign_pcap, "Normal"),
                         (small_attack, "Attack"), (small_benign, "Normal")]:
        if os.path.exists(path):
            pcap_files.append((path, label))

    if not pcap_files:
        results.fail("Pipeline flow", "No pcap files found for testing")
        return

    results.ok(f"Found {len(pcap_files)} test pcap files")

    # Save DDL model for pipeline to load
    ddl_path = os.path.join(_THIS_DIR, "models", "test_ddl.pkl")
    if ddl and ddl.is_fitted_:
        os.makedirs(os.path.dirname(ddl_path), exist_ok=True)
        ddl.save(ddl_path)

    from ZeroTrustPipeline.pipeline import ZeroTrustPipeline

    pipeline = ZeroTrustPipeline(
        dt_model_path=None,  # No DT model → everything goes to DDL (zero-trust)
        ddl_model_path=ddl_path if os.path.exists(ddl_path) else None,
        background_data=BENIGN_SAMPLES,
        enable_shap=False,  # Faster for tests
    )

    results_file = os.path.join(_THIS_DIR, "models", "test_pipeline_results.json")
    output = pipeline.run_batch(pcap_files, output_log=results_file)

    if output["stats"]["total_streams"] == len(pcap_files):
        results.ok(f"Pipeline processed all {len(pcap_files)} streams")
    else:
        results.fail("Stream count", f"Expected {len(pcap_files)}, got {output['stats']['total_streams']}")

    # Check that all streams got a final action
    actions = [r["final_action"] for r in output["stream_results"]]
    valid_actions = {"FORWARD", "DROP", "ERROR"}
    if all(a in valid_actions for a in actions):
        results.ok(f"All actions valid: {actions}")
    else:
        results.fail("Actions", f"Invalid actions found: {actions}")

    # Check stats
    total_eval = sum(output["stats"][k] for k in ["TP", "TN", "FP", "FN"])
    if total_eval > 0:
        results.ok(f"Stats: TP={output['stats']['TP']}, TN={output['stats']['TN']}, "
                   f"FP={output['stats']['FP']}, FN={output['stats']['FN']}")

    # Print one explanation if available
    for r in output["stream_results"]:
        if r.get("explanation") and r["explanation"].get("summary"):
            print(f"\n  Sample Explanation for {r['input_file']}:")
            for line in r["explanation"]["summary"].split("\n"):
                print(f"    {line}")
            break


def test_sdn_buffer(results):
    """Test SDN buffer operations."""
    print("\n─── Test: SDN Buffer ───")

    buf = SDNBuffer(max_buffer_size=10, timeout_ms=5000)

    buf.add("stream_001", [1, 2, 3], {"source": "test"})
    if buf.get_buffered_count() == 1:
        results.ok("Buffer add works")
    else:
        results.fail("Buffer add", f"Count={buf.get_buffered_count()}")

    release = buf.release("stream_001")
    if release and release["action"] == "FORWARD":
        results.ok(f"Buffer release works (hold={release['hold_time_ms']:.0f}ms)")
    else:
        results.fail("Buffer release", f"Got: {release}")

    buf.add("stream_002", [4, 5, 6])
    drop = buf.drop("stream_002")
    if drop and drop["action"] == "DROP":
        results.ok(f"Buffer drop works (hold={drop['hold_time_ms']:.0f}ms)")
    else:
        results.fail("Buffer drop", f"Got: {drop}")

    if buf.get_buffered_count() == 0:
        results.ok("Buffer empty after operations")
    else:
        results.fail("Buffer cleanup", f"Count={buf.get_buffered_count()}")


if __name__ == "__main__":
    print("=" * 60)
    print("  ZERO-TRUST PIPELINE — INTEGRATION TESTS")
    print("=" * 60)

    results = TestResult()

    # Core tests (no external dependencies needed)
    ddl = test_ddl_model(results)
    test_intermediate_representations(ddl, results)
    test_xai_explainer(ddl, results)
    test_sdn_buffer(results)

    # SHAP test (optional, depends on shap being installed)
    test_xai_with_shap(ddl, results)

    # Pipeline integration test (needs pcap files)
    test_pipeline_flow(ddl, results)

    # Summary
    all_passed = results.summary()
    sys.exit(0 if all_passed else 1)
