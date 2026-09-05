"""
rest_api.py — FastAPI REST Server for the Enhanced Pipeline
===========================================================
Zero-Trust XAI Anomaly Detection | University of Peradeniya
e20420Janith

Provides HTTP endpoints so any SDN controller or external system can
submit flow feature vectors and receive classification decisions + XAI.

Usage:
    # Start server (from project root):
    python EnhancedPipeline/rest_api.py --port 5001

    # Or with uvicorn directly:
    uvicorn EnhancedPipeline.rest_api:app --host 0.0.0.0 --port 5001 --reload

Endpoints:
    GET  /health                → {"status": "ok", "model_loaded": true}
    GET  /status                → pipeline stats (flows, drops, latency)
    POST /predict               → classify a 30-feature flow vector
    GET  /explain/{flow_id}     → retrieve stored XAI explanation
    GET  /adaptive_stats        → current MI-based feature selection state

Example predict call:
    curl -X POST http://localhost:5001/predict \\
         -H "Content-Type: application/json" \\
         -d '{"features": [420,0,54,1460,280,0,0.005,0.001,0.02,0.006,0.001,0.03,
                           85000,120,40000,45000,48000,400,1,45,1,0,12,0,
                           18900,15200,1.5,65535,65535,0.8]}'
"""

import os
import sys
import logging
import argparse
from typing import List, Optional, Dict, Any

# ── FastAPI import with helpful error ─────────────────────────────────────────
try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field, validator
    import uvicorn
except ImportError:
    print("ERROR: FastAPI and uvicorn are not installed.")
    print("Install with: pip install fastapi uvicorn pydantic")
    sys.exit(1)

# ── Path setup ────────────────────────────────────────────────────────────────
_THIS_DIR    = os.path.dirname(os.path.abspath(__file__))
SRC_ROOT     = os.path.dirname(_THIS_DIR)
PROJECT_ROOT = os.path.dirname(SRC_ROOT)
sys.path.insert(0, SRC_ROOT)

from EnhancedPipeline.config import CFG
from EnhancedPipeline.enhanced_pipeline import EnhancedPipeline
from DDLModel.ddl_feature_extractor import N_DDL_FEATURES, DDL_FEATURE_NAMES

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("EP.API")

# ─────────────────────────────────────────────────────────────────────────────
# FastAPI app + global pipeline instance
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Zero-Trust XAI Pipeline API",
    description=(
        "REST interface for the Enhanced DDL+XAI anomaly detection pipeline. "
        "Submit 30-feature flow vectors and receive DROP/FORWARD decisions with "
        "SHAP/LIME explanations."
    ),
    version="1.0.0",
)

# Lazy-loaded pipeline (loaded on first request or at startup)
_pipeline: Optional[EnhancedPipeline] = None


def get_pipeline() -> EnhancedPipeline:
    global _pipeline
    if _pipeline is None:
        logger.info("Loading pipeline models ...")
        _pipeline = EnhancedPipeline(
            enable_shap=True,
            enable_lime=False,  # Disable LIME by default for speed
            enable_adaptive=True,
        )
        _pipeline.load_models()
    return _pipeline


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic schemas
# ─────────────────────────────────────────────────────────────────────────────

class PredictRequest(BaseModel):
    features: List[float] = Field(
        ...,
        description=f"Exactly {N_DDL_FEATURES} DDL feature values in canonical order.",
        min_items=N_DDL_FEATURES,
        max_items=N_DDL_FEATURES,
    )
    flow_id: Optional[str] = Field(None, description="Optional client-supplied flow ID.")
    run_xai: bool = Field(True, description="Include XAI explanation for anomalies.")

    @validator("features")
    def check_length(cls, v):
        if len(v) != N_DDL_FEATURES:
            raise ValueError(f"Expected {N_DDL_FEATURES} features, got {len(v)}")
        return v


class PredictResponse(BaseModel):
    flow_id:       str
    action:        str   # "FORWARD" | "DROP"
    confidence:    str
    ddl_score:     float
    ddl_threshold: float
    if_label:      str
    if_score:      float
    latency_ms:    Dict[str, float]
    explanation:   Optional[Dict[str, Any]]


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    """Health check — always returns 200 if server is running."""
    try:
        ep = get_pipeline()
        loaded = ep._is_loaded
    except Exception:
        loaded = False
    return {"status": "ok", "model_loaded": loaded, "api_version": "1.0.0"}


@app.get("/status")
def status():
    """
    Return pipeline statistics: total flows, drops, forwards, drop rate,
    mean and p95 latency, uptime.
    """
    try:
        ep = get_pipeline()
        stats = ep.get_stats()
        adaptive = ep.get_adaptive_stats()
        return JSONResponse({"pipeline_stats": stats, "adaptive_feature_stats": adaptive})
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/predict", response_model=PredictResponse)
def predict(req: PredictRequest):
    """
    Classify a single flow.

    Submit a JSON body with a `features` array of exactly 30 floats
    (in canonical DDL order — see /feature_names for the order).

    Returns the DROP/FORWARD decision, DDL score, IF vote, and optionally
    a full XAI explanation.
    """
    import numpy as np
    try:
        ep = get_pipeline()
        feat = np.array(req.features, dtype=np.float64)
        result = ep.process_flow(feat, flow_id=req.flow_id, run_xai=req.run_xai)
        return result
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        logger.exception("predict error")
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/explain/{flow_id}")
def explain(flow_id: str):
    """
    Retrieve the stored XAI explanation for a previous flow by its ID.

    flow_id is returned by /predict or supplied by the caller.
    """
    try:
        ep = get_pipeline()
        exp = ep.get_explanation(flow_id)
        if exp is None:
            raise HTTPException(
                status_code=404,
                detail=f"No explanation found for flow_id='{flow_id}'. "
                       "Explanations are only stored for anomalous flows."
            )
        return JSONResponse({"flow_id": flow_id, "explanation": exp})
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/feature_names")
def feature_names():
    """Return the canonical ordered list of 30 DDL feature names."""
    return {
        "n_features": N_DDL_FEATURES,
        "feature_names": DDL_FEATURE_NAMES,
    }


@app.get("/adaptive_stats")
def adaptive_stats():
    """Return MI-based adaptive feature selection state."""
    try:
        ep = get_pipeline()
        return JSONResponse(ep.get_adaptive_stats())
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enhanced Pipeline REST API")
    parser.add_argument("--host",    default=CFG.API_HOST, help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port",    type=int, default=CFG.API_PORT, help="Port (default: 5001)")
    parser.add_argument("--reload",  action="store_true", help="Enable hot-reload (dev only)")
    parser.add_argument("--workers", type=int, default=1, help="Uvicorn worker count")
    args = parser.parse_args()

    logger.info(f"Starting Enhanced Pipeline API on {args.host}:{args.port}")
    uvicorn.run(
        "EnhancedPipeline.rest_api:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        workers=args.workers,
        log_level="info",
    )
