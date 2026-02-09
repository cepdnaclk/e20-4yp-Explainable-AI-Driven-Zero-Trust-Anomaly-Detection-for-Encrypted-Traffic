# ============================================================================
# Unified Docker image for the full anomaly-detection pipeline
#   Stage 1 – Data preprocessing  (Isolation Forest + Autoencoder)
#   Stage 2 – Random Forest classifier
#   Stage 3 – SHAP explainability
# ============================================================================
#
# BUILD (CPU):
#   docker build --build-arg BASE_IMAGE=python:3.10-slim -t ml-pipeline .
#
# BUILD (GPU):
#   docker build --build-arg BASE_IMAGE=tensorflow/tensorflow:latest-gpu -t ml-pipeline:gpu .
#
# RUN (CPU):
#   docker run -it -p 8888:8888 -v "$(pwd):/app" ml-pipeline
#
# RUN (GPU):
#   docker run --gpus all -it -p 8888:8888 -v "$(pwd):/app" ml-pipeline:gpu
# ============================================================================

ARG BASE_IMAGE=tensorflow/tensorflow:latest-gpu
FROM ${BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# System dependencies for numpy/scipy/shap C-extensions and matplotlib fonts
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    g++ \
    libgomp1 \
    libglib2.0-0 \
    libgl1 \
    libglx-mesa0 \
    git \
    fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy everything (notebooks, data, artifacts)
COPY . .

EXPOSE 8888

CMD ["jupyter", "lab", "--ip=0.0.0.0", "--port=8888", "--no-browser", "--allow-root"]
