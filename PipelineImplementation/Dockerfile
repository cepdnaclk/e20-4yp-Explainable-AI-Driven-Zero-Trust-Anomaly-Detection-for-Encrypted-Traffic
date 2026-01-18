# --- PROCEDURE ---
# TO BUILD FOR GPU: 
# docker build --build-arg BASE_IMAGE=tensorflow/tensorflow:latest-gpu -t ml-env:gpu .
#
# TO BUILD FOR CPU: 
# docker build --build-arg BASE_IMAGE=python:3.10-slim -t ml-pipeline.
# -----------------

# 1. Define a build argument with a default value (defaulting to GPU)
ARG BASE_IMAGE=tensorflow/tensorflow:latest-gpu
FROM ${BASE_IMAGE}

# 2. Set environment variables to prevent Python from buffering outputs
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# 3. Install system dependencies
# If using 'slim' (CPU), we need build-essential for some C-extensions in sklearn/numpy
RUN apt-get update && apt-get install -y \
    build-essential \
    libgl1 \
    libglx-mesa0 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# 4. Install Python dependencies
# Note: If BASE_IMAGE is tensorflow, it already has TF installed.
# Pip will simply skip it or update it based on your requirements.txt.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 5. Copy project files (Notebooks, datasets, etc.)
COPY . .

# 6. Expose Jupyter port
EXPOSE 8888

# 7. Start Jupyter
CMD ["jupyter", "notebook", "--ip=0.0.0.0", "--port=8888", "--no-browser", "--allow-root"]