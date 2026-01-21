# Data Cleaning & Environment Guide

This guide details the automated cleaning pipeline for the BCCC Darknet dataset and provides instructions for running the development environment using Docker.

## 1. Data Cleaning Pipeline Logic

The cleaning process is primarily handled in the early cells of `confidence_pseudo_labeling.ipynb`. It follows a rigid sequence to ensure the data is suitable for ensemble anomaly detection.

### Step 1: Loading & Initial Selection

- **Input:** The raw dataset is loaded from `bccc_darknet.csv`.

- **Type Filtering:** Only numeric features (`float64`, `int64`) are retained for the pipeline. Non-numeric identifiers like `flow_id` and `src_ip` are dropped to prevent the model from learning specific network addresses.

### Step 2: Numerical Sanitization

- **Infinite Value Handling:** Replaces all `inf` and `-inf` values with `NaN` to prevent calculation errors in the models.

- **Missing Value Imputation:** Fills all `NaN` entries with the median of each respective column. This is more robust to outliers than using the mean.

- **Value Clipping:** Extreme numerical values are clipped between `-1e9` and `1e9` to maintain numerical stability during the Autoencoder's backpropagation.

### Step 3: Feature Engineering & Scaling

- **Variance-Based Selection:** To reduce noise, the pipeline identifies the top 50 features with the highest variance. These are deemed the most informative for detecting anomalies.

- **Standardization:** All features are scaled using a `StandardScaler` to have a mean of 0 and a standard deviation of 1. This ensures that features with larger ranges do not dominate the Isolation Forest or the Autoencoder.

## 2. Running the Docker Environment

The environment is containerized to avoid Python version incompatibilities. Use the following procedures to build and launch the system.

### Building the Image

From the `PipelineImplementation` directory, run:

```bash
# For local CPU development
docker build --build-arg BASE_IMAGE=python:3.10-slim -t ml-pipeline .
```

### Starting the Container

Run the container with a volume mount to ensure your changes to the notebook are saved locally:

```bash
docker run -it -p 8888:8888 -v "$(pwd):/app" ml-pipeline
```

### GPU Guidelines

- **Ensure that the NVIDIA runtime is available for GPU support.**
- **Use the following command to run the container with GPU support:**

```bash
docker run --gpus all -it -p 8888:8888 -v "$(pwd):/app" ml-env:gpu
```

## 3. Accessing the Development Interface

### Access via Browser

Once the container starts, look at the terminal output for a URL starting with `http://127.0.0.1:8888/tree?token=....`

Copy this entire link and paste it into your web browser.

Click on `confidence_pseudo_labeling.ipynb` to begin.

### Access via VS Code

1. Open the `PipelineImplementation` folder in VS Code.
2. Open the `.ipynb` file.
3. Click "Select Kernel" in the top-right corner.
4. Choose "Existing Jupyter Server".
5. Paste the same URL (with the token) from your terminal.

## 4. Stopping and Starting the Container

### Stopping the Container

To stop the running container, you can use the following command in a new terminal:

```bash
docker stop <container_id>
```

Replace `<container_id>` with the actual ID of your running container. You can find the container ID by running:

```bash
docker ps
```

### Starting the Container

To start a stopped container, use:

```bash
docker start <container_id>
```

Again, replace `<container_id>` with the ID of the container you wish to start. You can also use the following command to start the container and attach to it:

```bash
docker start -ai <container_id>
```

## 5. Pipeline Artifacts

After running the full notebook, the following cleaned files will be generated in the `./pseudo_labeling_artifacts` folder:

- `scaler_pseudo_labeling.pkl`: The trained scaler for future inference.

- `bccc_labeled_high_confidence.csv`: The final cleaned dataset containing only high-confidence anomalies (where IF and AE agree) and normal traffic.