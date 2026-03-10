import pandas as pd
import numpy as np

def main():
    csv_path = '/scratch1/e20-fyp-xai-anomaly-detection/e20449Sandaru/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/BaseCheckClassifier/sdn/training/dataset_raw.csv'
    print(f"Loading dataset from {csv_path}...")
    df = pd.read_csv(csv_path)
    
    # Identify target column. Usually 'label' or 'attack_label'
    if 'label' in df.columns:
        df['target_numeric'] = (df['label'] != 'BENIGN').astype(int)
    elif 'attack_label' in df.columns:
        df['target_numeric'] = (df['attack_label'] != 'BENIGN').astype(int)
    else:
        print("Could not find 'label' or 'attack_label' column.")
        return
        
    # Get only numerical columns for correlation
    numerical_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    
    # Calculate correlations
    print("Calculating correlation matrix...")
    corr_matrix = df[numerical_cols].corr()
    
    target_corr = corr_matrix['target_numeric'].drop('target_numeric')
    target_corr_sorted = target_corr.sort_values(key=abs, ascending=False)
    
    print("\n--- Correlation of all features with the Target ('BENIGN' vs 'ATTACK') ---")
    for feature, corr_val in target_corr_sorted.items():
        print(f"{feature:30s} : {corr_val:.4f}")
        
    # Defining low correlation threshold
    threshold = 0.05
    low_corr_features = target_corr[target_corr.abs() < threshold].index.tolist()
    
    print(f"\n--- Features to remove (absolute correlation < {threshold}) ---")
    for feature in low_corr_features:
        print(f"- {feature} (corr: {target_corr[feature]:.4f})")
        
    # Remove these features and target_numeric, then save
    cols_to_drop = low_corr_features + ['target_numeric']
    df_filtered = df.drop(columns=cols_to_drop)
    
    output_path = '/scratch1/e20-fyp-xai-anomaly-detection/e20449Sandaru/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/BaseCheckClassifier/sdn/training/feature_selection/dataset_filtered.csv'
    df_filtered.to_csv(output_path, index=False)
    print(f"\nSaved filtered dataset with {len(df_filtered.columns)} columns (original had {len(df.columns) - 1 + len(low_corr_features)}) to {output_path}")

if __name__ == "__main__":
    main()
