import json
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import os

STATS_FILE = "dashboard/live_stats.json"
OUTPUT_FILE = "dashboard/simulation_confusion_matrix.png"

def generate_cm():
    if not os.path.exists(STATS_FILE):
        print(f"Error: {STATS_FILE} not found.")
        return

    with open(STATS_FILE, 'r') as f:
        stats = json.load(f)
        
    tp = stats.get("TP", 0)
    tn = stats.get("TN", 0)
    fp = stats.get("FP", 0)
    fn = stats.get("FN", 0)
    
    # Confusion Matrix layout:
    # [[TN, FP],
    #  [FN, TP]]
    # Note: Scikit-learn default is usually [[TN, FP], [FN, TP]] if labels=[0, 1] (Normal, Attack)
    # Let's be explicit with labels.
    
    cm = np.array([[tn, fp], [fn, tp]])
    labels = ["Normal", "Attack"]
    
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Reds', 
                xticklabels=labels, yticklabels=labels)
    plt.title('Sentry Simulation: Confusion Matrix')
    plt.xlabel('Predicted Label')
    plt.ylabel('Actual Label')
    
    plt.savefig(OUTPUT_FILE)
    print(f"Confusion Matrix saved to {OUTPUT_FILE}")
    print(f"Stats: TP={tp}, TN={tn}, FP={fp}, FN={fn}")

if __name__ == "__main__":
    generate_cm()
