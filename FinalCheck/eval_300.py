import os
import sys
import time
from multiprocessing import Pool, cpu_count

SIM_DIR = "/scratch1/e20-fyp-xai-anomaly-detection/e20449Sandaru/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/BaseCheckClassifier/sdn/basecheckclassifierSimulation"
sys.path.insert(0, SIM_DIR)

from simulation_pipeline import init_worker, process_stream, DEFAULT_MODEL

DATASET_ROOT = "/scratch1/e20-fyp-xai-anomaly-detection/e20449Sandaru/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/FinalCheck/Dataset300"
REPORT_FILE = "/scratch1/e20-fyp-xai-anomaly-detection/e20449Sandaru/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/FinalCheck/Failed_Detection_Report.md"

def main():
    print(f"[*] Discovering PCAPs in {DATASET_ROOT} ...")
    tasks = []
    for folder in os.listdir(DATASET_ROOT):
        folder_path = os.path.join(DATASET_ROOT, folder)
        if os.path.isdir(folder_path):
            pcap_path = os.path.join(folder_path, "packets.pcap")
            if os.path.exists(pcap_path):
                tasks.append((pcap_path, folder))

    total_tasks = len(tasks)
    print(f"[*] Found {total_tasks:,} streams to process.")

    failed_streams = []
    success_count = 0
    error_count = 0
    
    true_labels = []
    pred_labels = []

    print(f"[*] Starting simulation using {cpu_count()} workers ...")
    
    REAL_MODEL = "/scratch1/e20-fyp-xai-anomaly-detection/e20449Sandaru/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/BaseCheckClassifier_V1/sentry_model_v2.pkl"
    with Pool(processes=cpu_count(), initializer=init_worker, initargs=(REAL_MODEL,)) as pool:
        for idx, (folder, pred, ext_t, inf_t, valid) in enumerate(pool.imap_unordered(process_stream, tasks)):
            if valid:
                real_binary_class = "BENIGN" if "BENIGN" in folder else "ATTACK"
                subclass = folder.split('_')[-1]
                
                true_labels.append(real_binary_class)
                pred_labels.append(pred)
                
                if real_binary_class != pred:
                    failed_streams.append({
                        "folder": folder,
                        "real": real_binary_class,
                        "subclass": subclass,
                        "predicted": pred
                    })
                else:
                    success_count += 1
            else:
                error_count += 1
                
            if (idx + 1) % 50 == 0 or (idx + 1) == total_tasks:
                print(f"    Processed {idx+1:,} / {total_tasks:,} ...")

    from sklearn.metrics import confusion_matrix
    
    report = f"# Failed Detection Report - Subset 300\n\n"
    report += f"**Total Streams Evaluated:** {total_tasks}\n"
    report += f"**Processed Successfully (Valid):** {len(true_labels)}\n"
    report += f"**Successfully Detected:** {success_count}\n"
    report += f"**Failed Detections:** {len(failed_streams)}\n"
    report += f"**Processing Errors (Invalid PCAPs/Exceptions):** {error_count}\n\n"
    
    if len(true_labels) > 0:
        cm = confusion_matrix(true_labels, pred_labels, labels=["BENIGN", "ATTACK"])
        report += "## Confusion Matrix\n\n"
        report += "This matrix shows how the model classified the streams. Rows are actual classes, columns are predicted classes.\n\n"
        report += "| Actual \\ Predicted | Predicted BENIGN | Predicted ATTACK |\n"
        report += "| --- | --- | --- |\n"
        report += f"| **Actual BENIGN** | {cm[0,0]} (True Normal) | {cm[0,1]} (False Attack - Normal as Attack) |\n"
        report += f"| **Actual ATTACK** | {cm[1,0]} (False Normal - Attack as Normal) | {cm[1,1]} (True Attack) |\n\n"
    
    if len(failed_streams) > 0:
        report += "## List of Failed Streams\n\n"
        report += "| Folder Name | Real Binary Class | Specific Class | Predicted As |\n"
        report += "| --- | --- | --- | --- |\n"
        failed_streams.sort(key=lambda x: (x['real'], x['subclass']))
        for failure in failed_streams:
            report += f"| `{failure['folder']}` | {failure['real']} | {failure['subclass']} | {failure['predicted']} |\n"
    else:
        report += "🎉 All streams were correctly classified!\n"

    with open(REPORT_FILE, 'w') as f:
        f.write(report)
        
    print(f"Report saved to {REPORT_FILE}")

if __name__ == '__main__':
    main()
