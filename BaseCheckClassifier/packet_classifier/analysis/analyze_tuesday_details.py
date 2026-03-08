import json
import pandas as pd
import os

CSV_PATH = "/scratch1/e20-fyp-xai-anomaly-detection/CICDataset/Generated-Labelled-Flow/TrafficLabelling /Tuesday-WorkingHours.pcap_ISCX.csv"
REPORT_PATH = "Tuesday_report.json"

def analyze():
    print("[*] Loading Tuesday CSV...")
    df = pd.read_csv(CSV_PATH, encoding='latin-1')
    df.columns = df.columns.str.strip()
    total_csv_rows = len(df)
    
    print("[*] Loading Tuesday Report...")
    with open(REPORT_PATH, 'r') as f:
        report = json.load(f)
    
    matched_rows = {item['row'] for item in report}
    total_matched = len(matched_rows)
    
    print(f"\n--- Tuesday Classification Summary ---")
    print(f"Total CSV Flows: {total_csv_rows}")
    print(f"Successfully Matched: {total_matched} ({ (total_matched/total_csv_rows)*100:.2f}%)")
    print(f"Unmatched Flows: {total_csv_rows - total_matched}")
    
    # Analyze packet counts for matched
    total_expected_pkts = sum(item['expected_pkts'] for item in report)
    total_found_pkts = sum(item['found_pkts'] for item in report)
    print(f"Expected Packets (Matched Flows): {total_expected_pkts}")
    print(f"Found Packets (Matched Flows): {total_found_pkts} ({ (total_found_pkts/total_expected_pkts)*100 if total_expected_pkts > 0 else 0:.2f}%)")

    # Analyze labels of unmatched
    unmatched_df = df[~df.index.map(lambda x: x+2).isin(matched_rows)]
    label_counts = unmatched_df['Label'].value_counts()
    print("\n--- Unmatched Flows by Label ---")
    print(label_counts)

    # Analyze time range of unmatched
    print("\n--- Time Range Comparison ---")
    print(f"CSV Time Range: {df['Timestamp'].min()} to {df['Timestamp'].max()}")
    
    # Sample some unmatched rows
    print("\n--- Sample Unmatched Rows (First 5) ---")
    print(unmatched_df[['Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol', 'Timestamp', 'Label']].head(5))

if __name__ == "__main__":
    analyze()
