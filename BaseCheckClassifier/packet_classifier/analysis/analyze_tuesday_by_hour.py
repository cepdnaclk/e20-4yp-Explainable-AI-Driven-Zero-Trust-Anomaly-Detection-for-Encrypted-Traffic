import json
import pandas as pd
from datetime import datetime

CSV_PATH = "/scratch1/e20-fyp-xai-anomaly-detection/CICDataset/Generated-Labelled-Flow/TrafficLabelling /Tuesday-WorkingHours.pcap_ISCX.csv"
REPORT_PATH = "Tuesday_report.json"

def analyze():
    print("[*] Loading Tuesday CSV...")
    df = pd.read_csv(CSV_PATH, encoding='latin-1')
    df.columns = df.columns.str.strip()
    df['dt'] = pd.to_datetime(df['Timestamp'], format='mixed')
    
    print("[*] Loading Tuesday Report...")
    with open(REPORT_PATH, 'r') as f:
        report = json.load(f)
    
    matched_rows = {item['row'] for item in report}
    
    # Analyze by hour
    df['is_matched'] = df.index.map(lambda x: x+2 in matched_rows)
    df['hour'] = df['dt'].dt.hour
    
    res = df.groupby('hour').agg(
        total_flows=('is_matched', 'count'),
        matched_flows=('is_matched', 'sum')
    )
    res['recall (%)'] = (res['matched_flows'] / res['total_flows']) * 100
    
    print("\n--- Recall Breakdown by CSV Hour ---")
    print(res)
    
    print(f"\nTotal Matched: {len(matched_rows)}")
    print(f"Total CSV Rows: {len(df)}")
    
    # Summary of packet counts for matched
    total_expected = sum(item['expected_pkts'] for item in report)
    total_found = sum(item['found_pkts'] for item in report)
    print(f"\nPacket Recall (Matched Flows): {total_found} / {total_expected} ({ (total_found/total_expected)*100:.2f}%)")

if __name__ == "__main__":
    analyze()
