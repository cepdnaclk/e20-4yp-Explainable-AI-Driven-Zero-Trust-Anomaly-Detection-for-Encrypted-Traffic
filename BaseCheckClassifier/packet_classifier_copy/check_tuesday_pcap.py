from scapy.all import PcapReader
import pandas as pd
import os
from datetime import datetime

PCAP_PATH = "/scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Tuesday-WorkingHours.pcap"
CSV_PATH = "/scratch1/e20-fyp-xai-anomaly-detection/CICDataset/Generated-Labelled-Flow/TrafficLabelling /Tuesday-WorkingHours.pcap_ISCX.csv"

def check():
    print("[*] Reading first packet...")
    reader = PcapReader(PCAP_PATH)
    first_pkt = next(reader)
    first_ts = float(first_pkt.time)
    print(f"First PCAP TS: {first_ts} ({datetime.fromtimestamp(first_ts)})")
    
    # We don't want to read the whole 11GB file if we can avoid it.
    # Let's check the size and estimate.
    size = os.path.getsize(PCAP_PATH)
    print(f"PCAP Size: {size / 1e9:.2f} GB")
    
    # Actually, we need the last packet. Let's use a faster way if possible.
    # But for now, let's just sample every 1M packets.
    print("[*] Sampling packets to find end time...")
    last_ts = first_ts
    count = 0
    try:
        for p in reader:
            count += 1
            if count % 1000000 == 0:
                print(f"  - Read {count}...+1 M packets...")
                last_ts = float(p.time)
        last_ts = float(p.time) # Final packet
    except StopIteration:
        pass
    
    print(f"Last PCAP TS: {last_ts} ({datetime.fromtimestamp(last_ts)})")
    print(f"Total packets approx: {count + 1}")
    print(f"Duration: {(last_ts - first_ts) / 3600:.2f} hours")

    print("\n[*] Loading CSV...")
    df = pd.read_csv(CSV_PATH, encoding='latin-1')
    df.columns = df.columns.str.strip()
    # Handle both formats
    df['dt'] = pd.to_datetime(df['Timestamp'], format='mixed')
    csv_min = df['dt'].min()
    csv_max = df['dt'].max()
    print(f"CSV Min: {csv_min}")
    print(f"CSV Max: {csv_max}")
    print(f"CSV Duration: {(csv_max - csv_min).total_seconds() / 3600:.2f} hours")

    offset = first_ts - csv_min.timestamp()
    print(f"Suggested Offset: {offset:.2f}s ({(offset/3600):.2f} hours)")

if __name__ == "__main__":
    check()
