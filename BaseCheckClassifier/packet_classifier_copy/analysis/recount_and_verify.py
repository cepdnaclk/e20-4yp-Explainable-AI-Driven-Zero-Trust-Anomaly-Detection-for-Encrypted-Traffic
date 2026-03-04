import os
import sys
import pandas as pd
from scapy.all import rdpcap

def verify_day(day_name, sample_size=10):
    root_dir = f"/scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/{day_name}"
    if not os.path.exists(root_dir):
        print(f"Directory not found: {root_dir}")
        return

    subdirs = [os.path.join(root_dir, d) for d in os.listdir(root_dir) if os.path.isdir(os.path.join(root_dir, d))]
    if not subdirs:
        print(f"No streamlines found in {root_dir}")
        return

    import random
    samples = random.sample(subdirs, min(len(subdirs), sample_size))
    
    print(f"--- Verification Report for {day_name} (Sample of {len(samples)}) ---")
    for sdir in samples:
        basename = os.path.basename(sdir)
        # Expected row index is in the folder name Row_<ID>_<Label>
        parts = basename.split("_")
        row_idx = int(parts[1])
        label = parts[2]
        
        pcap_file = os.path.join(sdir, "packets.pcap")
        if not os.path.exists(pcap_file):
            print(f"[FAIL] {basename}: packets.pcap missing")
            continue
            
        try:
            pkts = rdpcap(pcap_file)
            found_count = len(pkts)
            print(f"[OK] {basename}: {found_count} packets found.")
        except Exception as e:
            print(f"[ERR] {basename}: Could not read PCAP: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        verify_day(sys.argv[1])
    else:
        print("Usage: python3 recount_and_verify.py <DayName>")
