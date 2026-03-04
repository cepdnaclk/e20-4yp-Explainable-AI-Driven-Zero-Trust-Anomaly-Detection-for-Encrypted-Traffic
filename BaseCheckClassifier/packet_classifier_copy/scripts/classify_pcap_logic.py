"""
PCAP Packet Classifier and Labeler
==================================

This script matches raw packets from PCAP files with corresponding rows in CSV 
files (labels) from the CIC-IDS-2017 dataset. It generates labeled PCAP streams 
grouped by their classification (e.g., Benign, DDoS).

The script handles time synchronization between PCAP timestamps and CSV entries 
to ensure accurate matching.
"""

import sys
import os
import glob
import pandas as pd
import numpy as np
from scapy.all import PcapReader, PcapWriter, IP, TCP, UDP
from datetime import datetime, timedelta
import shutil

# --- Configuration ---
PCAP_DIR = "../PCAP"
CSV_DIR = "../Generated-Labelled-Flow/TrafficLabelling"
OUTPUT_DIR = "../PCAP/Labeled"
REPORT_FILE = "analytics_report.txt"

# Target Dataset (Friday)
TARGET_DAY = "Friday"
PCAP_FILE = "Friday-WorkingHours.pcap"

# --- Constants ---
# IP Protocol numbers
PROTO_MAP = {6: 'TCP', 17: 'UDP'}

def ensure_dir(directory):
    """Ensures that the specified directory exists, creating it if necessary."""
    if not os.path.exists(directory):
        os.makedirs(directory)

def parse_custom_timestamp(ts_str, is_afternoon):
    """
    Parses timestamp from CSV.
    Handles '7/7/2017 3:30' -> 15:30 if is_afternoon is True.
    """
    try:
        dt = datetime.strptime(ts_str, "%d/%m/%Y %H:%M")
    except ValueError:
        # Try finding AM/PM if present, or just try distinct format
        try:
            dt = datetime.strptime(ts_str, "%d/%m/%Y %I:%M:%S %p")
        except:
             # Fallback or error
             return None

    # Heuristic for 12h format without AM/PM in older CIC datasets
    if is_afternoon and dt.hour < 12:
        dt = dt + timedelta(hours=12)
    
    return dt.timestamp()


def load_flow_data(day_filter):
    """
    Loads all CSVs matching the day_filter.
    Returns a dictionary of flows keyed by 5-tuple.
    """
    print(f"[*] Loading CSV data for {day_filter}...")
    flow_map = {} # Key: (src_ip, dst_ip, sport, dport, proto), Value: List of flow dicts
    
    csv_files = glob.glob(os.path.join(CSV_DIR, f"*{day_filter}*"))
    if not csv_files:
        # Try the space-padded directory name as fallback
        csv_files = glob.glob(os.path.join(CSV_DIR.replace("TrafficLabelling", "TrafficLabelling "), f"*{day_filter}*"))
    
    total_flows = 0
    
    for csv_path in csv_files:
        filename = os.path.basename(csv_path)
        is_afternoon = "Afternoon" in filename
        print(f"    - Parsing {filename} (Afternoon mode: {is_afternoon})")
        
        # Read CSV - optimizing columns
        cols = [
            ' Flow ID', ' Source IP', ' Source Port', ' Destination IP', ' Destination Port', 
            ' Protocol', ' Timestamp', ' Flow Duration', 
            ' Total Fwd Packets', ' Total Backward Packets', 
            'Total Length of Fwd Packets', ' Total Length of Bwd Packets',
            ' Label'
        ]
        
        # Handle potential leading spaces in CSV headers common in CIC datasets
        try:
            df = pd.read_csv(csv_path, usecols=cols, encoding='latin-1')
        except ValueError:
            # Fallback: try reading first row to normalize columns
            df = pd.read_csv(csv_path, encoding='latin-1')
            df.columns = df.columns.str.strip()
            # Select columns again with stripped names
            clean_cols = [c.strip() for c in cols]
            df = df[clean_cols]
        
        df.columns = df.columns.str.strip()
        
        for idx, row in df.iterrows():
            flow_id = row['Flow ID']
            src_ip = row['Source IP']
            dst_ip = row['Destination IP']
            sport = row['Source Port']
            dport = row['Destination Port']
            proto = row['Protocol']
            label = row['Label']
            
            # Key for matching
            key = (src_ip, dst_ip, sport, dport, proto)
            
            ts_val = parse_custom_timestamp(row['Timestamp'], is_afternoon)
            
            flow_data = {
                'id': flow_id,
                'source_file': filename,
                'csv_row': idx + 2, # 1-based index, +header
                'timestamp': ts_val,
                'duration': row['Flow Duration'], # Microseconds
                'fwd_pkts_csv': row['Total Fwd Packets'],
                'bwd_pkts_csv': row['Total Backward Packets'],
                'fwd_bytes_csv': row['Total Length of Fwd Packets'],
                'bwd_bytes_csv': row['Total Length of Bwd Packets'],
                'label': label,
                
                # Stats accumulator for Pass 1 verification
                'matched_packets': 0,
                'calc_fwd_pkts': 0,
                'calc_bwd_pkts': 0,
                'calc_fwd_bytes': 0,
                'calc_bwd_bytes': 0,
                'packet_indices': [] # List of (packet_index, direction)
            }
            
            if key not in flow_map: flow_map[key] = []
            flow_map[key].append(flow_data)
            total_flows += 1

    print(f"[*] Loaded {total_flows} flows across {len(csv_files)} files.")
    return flow_map

def calibrate_time_offset(pcap_path, flow_map):
    """
    Scans first N packets to find a confident match and calculate time offset.
    Offset = PCAP_Time - CSV_Time
    """
    print("[*] Calibrating time offset...")
    offset_samples = []
    
    try:
        reader = PcapReader(pcap_path)
        for i, pkt in enumerate(reader):
            if i > 50000: break # Scan limit
            
            if IP in pkt:
                ip = pkt[IP]
                if TCP in pkt:
                    sport = ip.sport
                    dport = ip.dport
                    proto = 6
                elif UDP in pkt:
                    sport = ip.sport
                    dport = ip.dport
                    proto = 17
                else:
                    continue
                
                # Try finding this flow
                key = (ip.src, ip.dst, sport, dport, proto)
                
                if key in flow_map:
                    # Found a candidate flow
                    # Check if it is a unique flow (only 1 in map) for High Confidence
                    if len(flow_map[key]) == 1:
                        flow_csv_ts = flow_map[key][0]['timestamp']
                        pkt_ts = float(pkt.time)
                        
                        # Rough heuristic: PCAP is likely 2017, CSV is 2017
                        # Difference shouldn't be years.
                        # We expect offset to be around ~3-4 hours (10800s - 14400s) + small drift
                        diff = pkt_ts - flow_csv_ts
                        offset_samples.append(diff)
                        
            if len(offset_samples) > 50: break
    except Exception as e:
        print(f"Error during calibration: {e}")
        return 0.0
        
    if not offset_samples:
        print("[!] Warning: Could not calibrate time offset using exact matches.")
        return 0.0
        
    median_offset = np.median(offset_samples)
    print(f"[*] Time Calibration Complete. Median Offset: {median_offset:.4f} seconds")
    return median_offset

def process_pcap_streams(pcap_path, flow_map, time_offset):
    # Determine Output Directory based on PCAP name
    base_name = os.path.basename(pcap_path).replace(".pcap", "")
    # Final output folder: e.g. Friday-WorkingHours_labeled
    stream_output_dir = os.path.join(OUTPUT_DIR, f"{base_name}_labeled")
    
    if os.path.exists(stream_output_dir):
        shutil.rmtree(stream_output_dir)
    ensure_dir(stream_output_dir)
    
    print(f"\n[Stream Processing] Output Directory: {stream_output_dir}")
    print("[Pass 1] Buffering packets in memory...")
    
    # Map flow_id -> List[Packet]
    # We use flow_id because multiple 5-tuples might map to same flow (retransmissions etc, unlikely but safe)
    # Actually flow_map values have 'id'. Let's map by flow object ID to avoid ambiguity
    flow_buffers = {} 
    
    # We also need to keep track of flow metadata for writing later
    flow_metadata = {}

    try:
        reader = PcapReader(pcap_path)
        for i, pkt in enumerate(reader):
            if i % 10000 == 0:
                print(f"    - buffering {i} packets...", end='\r', flush=True)
            
            if IP not in pkt: continue
            
            ip = pkt[IP]
            proto = 0
            sport = 0
            dport = 0
            payload_len = len(pkt[IP].payload)
            
            if TCP in pkt:
                proto = 6
                sport = ip.sport
                dport = ip.dport
                # Calculate payload size
                tcp_hl = pkt[TCP].dataofs * 4
                ip_hl = ip.ihl * 4
                payload_len = ip.len - ip_hl - tcp_hl
            elif UDP in pkt:
                proto = 17
                sport = ip.sport
                dport = ip.dport
                ip_hl = ip.ihl * 4
                payload_len = ip.len - ip_hl - 8 # UDP header is 8 bytes
            else:
                continue
                
            pkt_ts = float(pkt.time)
            normalized_ts = pkt_ts - time_offset
            
            # Lookup Keys
            key_fwd = (ip.src, ip.dst, sport, dport, proto)
            key_bwd = (ip.dst, ip.src, dport, sport, proto)
            
            # Unified Search Logic: 5-tuple + Timestamp
            candidates = flow_map.get(key_fwd, []) + flow_map.get(key_bwd, [])
            
            for flow in candidates:
                # Time Matching Logic
                start = flow['timestamp']
                duration_sec = flow['duration'] / 1e6
                end = start + duration_sec
                
                # Tolerance: 5 seconds padding
                if (start - 5.0) <= normalized_ts <= (end + 5.0):
                    # Found Match
                    
                    # Initialize buffer if needed
                    fid = flow['id']
                    if fid not in flow_buffers:
                        flow_buffers[fid] = []
                        flow_metadata[fid] = flow
                        
                    flow_buffers[fid].append(pkt)
                    
                    # Update Stats
                    flow['matched_packets'] += 1
                    
                    if ip.src == flow_map.get(key_fwd, [{}])[0].get('src_ip', '') or \
                       (key_fwd in flow_map and flow in flow_map[key_fwd]): 
                        flow['calc_fwd_pkts'] += 1
                        flow['calc_fwd_bytes'] += payload_len
                    else:
                        flow['calc_bwd_pkts'] += 1
                        flow['calc_bwd_bytes'] += payload_len
                        
                    break # Stop after finding the first valid time-match
            
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(1)
        
    print(f"\n[Pass 1] Buffering Complete. Identified {len(flow_buffers)} flow streams.")
    print(f"[Pass 2] Writing streams to disk and verifying...")
    
    # --- Verification & Writing Step ---
    verified_flows = 0
    mismatch_flows = 0
    
    with open(REPORT_FILE, 'w') as f:
        f.write("PCAP Stream Classification Report\n")
        f.write("=================================\n")
        f.write(f"Date: {datetime.now()}\n")
        f.write(f"PCAP: {pcap_path}\n")
        f.write(f"Time Offset Used: {time_offset}\n\n")
        
        # Iterate over all buffered flows
        # We only care about flows that have packets
        
        for fid, pkts in flow_buffers.items():
            flow = flow_metadata[fid]
            
            # Verification Logic
            csv_cnt = flow['fwd_pkts_csv'] + flow['bwd_pkts_csv']
            calc_cnt = len(pkts) # Should match matched_packets
            
            csv_bytes = flow['fwd_bytes_csv'] + flow['bwd_bytes_csv']
            calc_bytes = flow['calc_fwd_bytes'] + flow['calc_bwd_bytes']
            
            delta_cnt = abs(csv_cnt - calc_cnt)
            # Relaxed Tolerance: Allow up to 5 packets diff OR 20% diff
            is_pkt_mismatch = delta_cnt > 5 and (delta_cnt / max(csv_cnt, 1) >= 0.20)
            
            if not is_pkt_mismatch:
                flow['is_verified'] = True
                verified_flows += 1
            else:
                flow['is_verified'] = False
                mismatch_flows += 1
                
                f.write(f"[MISMATCH] Row {flow['csv_row']} (File: {flow['source_file']}) | Flow {flow['id']} | Label: {flow['label']}\n")
                f.write(f"  - Time: {flow['timestamp']} (Duration: {flow['duration']})\n")
                f.write(f"  - Expected CSV Packets: {csv_cnt} | Found PCAP Packets: {calc_cnt}\n")
                f.write(f"  - Expected CSV Bytes: {csv_bytes} | Found PCAP Bytes: {calc_bytes}\n")
                f.write("-" * 50 + "\n")

            # --- WRITING STREAM ---
            # Create Folder: Row_<Index>_<Label>
            # Sanitize label for folder name
            safe_label = "".join(x for x in str(flow['label']) if x.isalnum() or x in "._- ")
            folder_name = f"Row_{flow['csv_row']}_{safe_label}".replace(" ", "_")
            
            flow_dir = os.path.join(stream_output_dir, folder_name)
            ensure_dir(flow_dir)
            
            pcap_out_file = os.path.join(flow_dir, "packets.pcap")
            
            try:
                # Write packets
                wr = PcapWriter(pcap_out_file, append=False, sync=False)
                for p in pkts:
                    wr.write(p)
                wr.close()
            except Exception as e:
                print(f"[!] Error writing flow {fid} to {pcap_out_file}: {e}")

        f.write(f"\nSummary:\n")
        f.write(f"Total Flows Processed: {len(flow_buffers)}\n")
        f.write(f"Verified Flows: {verified_flows}\n")
        f.write(f"Mismatch Flows: {mismatch_flows}\n")
        f.write(f"Output Directory: {stream_output_dir}\n")
    
    print(f"[*] Done. {verified_flows} verified, {mismatch_flows} mismatched.")
    print(f"    - Output: {stream_output_dir}")
    print(f"    - Report: {REPORT_FILE}")

def main():
    full_pcap_path = os.path.join(PCAP_DIR, PCAP_FILE)
    
    print("=== PCAP Classifier Started ===")
    
    # 1. Load Flows
    flows = load_flow_data(TARGET_DAY)
    
    # 2. Calibrate
    if flows:
        offset = calibrate_time_offset(full_pcap_path, flows)
    else:
        print("No flows loaded. Exiting.")
        return

    # 3. Process
    process_pcap_streams(full_pcap_path, flows, offset)

if __name__ == "__main__":
    main()
