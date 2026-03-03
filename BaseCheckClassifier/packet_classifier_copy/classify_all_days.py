import sys
import os
import glob
import pandas as pd
import numpy as np
from scapy.all import PcapReader, PcapWriter, IP, TCP, UDP
from datetime import datetime, timedelta
import shutil
import json

# --- Configuration ---
# Use absolute paths for clarity
BASE_DIR = "/scratch1/e20-fyp-xai-anomaly-detection/CICDataset"
PCAP_DIR = os.path.join(BASE_DIR, "PCAP")
CSV_DIR = os.path.join(BASE_DIR, "Generated-Labelled-Flow", "TrafficLabelling ")
OUTPUT_ROOT = os.path.join(PCAP_DIR, "Labeled")
REPORT_ROOT = "/scratch1/e20-fyp-xai-anomaly-detection/e20449Sandaru/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/BaseCheckClassifier/packet_classifier_copy"

# Day-Specific Mapping
DAYS_TO_PROCESS = {
    "Monday": {
        "pcap": "Monday-WorkingHours.pcap",
        "csv_pattern": "*Monday*"
    },
    "Tuesday": {
        "pcap": "Tuesday-WorkingHours.pcap",
        "csv_pattern": "*Tuesday*"
    },
    "Wednesday": {
        "pcap": "Wednesday-workingHours.pcap",
        "csv_pattern": "*Wednesday*"
    },
    "Thursday": {
        "pcap": "Thursday-WorkingHours.pcap",
        "csv_pattern": "*Thursday*"
    }
}

def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def parse_custom_timestamp(ts_str, is_afternoon):
    formats = ["%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%d/%m/%Y %I:%M:%S %p", "%d/%m/%Y %I:%M %p"]
    dt = None
    for fmt in formats:
        try:
            dt = datetime.strptime(ts_str, fmt)
            break
        except ValueError:
            continue
    
    if dt is None:
        return None

    if is_afternoon and dt.hour < 12:
        dt = dt + timedelta(hours=12)
    
    return dt.timestamp()

def load_flow_data(day_name, csv_pattern):
    print(f"[*] Loading CSV data for {day_name}...")
    flow_map = {}
    csv_files = glob.glob(os.path.join(CSV_DIR, csv_pattern))
    
    if not csv_files:
        print(f"[!] No CSV files found for pattern: {csv_pattern}")
        return {}

    total_flows = 0
    for csv_path in csv_files:
        filename = os.path.basename(csv_path)
        is_afternoon = "Afternoon" in filename
        print(f"    - Parsing {filename} (Afternoon: {is_afternoon})")
        
        try:
            df = pd.read_csv(csv_path, encoding='latin-1')
            df.columns = df.columns.str.strip()
        except Exception as e:
            print(f"[!] Error reading {csv_path}: {e}")
            continue

        for idx, row in df.iterrows():
            src_ip = str(row['Source IP']).strip()
            dst_ip = str(row['Destination IP']).strip()
            sport = int(row['Source Port'])
            dport = int(row['Destination Port'])
            proto = int(row['Protocol'])
            label = str(row['Label']).strip()
            
            key = (src_ip, dst_ip, sport, dport, proto)
            ts_val = parse_custom_timestamp(str(row['Timestamp']), is_afternoon)
            
            flow_data = {
                'id': row.get('Flow ID', f"flow_{total_flows}"),
                'csv_row': idx + 2,
                'timestamp': ts_val,
                'duration': row['Flow Duration'],
                'total_pkts': row['Total Fwd Packets'] + row['Total Backward Packets'],
                'label': label,
                'matched_packets': 0
            }
            
            if key not in flow_map: flow_map[key] = []
            flow_map[key].append(flow_data)
            total_flows += 1

    print(f"[*] Loaded {total_flows} flows for {day_name}.")
    return flow_map

def calibrate_time_offset(pcap_path, flow_map):
    print("[*] Calibrating time offset...")
    offset_samples = []
    
    try:
        reader = PcapReader(pcap_path)
        for i, pkt in enumerate(reader):
            if i > 50000: break
            if IP not in pkt: continue
            
            ip = pkt[IP]
            if TCP in pkt:
                sport, dport, proto = ip.sport, ip.dport, 6
            elif UDP in pkt:
                sport, dport, proto = ip.sport, ip.dport, 17
            else: continue
            
            key = (ip.src, ip.dst, sport, dport, proto)
            if key in flow_map:
                for flow in flow_map[key]:
                    # If unique or close enough for calibration
                    flow_csv_ts = flow['timestamp']
                    pkt_ts = float(pkt.time)
                    offset_samples.append(pkt_ts - flow_csv_ts)
                    break
                    
            if len(offset_samples) > 100: break
    except Exception as e:
        print(f"Error during calibration: {e}")
        return 0.0
        
    if not offset_samples: return 0.0
    return np.median(offset_samples)

def process_day(day_name):
    config = DAYS_TO_PROCESS[day_name]
    pcap_path = os.path.join(PCAP_DIR, config["pcap"])
    
    if not os.path.exists(pcap_path):
        print(f"[!] PCAP not found: {pcap_path}")
        return

    flow_map = load_flow_data(day_name, config["csv_pattern"])
    if not flow_map: return

    offset = calibrate_time_offset(pcap_path, flow_map)
    print(f"[*] Offset for {day_name}: {offset:.4f}s")

    day_output_dir = os.path.join(OUTPUT_ROOT, day_name)
    ensure_dir(day_output_dir)
    
    flow_buffers = {}
    flow_metadata = {}

    print(f"[*] Processing {pcap_path}...")
    try:
        reader = PcapReader(pcap_path)
        for i, pkt in enumerate(reader):
            if i % 50000 == 0:
                print(f"    - analyzed {i} packets...", end='\r', flush=True)
            
            if IP not in pkt: continue
            ip = pkt[IP]
            if TCP in pkt:
                sport, dport, proto = ip.sport, ip.dport, 6
            elif UDP in pkt:
                sport, dport, proto = ip.sport, ip.dport, 17
            else: continue
            
            pkt_ts = float(pkt.time)
            norm_ts = pkt_ts - offset
            
            key_fwd = (ip.src, ip.dst, sport, dport, proto)
            key_bwd = (ip.dst, ip.src, dport, sport, proto)
            
            candidates = flow_map.get(key_fwd, []) + flow_map.get(key_bwd, [])
            for flow in candidates:
                start = flow['timestamp']
                end = start + (flow['duration'] / 1e6)
                if (start - 2.0) <= norm_ts <= (end + 2.0):
                    fid = flow['csv_row']
                    if fid not in flow_buffers:
                        flow_buffers[fid] = []
                        flow_metadata[fid] = flow
                    flow_buffers[fid].append(pkt)
                    flow['matched_packets'] += 1
                    break
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        return

    print(f"\n[*] Writing {len(flow_buffers)} streamlines for {day_name}...")
    report_data = []
    
    for fid, pkts in flow_buffers.items():
        flow = flow_metadata[fid]
        safe_label = "".join(x for x in flow['label'] if x.isalnum() or x in "._-").replace(" ", "_")
        folder_name = f"Row_{flow['csv_row']}_{safe_label}"
        flow_dir = os.path.join(day_output_dir, folder_name)
        ensure_dir(flow_dir)
        
        pcap_out = os.path.join(flow_dir, "packets.pcap")
        wr = PcapWriter(pcap_out, append=False, sync=False)
        for p in pkts: wr.write(p)
        wr.close()
        
        report_data.append({
            "row": flow['csv_row'],
            "label": flow['label'],
            "expected_pkts": flow['total_pkts'],
            "found_pkts": len(pkts)
        })

    # Save day report
    report_file = os.path.join(REPORT_ROOT, f"{day_name}_report.json")
    with open(report_file, 'w') as rf:
        json.dump(report_data, rf, indent=2)
    print(f"[*] Report saved: {report_file}")

def main():
    if len(sys.argv) > 1:
        target = sys.argv[1]
        if target in DAYS_TO_PROCESS:
            process_day(target)
        else:
            print(f"Unknown day: {target}")
    else:
        for day in DAYS_TO_PROCESS:
            process_day(day)

if __name__ == "__main__":
    main()
