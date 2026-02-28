import os
import glob
import dpkt

BASE_DIR = "/scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Friday-labeled-small"

def count_packets(pcap_path):
    try:
        f = open(pcap_path, 'rb')
        pcap = dpkt.pcap.Reader(f)
        count = 0
        for _ in pcap:
            count += 1
        f.close()
        return count
    except Exception as e:
        # print(f"Error reading {pcap_path}: {e}")
        return -1

def survey_dataset():
    print(f"Surveying PCAPs in: {BASE_DIR}")
    
    # Find all packets.pcap files recursively
    pcap_files = glob.glob(os.path.join(BASE_DIR, "*", "*.pcap"))
    
    benign_counts = []
    attack_counts = []
    
    print(f"Found {len(pcap_files)} PCAP files.")
    
    for pcap in pcap_files:
        count = count_packets(pcap)
        parent_dir = os.path.basename(os.path.dirname(pcap))
        
        if "BENIGN" in parent_dir:
            benign_counts.append((parent_dir, count))
        else:
            attack_counts.append((parent_dir, count))
            
    # Sort by packet count
    benign_counts.sort(key=lambda x: x[1])
    attack_counts.sort(key=lambda x: x[1])
    
    print("\n--- ATTACK SAMPLES (Smallest 10) ---")
    for name, count in attack_counts[:10]:
        print(f"{count:5d} packets | {name}")

    print("\n--- ATTACK SAMPLES (Largest 10) ---")
    for name, count in attack_counts[-10:]:
        print(f"{count:5d} packets | {name}")
        
    print("\n--- BENIGN SAMPLES (Smallest 10) ---")
    for name, count in benign_counts[:10]:
        print(f"{count:5d} packets | {name}")

    print("\n--- BENIGN SAMPLES (Largest 10) ---")
    for name, count in benign_counts[-10:]:
        print(f"{count:5d} packets | {name}")

    # Summary Stats
    print("\n--- SUMMARY ---")
    print(f"Total Benign Files: {len(benign_counts)}")
    print(f"Total Attack Files: {len(attack_counts)}")
    
    if attack_counts:
        avg_attack = sum(c for _, c in attack_counts) / len(attack_counts)
        print(f"Avg Attack Packets: {avg_attack:.2f}")
        print(f"Min Attack Packets: {attack_counts[0][1]}")
        print(f"Max Attack Packets: {attack_counts[-1][1]}")
        
    if benign_counts:
        avg_benign = sum(c for _, c in benign_counts) / len(benign_counts)
        print(f"Avg Benign Packets: {avg_benign:.2f}")
        print(f"Min Benign Packets: {benign_counts[0][1]}")
        print(f"Max Benign Packets: {benign_counts[-1][1]}")

if __name__ == "__main__":
    survey_dataset()
