import dpkt
import sys

def check_timestamps(pcap_path):
    print(f"Checking {pcap_path}...")
    f = open(pcap_path, 'rb')
    pcap = dpkt.pcap.Reader(f)
    
    first_ts = None
    last_ts = None
    count = 0
    
    for ts, buf in pcap:
        if first_ts is None:
            first_ts = ts
        last_ts = ts
        count += 1
        
    print(f"Count: {count}")
    print(f"First TS: {first_ts}")
    print(f"Last TS:  {last_ts}")
    if first_ts and last_ts:
        print(f"Duration: {last_ts - first_ts:.2f}s")

if __name__ == "__main__":
    check_timestamps(sys.argv[1])
