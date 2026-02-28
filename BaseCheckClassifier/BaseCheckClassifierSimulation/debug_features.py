import sys
import os
import logging

# Add current dir to path to find local modules
sys.path.append(os.getcwd())

# Setup logging to console
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DebugFeatures")

from extraction.feature_extractor import extract_features

TEST_PCAP = "synthetic_attack.pcap"

def debug_extraction():
    print(f"--- Debugging Feature Extraction on {TEST_PCAP} ---")
    
    if not os.path.exists(TEST_PCAP):
        print("[-] Test file not found!")
        return

    try:
        # Run the existing extractor
        print("Running extract_features()...")
        result = extract_features(TEST_PCAP)
        
        print("\n--- Result ---")
        if not result['valid']:
            print(f"[-] Extraction Failed: {result.get('error')}")
        else:
            print("[+] Extraction Success")
            print("Features:")
            for k, v in result['features'].items():
                print(f"  {k}: {v}")
                
            print(f"\nFlow ID: {result['flow_id']}")
            
        print("\n--- Manual DPKT Check ---")
        import dpkt
        import socket
        
        f = open(TEST_PCAP, 'rb')
        pcap = dpkt.pcap.Reader(f)
        
        count = 0
        for ts, buf in pcap:
            count += 1
            if count > 5: break # Only show first 5
            
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP): continue
                ip = eth.data
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
                
                proto = ip.p
                print(f"Packet {count}: {src_ip} -> {dst_ip} (Proto: {proto})")
                
                if proto == dpkt.ip.IP_PROTO_TCP:
                    tcp = ip.data
                    print(f"   TCP Flags: {tcp.flags} | Window: {tcp.win}")
            except:
                pass
        
        print(f"Total packets checked: {count}")
        f.close()

    except Exception as e:
        print(f"[-] Debug Script Crashed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    debug_extraction()
