import logging
import random
import sys
from scapy.all import Ether, IP, TCP, UDP, wrpcap, RandShort, RandString

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("TrafficGenerator")

def generate_benign_traffic(output_path, num_packets=100):
    """
    Generates a synthetic benign traffic flow.
    Characteristics: consistent packet sizes, regular intervals (simulated), standard flags.
    """
    logger.info(f"Generating BENIGN traffic to {output_path}...")
    packets = []
    
    # Simulate a standard HTTP-like interaction
    src_ip = "192.168.1.100"
    dst_ip = "10.0.0.5"
    src_port = 12345
    dst_port = 80
    
    # Handshake
    packets.append(Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="S", seq=1000))
    packets.append(Ether()/IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags="SA", seq=2000, ack=1001))
    packets.append(Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="A", seq=1001, ack=2001))
    
    # Data packets - consistent size (simulating steady stream)
    for i in range(num_packets):
        payload = "A" * 100 # Fixed payload size -> Low Variance
        p = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="PA")/payload
        packets.append(p)
        
    # Fin
    packets.append(Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="FA"))
    
    wrpcap(output_path, packets)
    logger.info("Done.")


def generate_attack_traffic(output_path, num_packets=5000):
    """
    Generates a synthetic ATTACK traffic flow (Volumetric DDoS).
    Characteristics: High packet rate, high variance (random payloads), sustained flood.
    """
    logger.info(f"Generating ATTACK traffic to {output_path}...")
    packets = []
    
    src_ip = "172.16.66.66"
    dst_ip = "192.168.10.50"
    src_port = random.randint(1024, 65535)
    dst_port = 80
    
    # Start time
    import time
    t = time.time()
    
    # Handshake
    p1 = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="S", seq=1000, options=[('MSS', 1460)])
    p1.time = t
    packets.append(p1)
    
    t += 0.001
    p2 = Ether()/IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags="SA", seq=2000, ack=1001, options=[('MSS', 1460)])
    p2.time = t
    packets.append(p2)
    
    t += 0.001
    p3 = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="A", seq=1001, ack=2001)
    p3.time = t
    packets.append(p3)
    
    t += 0.005
    
    # high-rate flood
    for i in range(num_packets):
        # 1. Packet Size Variance 
        # Randomize to ensure high variance feature
        if random.random() < 0.5:
             payload_size = random.randint(0, 50)
        else:
             payload_size = random.randint(800, 1460)
        
        payload = str(RandString(payload_size)).encode('utf-8')
        
        # 2. Inter-Arrival Time (IAT) - HIGH RATE
        # Flood: very small dt
        dt = random.uniform(0.0001, 0.002) 
            
        t += dt
        
        # 3. Flags & Direction
        flags = 'PA'
        
        p = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags=flags)/payload
        p.time = t
        packets.append(p)

        # High volume of backward packets (responses/errors) to boost Bwd Packet/s
        # 40% response rate
        if random.random() < 0.4:
            t += 0.0001
            p_bwd = Ether()/IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags='A')
            p_bwd.time = t
            packets.append(p_bwd)
        
    # Fin
    t += 0.01
    p_fin = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="FA", seq=1000+num_packets, ack=2000)
    p_fin.time = t
    packets.append(p_fin)
    
    # Use PcapWriter to enforce timestamps
    from scapy.utils import PcapWriter
    with PcapWriter(output_path, append=False, sync=True) as pktdump:
        for pkt in packets:
            pktdump.write(pkt)
            
    logger.info(f"Done. Generated {len(packets)} packets. Duration: {t - packets[0].time:.2f}s")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 generate_synthetic.py <output_folder>")
        sys.exit(1)
        
    output_folder = sys.argv[1]
    
    benign_file = f"{output_folder}/synthetic_benign.pcap"
    attack_file = f"{output_folder}/synthetic_attack.pcap"
    
    generate_benign_traffic(benign_file)
    generate_attack_traffic(attack_file)
