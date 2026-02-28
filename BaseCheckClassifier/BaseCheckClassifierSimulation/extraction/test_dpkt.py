import dpkt
import socket

def test_dpkt_extraction(pcap_path):
    f = open(pcap_path, 'rb')
    pcap = dpkt.pcap.Reader(f)
    
    flows = {} # (proto, s_ip, s_port, d_ip, d_port) -> data
    
    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            
            ip = eth.data
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            proto = ip.p
            
            header_len = ip.hl * 4 # IP header length
            
            if proto == dpkt.ip.IP_PROTO_TCP:
                tcp = ip.data
                header_len += tcp.off * 4 # TCP header length
                
                # Flow key (bidirectional comparison is usually needed, but let's keep it simple for now)
                # NFStream-like key: sorted (src, dst)
                if (src_ip, tcp.sport) < (dst_ip, tcp.dport):
                    key = (proto, src_ip, tcp.sport, dst_ip, tcp.dport)
                    direction = 'fwd'
                else:
                    key = (proto, dst_ip, tcp.dport, src_ip, tcp.sport)
                    direction = 'bwd'
                
                if key not in flows:
                    flows[key] = {
                        'init_win_fwd': -1,
                        'init_win_bwd': -1,
                        'header_len_fwd': 0,
                        'header_len_bwd': 0
                    }
                
                if direction == 'fwd':
                    if flows[key]['init_win_fwd'] == -1:
                        flows[key]['init_win_fwd'] = tcp.win
                    flows[key]['header_len_fwd'] += header_len
                else:
                    if flows[key]['init_win_bwd'] == -1:
                        flows[key]['init_win_bwd'] = tcp.win
                    flows[key]['header_len_bwd'] += header_len
                    
        except Exception as e:
            continue
            
    f.close()
    return flows

pcap_path = "/scratch1/e20-fyp-xai-anomaly-detection/e20449Sandaru/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/BaseCheckClassifier/BaseCheckClassifierSimulation/normal/benign_1.pcap"
results = test_dpkt_extraction(pcap_path)
for key, val in list(results.items())[:5]:
    print(f"Flow {key}: {val}")
