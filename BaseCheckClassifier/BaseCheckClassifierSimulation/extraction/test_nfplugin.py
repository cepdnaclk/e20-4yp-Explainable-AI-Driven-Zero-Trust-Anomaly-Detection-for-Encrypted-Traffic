from nfstream import NFStreamer, NFPlugin

class TCPWindowPlugin(NFPlugin):
    def on_init(self, packet, flow):
        if packet.protocol == 6: # TCP
            if flow.src_port == packet.src_port: # Forward
                if flow.src2dst_packets == 1:
                    flow.udps.init_win_fwd = packet.window
            else: # Backward
                if flow.dst2src_packets == 1:
                    flow.udps.init_win_bwd = packet.window

    def on_update(self, packet, flow):
        if packet.protocol == 6:
            if flow.src_port == packet.src_port: # Forward
                if flow.src2dst_packets == 1:
                    flow.udps.init_win_fwd = packet.window
            else:
                 if flow.dst2src_packets == 1:
                    flow.udps.init_win_bwd = packet.window

pcap_path = "/scratch1/e20-fyp-xai-anomaly-detection/e20449Sandaru/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/BaseCheckClassifier/BaseCheckClassifierSimulation/normal/benign_1.pcap"

try:
    streamer = NFStreamer(source=pcap_path, udps=TCPWindowPlugin(), statistical_analysis=True)
    df = streamer.to_pandas()
    if not df.empty:
        print("Projected columns:")
        print(df.columns)
        if 'udps.init_win_fwd' in df.columns:
            print("Init Win Fwd example:", df['udps.init_win_fwd'].iloc[0])
        else:
            print("udps.init_win_fwd not found")
            
        if 'udps.init_win_bwd' in df.columns:
            print("Init Win Bwd example:", df['udps.init_win_bwd'].iloc[0])
    else:
        print("No flows found")
except Exception as e:
    print(f"Error: {e}")
