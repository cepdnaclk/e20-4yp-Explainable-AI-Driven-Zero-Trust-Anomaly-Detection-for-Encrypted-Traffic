from nfstream import NFStreamer, NFPlugin

class InspectPlugin(NFPlugin):
    def on_init(self, packet, flow):
        if flow.src2dst_packets == 1:
            print("Packet attributes:", dir(packet))
            print("Raw packet content available?", hasattr(packet, 'raw'))
            print("Payload size:", packet.payload_size)
            print("IP size:", packet.ip_size)

pcap_path = "/scratch1/e20-fyp-xai-anomaly-detection/e20449Sandaru/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/BaseCheckClassifier/BaseCheckClassifierSimulation/normal/benign_1.pcap"
streamer = NFStreamer(source=pcap_path, udps=InspectPlugin(), statistical_analysis=True)
streamer.to_pandas()
