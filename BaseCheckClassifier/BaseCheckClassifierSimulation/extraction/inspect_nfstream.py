from nfstream import NFStreamer
import pandas as pd

pcap_path = "/scratch1/e20-fyp-xai-anomaly-detection/e20449Sandaru/e20-4yp-Explainable-AI-Driven-Zero-Trust-Anomaly-Detection-for-Encrypted-Traffic/BaseCheckClassifier/BaseCheckClassifierSimulation/normal/benign_1.pcap"

try:
    streamer = NFStreamer(source=pcap_path, statistical_analysis=True)
    df = streamer.to_pandas()
    if not df.empty:
        print("Columns in NFStream DataFrame:")
        for col in df.columns:
            print(col)
        # print first row to see values
        print("\nFirst row values:")
        print(df.iloc[0])
    else:
        print("No flows found.")
except Exception as e:
    print(f"Error: {e}")
