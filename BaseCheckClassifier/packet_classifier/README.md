# Packet Classifier — Base Check Classifier

Stream-based PCAP classifier for the CIC-IDS-2017 dataset. Matches raw PCAP traffic to ground-truth CIC CSV flow records, and writes each matched stream as a labeled mini-PCAP file.

## Directory Structure

```
packet_classifier_copy/
├── CLASSIFICATION_REPORT.md   # Full analysis report for all days
├── README.md                  # This file
├── scripts/                   # Core classification scripts
│   ├── classify_all_days.py   # Main pipeline: runs all 4 days
│   ├── classify_pcap.py       # Single-day classifier (entrypoint)
│   ├── classify_pcap_logic.py # Core matching logic
│   └── run_remaining_days.sh  # Shell launcher for remaining days
├── reports/                   # JSON classification reports (per day)
│   ├── Monday_report.json
│   ├── Tuesday_report.json
│   ├── Wednesday_report.json
│   └── Thursday_report.json
├── logs/                      # Progress logs (per day)
│   ├── monday_progress.log
│   ├── tuesday_progress.log
│   ├── wednesday_progress.log
│   └── thursday_progress.log
├── analysis/                  # Auxiliary analysis scripts & reports
│   ├── analyze_tuesday_by_hour.py
│   ├── analyze_tuesday_details.py
│   ├── check_tuesday_pcap.py
│   ├── recount_and_verify.py
│   ├── analytics_report.txt
│   └── Tuesday_Detailed_Report.md
└── venv/                      # Python virtual environment
```

## Output

Labeled PCAP files are written to:
```
/scratch1/e20-fyp-xai-anomaly-detection/CICDataset/PCAP/Labeled/
├── Monday/      (268,857 streams, 8.91 GB)
├── Tuesday/     (53,875  streams, 7.70 GB)
├── Wednesday/   (175,397 streams, 9.13 GB)
└── Thursday/    (81,803  streams, 5.81 GB)
```

Each subfolder is named `Row_<N>_<LABEL>/` and contains one PCAP file per matched stream.

## Quick Start

```bash
cd scripts/
source ../venv/bin/activate
python classify_all_days.py
```

## Status

| Day | Status | Streams | Match Rate |
|-----|--------|---------|------------|
| Monday | ✅ Done | 268,857 | 101.9% |
| Tuesday | ✅ Done | 53,875 | 91.4% |
| Wednesday | ✅ Done | 175,397 | 87.9% |
| Thursday | ✅ Done | 81,803 | 82.2% |
