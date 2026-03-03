# PCAP Streamline Classification Documentation

## Overview
This component is responsible for decomposing large daily PCAP captures into individual flow-level streamlines (PCAPs) based on the ground-truth labels provided by the CIC-IDS-2017 dataset.

## Logic Flow
1.  **CSV Parsing**: Loads flow metadata (5-tuple, timestamp, duration, label) from the "TrafficLabelling" CSVs.
2.  **Time Calibration**: PCAP timestamps often have a drift/offset compared to CSV records. The script scans the first 50,000 packets to find a confident match and calculates the median offset.
3.  **Two-Pass Matching**:
    -   **Pass 1**: Iterates through the raw PCAP. Matches packets to CSV flows using the 5-tuple and time-window (flow start to end + 2s padding). Packets are buffered in memory grouped by their CSV row index.
    -   **Pass 2**: Writes each buffer to a separate `packets.pcap` file within a directory named `Row_<Index>_<Label>`.
4.  **Reporting**: Generates a JSON report for each day summarizing the number of packets expected vs. found for every row.

## Directory Structure
```
Labeled/
└── <Day>/
    └── Row_<Index>_<Label>/
        └── packets.pcap
```

## How to Run
To process a specific day:
```bash
python3 classify_all_days.py <DayName>
```
To process all days:
```bash
python3 classify_all_days.py
```

## Performance Note
Processing 10GB+ PCAPs is CPU and I/O intensive. The script is optimized to use `PcapReader` (scapy) for memory efficiency, though it may take several hours to complete a full day.
