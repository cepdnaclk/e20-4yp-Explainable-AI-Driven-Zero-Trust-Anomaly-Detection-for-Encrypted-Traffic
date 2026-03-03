# Tuesday Classification Detailed Analysis

## 1. Overall Summary
- **Total CSV Flows**: 445,909
- **Matched Flows**: 53,875 (**12.08%** total recall)
- **Unmatched Flows**: 392,034

## 2. Why is recall low?
The Tuesday CSV contains two distinct time blocks. The PCAP file only covers the latter part of the day.

### Time Block Breakdown
| CSV Hour | Total Flows | Matched | Recall | Status |
|---|---|---|---|---|
| 1 AM - 5 AM | 220,766 | 0 | 0% | **Missing from PCAP** |
| 8 AM - 12 PM | 225,143 | 53,875 | ~24% | Captured in PCAP |

- **Missing Data**: Approximately 50% of the CSV rows (1 AM - 5 AM) are not present in the PCAP file, leading to 0% recall for that period.
- **Captured Data**: For the "Working Hours" block (8 AM - 12 PM), the flow match rate is **~24%**.

## 3. Packet Recall (Matched Flows)
For the flows that were successfully matched, the packet extraction was highly accurate:
- **Expected Packets**: 7,060,021
- **Found Packets**: 6,450,030
- **Packet Recall Rate**: **91.36%**

## 4. Unmatched Flows by Label (Working Hours)
The majority of unmatched flows are `BENIGN`. Attack flows like `FTP-Patator` and `SSH-Patator` also had low recall, matching the ~24% trend of the day.

## 5. Conclusion
The "low" recall for Tuesday is primarily due to:
1. **Time Mismatch**: Half of the CSV data describes traffic from early morning hours that were not recorded in the PCAP.
2. **Sampling/Sync**: Within the captured hours, about 1 in 4 flows were uniquely identified and extracted. 
