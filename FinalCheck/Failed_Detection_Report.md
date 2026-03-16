# Failed Detection Report - Subset 300

**Total Streams Evaluated:** 300
**Processed Successfully (Valid):** 266
**Successfully Detected:** 258
**Failed Detections:** 8
**Processing Errors (Invalid PCAPs/Exceptions):** 34

## Confusion Matrix

This matrix shows how the model classified the streams. Rows are actual classes, columns are predicted classes.

| Actual \ Predicted | Predicted BENIGN | Predicted ATTACK |
| --- | --- | --- |
| **Actual BENIGN** | 108 (True Normal) | 8 (False Attack - Normal as Attack) |
| **Actual ATTACK** | 0 (False Normal - Attack as Normal) | 150 (True Attack) |

## List of Failed Streams

| Folder Name | Real Binary Class | Specific Class | Predicted As |
| --- | --- | --- | --- |
| `Wednesday_Row_97742_BENIGN` | BENIGN | BENIGN | ATTACK |
| `Thursday_Row_162495_BENIGN` | BENIGN | BENIGN | ATTACK |
| `Thursday_Row_48383_BENIGN` | BENIGN | BENIGN | ATTACK |
| `Thursday_Row_12511_BENIGN` | BENIGN | BENIGN | ATTACK |
| `Friday_Row_33205_BENIGN` | BENIGN | BENIGN | ATTACK |
| `Wednesday_Row_98694_BENIGN` | BENIGN | BENIGN | ATTACK |
| `Friday_Row_87666_BENIGN` | BENIGN | BENIGN | ATTACK |
| `Friday_Row_94733_BENIGN` | BENIGN | BENIGN | ATTACK |
