# XAI Explanation Samples


## Flow #11 — GT: Attack, Decision: DROP


### IF LIME Top Features

| Feature | Weight |
|---------|--------|
| syn_flag_count <= 0.00 | -0.037358 |
| fwd_iat_total > 1259136.75 | 0.032470 |
| urg_flag_count <= 0.00 | -0.027502 |
| flow_iat_std > 943208.78 | 0.026450 |
| 0.00 < ack_flag_count <= 1.00 | 0.024704 |

**Timing:** DDL-LIME: 44.74ms | DDL-SHAP: N/Ams | IF-LIME: 20.09ms | IF-SHAP: N/Ams


## Flow #12 — GT: Normal, Decision: DROP


### IF LIME Top Features

| Feature | Weight |
|---------|--------|
| fwd_iat_total > 1259136.75 | 0.031186 |
| flow_iat_std > 943208.78 | 0.030044 |
| flow_duration > 4756517.25 | 0.029360 |
| 0.00 < ack_flag_count <= 1.00 | 0.026885 |
| fwd_pkt_len_std > 23.11 | 0.024439 |

**Timing:** DDL-LIME: 43.75ms | DDL-SHAP: N/Ams | IF-LIME: 19.57ms | IF-SHAP: N/Ams


## Flow #16 — GT: Attack, Decision: DROP


### IF LIME Top Features

| Feature | Weight |
|---------|--------|
| bwd_pkt_len_mean > 161.42 | 0.031067 |
| urg_flag_count <= 0.00 | -0.030127 |
| fwd_iat_total > 1259136.75 | 0.029157 |
| flow_duration > 4756517.25 | 0.027807 |
| bwd_iat_std > 15752.07 | 0.025805 |

**Timing:** DDL-LIME: 42.2ms | DDL-SHAP: N/Ams | IF-LIME: 19.18ms | IF-SHAP: N/Ams
