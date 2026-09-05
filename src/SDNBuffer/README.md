# SDN Buffer — Zero-Trust Stream Buffering Simulation

This module simulates the **SDN (Software-Defined Networking) buffer** that holds flagged traffic streams while the DDL + XAI deep analysis runs.

## How It Works

In the zero-trust pipeline:

1. **Decision Tree** flags a stream as suspicious
2. **SDN Buffer** holds the stream's packets (simulated as a dict entry)
3. **DDL + XAI** analyze the stream in the background
4. Based on DDL's verdict:
   - **Normal** → Buffer **RELEASES** the stream (FORWARD)
   - **Anomaly** → Buffer **DROPS** the stream

## Real-World Mapping

| Simulation | Real SDN Deployment |
|------------|---------------------|
| `SDNBuffer.add()` | `OFPT_PACKET_IN` → controller buffers packet |
| `SDNBuffer.release()` | `OFPT_FLOW_MOD` with `FORWARD` action |
| `SDNBuffer.drop()` | `OFPT_FLOW_MOD` with `DROP` action |
| `timeout_ms` | OpenFlow `idle_timeout` / `hard_timeout` |

## Files

| File | Description |
|------|-------------|
| `sdn_buffer.py` | `SDNBuffer` class — add, release, drop, clear_expired |
| `__init__.py` | Package init, exports `SDNBuffer` |

## Usage

```python
from SDNBuffer.sdn_buffer import SDNBuffer

buffer = SDNBuffer(max_buffer_size=1000, timeout_ms=5000)

# Buffer a flagged stream
buffer.add("stream_001", features=[1, 2, 3], metadata={"src": "192.168.1.1"})

# After DDL analysis...
buffer.release("stream_001")  # → {"action": "FORWARD", "hold_time_ms": 42}
# or
buffer.drop("stream_002")     # → {"action": "DROP", "hold_time_ms": 38}
```

## Dependencies

- `time` (stdlib)
- `logging` (stdlib)

No external dependencies required.
