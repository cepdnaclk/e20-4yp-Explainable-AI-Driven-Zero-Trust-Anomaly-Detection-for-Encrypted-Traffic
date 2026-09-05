"""
SDN Buffer — Simulated OpenFlow Buffer Table
=============================================

Simulates the SDN buffer that holds flagged streams while the DDL + XAI
pipeline processes them in the background.

In a real deployment, this would be an actual OpenFlow buffer table where
the SDN controller issues OFPT_PACKET_IN / OFPT_FLOW_MOD messages.
Here we track buffered streams, their features, metadata, and timing.

Flow:
    Decision Tree flags stream → SDN Buffer HOLDS packets
        → DDL says Normal   → SDN Buffer RELEASES (FORWARD)
        → DDL says Anomaly  → SDN Buffer DROPS
"""

import time
import logging

logger = logging.getLogger("SDNBuffer")


class SDNBuffer:
    """
    Simulates the SDN buffer that holds flagged streams while DDL + XAI
    processes them.
    
    In a real deployment, this would be an actual OpenFlow buffer table.
    Here we track buffered streams, their features, and timing.
    """

    def __init__(self, max_buffer_size=1000, timeout_ms=5000):
        """
        Args:
            max_buffer_size: Maximum number of streams that can be buffered.
            timeout_ms: Maximum time (ms) a stream can be held before auto-release.
        """
        self.buffer = {}
        self.max_buffer_size = max_buffer_size
        self.timeout_ms = timeout_ms

    def add(self, stream_id, features, metadata=None):
        """
        Buffer a flagged stream.
        
        Args:
            stream_id: Unique stream identifier.
            features: Feature vector (list or array) for the stream.
            metadata: Optional dict of additional stream info.
        """
        self.buffer[stream_id] = {
            "features": features,
            "metadata": metadata or {},
            "buffered_at": time.time(),
            "status": "BUFFERED"
        }
        logger.info(f"[SDN Buffer] Stream {stream_id} buffered for deep analysis")

    def release(self, stream_id):
        """
        Release a buffered stream (DDL says clean → FORWARD).
        
        Args:
            stream_id: Stream to release.
            
        Returns:
            dict with action and hold time, or None if not found.
        """
        if stream_id in self.buffer:
            entry = self.buffer.pop(stream_id)
            hold_time = (time.time() - entry["buffered_at"]) * 1000
            logger.info(f"[SDN Buffer] Stream {stream_id} RELEASED after {hold_time:.0f}ms")
            return {"action": "FORWARD", "hold_time_ms": hold_time}
        return None

    def drop(self, stream_id):
        """
        Drop a buffered stream (DDL confirms anomaly → DROP).
        
        Args:
            stream_id: Stream to drop.
            
        Returns:
            dict with action and hold time, or None if not found.
        """
        if stream_id in self.buffer:
            entry = self.buffer.pop(stream_id)
            hold_time = (time.time() - entry["buffered_at"]) * 1000
            logger.info(f"[SDN Buffer] Stream {stream_id} DROPPED after {hold_time:.0f}ms")
            return {"action": "DROP", "hold_time_ms": hold_time}
        return None

    def get_buffered_count(self):
        """Return the number of currently buffered streams."""
        return len(self.buffer)

    def get_all_buffered(self):
        """Return a copy of all buffered stream IDs and their metadata."""
        return {sid: {"status": info["status"], "metadata": info["metadata"]}
                for sid, info in self.buffer.items()}

    def clear_expired(self):
        """
        Auto-release any streams that have been buffered longer than timeout_ms.
        
        Returns:
            List of stream IDs that were expired and released.
        """
        now = time.time()
        expired = []
        for stream_id, entry in list(self.buffer.items()):
            hold_time = (now - entry["buffered_at"]) * 1000
            if hold_time > self.timeout_ms:
                self.buffer.pop(stream_id)
                expired.append(stream_id)
                logger.warning(f"[SDN Buffer] Stream {stream_id} EXPIRED after {hold_time:.0f}ms → auto-released")
        return expired
