import os
import json
import math
from collections import Counter

# memory analyzer will compute entropy over dump and flag suspicious regions


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy for a byte sequence."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class MemoryAnalyzer:
    """Analyzer for raw memory dumps using entropy heuristics.

    Scans the file in fixed-size chunks and flags regions with high entropy.
    Returns structured JSON similar to network analyzer.
    """

    CHUNK_SIZE = 4096
    ENTROPY_THRESHOLD = 7.5

    def analyze(self, filepath: str):
        if not os.path.exists(filepath):
            return self._format_output(
                detected=False,
                anomalies=[],
                detail={"error": "dump_missing"},
                confidence=0.0,
            )

        try:
            with open(filepath, "rb") as f:
                data = f.read()
        except Exception as e:
            return self._format_output(
                detected=False,
                anomalies=[],
                detail={"error": str(e)},
                confidence=0.0,
            )

        regions = []
        for offset in range(0, len(data), self.CHUNK_SIZE):
            chunk = data[offset : offset + self.CHUNK_SIZE]
            ent = calculate_entropy(chunk)
            if ent > self.ENTROPY_THRESHOLD:
                regions.append({"offset": offset, "entropy": ent})

        if regions:
            anomaly = {
                "anomaly_type": "high_entropy",
                "evidence": {"regions": regions},
                "confidence": 0.6,
            }
            return self._format_output(detected=True, anomalies=[anomaly], confidence=0.6)

        return self._format_output(detected=False, anomalies=[], confidence=0.0)

    def _format_output(self, detected, anomalies, detail=None, confidence=0.0):
        output = {
            "module": "memory",
            "anomaly_detected": detected,
            "confidence": confidence,
            "anomalies": anomalies,
        }
        if detail is not None:
            output["detail"] = detail
        return output

