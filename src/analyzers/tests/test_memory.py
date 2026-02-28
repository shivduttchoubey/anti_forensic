import os
import tempfile

import pytest

from src.analyzers.memory import MemoryAnalyzer, calculate_entropy


def test_entropy_low():
    data = b"\x00" * 4096
    assert calculate_entropy(data) == 0.0


def test_entropy_high():
    data = os.urandom(4096)
    ent = calculate_entropy(data)
    assert ent > 7.0


def test_memory_analyzer_no_file():
    analyzer = MemoryAnalyzer()
    result = analyzer.analyze("nope.dump")
    assert result["anomaly_detected"] is False
    assert "dump_missing" in result.get("detail", {}).get("error", "")


def test_memory_analyzer_entropy(tmp_path):
    # create file with a high-entropy chunk followed by zeros
    path = tmp_path / "mem.bin"
    with open(path, "wb") as f:
        f.write(os.urandom(4096))
        f.write(b"\x00" * 4096)
    analyzer = MemoryAnalyzer()
    result = analyzer.analyze(str(path))
    assert result["anomaly_detected"]
    types = [a["anomaly_type"] for a in result["anomalies"]]
    assert "high_entropy" in types
