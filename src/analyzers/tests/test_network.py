import os
import tempfile

import pytest
from scapy.all import IP, TCP, UDP, DNS, DNSQR, wrpcap, Packet

from src.analyzers.network import NetworkAnalyzer


def create_simple_pcap(packets, path):
    wrpcap(path, packets)


def test_no_file():
    analyzer = NetworkAnalyzer()
    result = analyzer.analyze("nonexistent.pcap")
    assert result["anomaly_detected"] is False
    assert "pcap_missing" in result.get("detail", {}).get("error", "")


def test_protocol_anomaly(tmp_path):
    # craft a TCP packet with SYN+FIN
    pkt = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1234, dport=80, flags="SF")
    pcap = tmp_path / "proto.pcap"
    create_simple_pcap([pkt], str(pcap))

    analyzer = NetworkAnalyzer()
    result = analyzer.analyze(str(pcap))
    assert result["anomaly_detected"]
    types = [a["anomaly_type"] for a in result["anomalies"]]
    assert "protocol_anomaly" in types


def test_ghost_connection(tmp_path):
    # craft packet with PSH/ACK but no SYN
    pkt = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1234, dport=80, flags="PA") / b"data"
    pcap = tmp_path / "ghost.pcap"
    create_simple_pcap([pkt], str(pcap))

    analyzer = NetworkAnalyzer()
    result = analyzer.analyze(str(pcap))
    assert result["anomaly_detected"]
    types = [a["anomaly_type"] for a in result["anomalies"]]
    assert "ghost_connection" in types


def test_beaconing(tmp_path):
    # create multiple packets with near-constant interval
    pkts = []
    base = 1.0
    for i in range(6):
        pkt = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1000, dport=80)
        pkt.time = base + i * 0.5
        pkts.append(pkt)
    pcap = tmp_path / "beacon.pcap"
    create_simple_pcap(pkts, str(pcap))

    analyzer = NetworkAnalyzer()
    result = analyzer.analyze(str(pcap))
    assert result["anomaly_detected"]
    types = [a["anomaly_type"] for a in result["anomalies"]]
    assert "beaconing" in types


def test_correlation_layer():
    from src.analyzers.network import correlate_results

    net = {"anomaly_detected": True, "anomalies": [{"anomaly_type": "beaconing"}], "confidence": 0.6}
    mem = {"anomaly_detected": True, "anomalies": [{"anomaly_type": "high_entropy"}], "confidence": 0.6}
    corr = correlate_results(net, mem)
    assert "possible_c2" in corr["correlation_tags"]
    assert "injection_suspected" in corr["correlation_tags"]
    assert "network_and_memory" in corr["correlation_tags"]


def test_run_analysis_integration(tmp_path):
    from src.analyzers.main import run_analysis
    # create minimal pcap and memory dump
    from scapy.all import IP, TCP, wrpcap

    pkt = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1234, dport=80, flags="SF")
    pcap_path = tmp_path / "int.pcap"
    wrpcap(str(pcap_path), [pkt])

    mem_path = tmp_path / "int.mem"
    with open(mem_path, "wb") as f:
        f.write(os.urandom(4096))

    agg = run_analysis(str(pcap_path), str(mem_path))
    assert agg["network"]["anomaly_detected"]
    assert agg["memory"]["anomaly_detected"]
    # protocol anomaly + entropy only yields general and injection tags
    tags = agg["correlation"]["correlation_tags"]
    assert "network_and_memory" in tags
    assert "injection_suspected" in tags
