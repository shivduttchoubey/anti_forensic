import os
import json

from scapy.all import rdpcap, IP, TCP, UDP, DNS

# network analyzer produces structured JSON output; anomalies are collected in lists


class NetworkAnalyzer:
    """Modular network artifact analyzer producing structured JSON results.

    Methods detect protocol anomalies, ghost connections, and beaconing.
    The analyze() call returns a dictionary suitable for the scoring engine.
    """

    def analyze(self, filepath: str):
        if not os.path.exists(filepath):
            return self._format_output(
                detected=False,
                anomalies=[],
                detail={"error": "pcap_missing"},
                confidence=0.0,
            )

        try:
            packets = rdpcap(filepath)
        except Exception as e:
            return self._format_output(
                detected=False,
                anomalies=[],
                detail={"error": str(e)},
                confidence=0.0,
            )

        anomalies = []
        proto = self._detect_protocol_anomalies(packets)
        if proto:
            anomalies.append(proto)

        ghost = self._detect_ghost_connections(packets)
        if ghost:
            anomalies.append(ghost)

        beacon = self._detect_beaconing(packets)
        if beacon:
            anomalies.append(beacon)

        if not anomalies:
            return self._format_output(detected=False, anomalies=[], confidence=0.0)

        # overall confidence = max of individual confidences
        overall_conf = max(item.get("confidence", 0.5) for item in anomalies)
        return self._format_output(detected=True, anomalies=anomalies, confidence=overall_conf)

    # --- detection helpers ------------------------------------------------

    def _detect_protocol_anomalies(self, packets):
        issues = []
        for pkt in packets:
            if pkt.haslayer(TCP):
                flags = pkt[TCP].flags
                # SYN+FIN is invalid combination
                if flags & 0x02 and flags & 0x01:
                    issues.append({
                        "packet": pkt.summary(),
                        "issue": "SYN+FIN",
                    })
                # no other handshake/flag rules added yet
        if issues:
            return self._create_anomaly(
                "protocol_anomaly",
                {"issues": issues},
                confidence=0.7,
            )
        return None

    def _detect_ghost_connections(self, packets):
        streams = set()
        anomalies = []
        for pkt in packets:
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                stream_id = f"{pkt[IP].src}:{pkt[TCP].sport}-{pkt[IP].dst}:{pkt[TCP].dport}"
                if pkt[TCP].flags & 0x02:  # SYN
                    streams.add(stream_id)
                elif pkt[TCP].flags & 0x08 and len(pkt[TCP].payload) > 0:
                    if stream_id not in streams:
                        anomalies.append({
                            "stream": stream_id,
                            "description": "data without handshake",
                        })
                        streams.add(stream_id)
        if anomalies:
            return self._create_anomaly(
                "ghost_connection",
                {"streams": anomalies},
                confidence=0.6,
            )
        return None

    def _detect_beaconing(self, packets):
        # simple timing analysis per (src,dst,sport,dport) tuple
        intervals = {}
        for pkt in packets:
            if pkt.haslayer(TCP) or pkt.haslayer(UDP):
                if pkt.haslayer(IP):
                    key = (
                        pkt[IP].src,
                        pkt[IP].dst,
                        pkt.sport if hasattr(pkt, 'sport') else None,
                        pkt.dport if hasattr(pkt, 'dport') else None,
                    )
                    ts = float(pkt.time)
                    if key in intervals:
                        intervals[key].append(ts)
                    else:
                        intervals[key] = [ts]
        beacons = []
        import statistics
        for key, times in intervals.items():
            if len(times) < 5:
                continue
            diffs = [j - i for i, j in zip(times, times[1:])]
            if statistics.pstdev(diffs) < 0.01 and statistics.mean(diffs) < 2.0:
                beacons.append({"stream": key, "avg_interval": statistics.mean(diffs)})
        if beacons:
            return self._create_anomaly(
                "beaconing",
                {"beacons": beacons},
                confidence=0.65,
            )
        return None

    # --- output formatting ------------------------------------------------

    def _create_anomaly(self, anomaly_type, evidence, confidence=0.5):
        return {"anomaly_type": anomaly_type, "evidence": evidence, "confidence": confidence}

    def _format_output(self, detected, anomalies, detail=None, confidence=0.0):
        output = {
            "module": "network",
            "anomaly_detected": detected,
            "confidence": confidence,
            "anomalies": anomalies,
        }
        if detail is not None:
            output["detail"] = detail
        return output


def correlate_results(network_result: dict, memory_result: dict) -> dict:
    """Produce correlation tags based on both analyzers' outputs.

    - beaconing + high_entropy -> possible_c2 & injection_suspected
    - ghost_connection with high_entropy -> possible_c2
    - any network anomaly together with memory anomaly -> general link tag
    """
    tags = set()
    if network_result.get("anomaly_detected") and memory_result.get("anomaly_detected"):
        tags.add("network_and_memory")
    # specific heuristics
    for a in network_result.get("anomalies", []):
        if a.get("anomaly_type") == "beaconing":
            if memory_result.get("anomaly_detected"):
                tags.add("possible_c2")
    for a in memory_result.get("anomalies", []):
        if a.get("anomaly_type") == "high_entropy":
            tags.add("injection_suspected")
    return {"correlation_tags": list(tags)}

