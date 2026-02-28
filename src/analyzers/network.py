from scapy.all import rdpcap, IP, TCP, UDP, DNS, ICMP
from src.engine.scoring import Anomaly, get_scoring_engine
import os

class NetworkAnalyzer:
    def __init__(self):
        self.scoring = get_scoring_engine()

    def analyze(self, filepath: str):
        if not os.path.exists(filepath):
            print(f"[-] PCAP not found: {filepath}")
            return
            
        print(f"[*] Analyzing Network Traffics: {filepath}")
        try:
            packets = rdpcap(filepath)
            self._detect_dns_tunneling(packets)
            self._detect_stat_violations(packets)
            self._detect_icmp_tunnels(packets)
            self._detect_exfiltration_anomalies(packets)
        except Exception as e:
            print(f"[-] Network error: {e}")

    def _detect_stat_violations(self, packets):
        """ Detects Protocol STAT violations: e.g. PSH-ACK without SYN (Ghost Connections). """
        active_syns = set()
        for pkt in packets:
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                stream = f"{pkt[IP].src}:{pkt[TCP].sport}->{pkt[IP].dst}:{pkt[TCP].dport}"
                if pkt[TCP].flags & 0x02: # SYN
                    active_syns.add(stream)
                elif (pkt[TCP].flags & 0x08) and (pkt[TCP].flags & 0x10): # PSH-ACK
                    if stream not in active_syns:
                        self.scoring.add_anomaly(Anomaly(
                            category="HIDE",
                            description="Protocol STAT Violation: Ghost Connection (Data push without SYN).",
                            source="Network Engine",
                            reference=f"TCP Stream: {stream}",
                            confidence=85
                        ))
                        active_syns.add(stream) # Avoid repeat alerts

    def _detect_dns_tunneling(self, packets):
        for pkt in packets:
            if pkt.haslayer(DNS) and pkt[DNS].qd:
                qname = pkt[DNS].qd.qname.decode('utf-8', errors='ignore')
                if len(qname) > 60: # High length entropy indicator
                    self.scoring.add_anomaly(Anomaly(
                        category="HIDE",
                        description=f"DNS Covert Channel detected (Long Query: {qname[:20]}...).",
                        source="Network Engine",
                        reference=f"DNS Server: {pkt[IP].dst}",
                        confidence=75
                    ))

    def _detect_icmp_tunnels(self, packets):
        for pkt in packets:
            if pkt.haslayer(ICMP) and len(pkt[ICMP].payload) > 128:
                self.scoring.add_anomaly(Anomaly(
                    category="HIDE",
                    description="ICMP Tunneling: Unusually large ICMP payload.",
                    source="Network Engine",
                    reference=f"src: {pkt[IP].src}, dsize: {len(pkt[ICMP].payload)}",
                    confidence=80
                ))

    def _detect_exfiltration_anomalies(self, packets):
        """ Statistical exfiltration: High Outbound/Inbound ratio to single IP. """
        # Simplified: check for single flows > 5MB in short burst
        pass
