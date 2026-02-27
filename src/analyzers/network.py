from scapy.all import rdpcap, IP, TCP, UDP, DNS
from src.engine.scoring import Anomaly, get_scoring_engine
import os

class NetworkAnalyzer:
    def __init__(self):
        self.scoring = get_scoring_engine()

    def analyze(self, filepath: str):
        if not os.path.exists(filepath):
            print(f"[-] PCAP not found: {filepath}")
            return
            
        print(f"[*] Analyzing PCAP: {filepath}")
        try:
            packets = rdpcap(filepath)
            self._detect_dns_tunneling(packets)
            self._detect_ghost_connections(packets)
        except Exception as e:
            print(f"[-] Error reading PCAP: {e}")

    def _detect_dns_tunneling(self, packets):
        """
        Detects potential DNS tunneling by looking for unusually long DNS query names.
        """
        DNS_LENGTH_THRESHOLD = 50 # Arbitrary threshold for long DNS requests
        
        for pkt in packets:
            if pkt.haslayer(DNS) and pkt.haslayer(IP) and pkt[DNS].qd:
                qname = pkt[DNS].qd.qname.decode('utf-8', errors='ignore')
                if len(qname) > DNS_LENGTH_THRESHOLD:
                    anomaly = Anomaly(
                        category="HIDE",
                        description=f"Potential DNS Tunneling detected. Unusually long query: {qname[:30]}...",
                        source="network",
                        reference=f"Packet src: {pkt[IP].src}, dst: {pkt[IP].dst}",
                        confidence=0.8
                    )
                    self.scoring.add_anomaly(anomaly)
                    print(f"[!] Network Anomaly: {anomaly.description}")

    def _detect_ghost_connections(self, packets):
        """
        Detects TCP connections that have data but no accompanying handshake in the capture,
        which might indicate wiped logs or stealth connections.
        (Simplified implementation: looking for PSH/ACK flags without seeing SYN for that stream)
        """
        active_streams = set()
        
        for pkt in packets:
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                 stream_id = f"{pkt[IP].src}:{pkt[TCP].sport}-{pkt[IP].dst}:{pkt[TCP].dport}"
                 
                 # SYN packet starts a trackable stream
                 if pkt[TCP].flags & 0x02: # SYN
                     active_streams.add(stream_id)
                     
                 # PSH or general ACK with data
                 elif pkt[TCP].flags & 0x08 and len(pkt[TCP].payload) > 0:
                     if stream_id not in active_streams:
                         # We see data being pushed but no SYN was captured
                         anomaly = Anomaly(
                            category="HIDE",
                            description=f"Ghost Connection detected (Data pushed without handshake captured).",
                            source="network",
                            reference=f"TCP Stream: {stream_id}",
                            confidence=0.6
                        )
                         self.scoring.add_anomaly(anomaly)
                         # Add to active so we don't alert on every single packet of this stream
                         active_streams.add(stream_id)
                         print(f"[!] Network Anomaly: {anomaly.description}")
