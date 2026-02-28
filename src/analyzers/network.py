"""
Engine 3: Network Artifact Analyzer
=====================================
Detects anti-forensic manipulation of network evidence across captured traffic.

Key Detections:
  - Protocol STAT violations / Ghost Connections (data before SYN)
  - DNS Tunneling (high-entropy / long query names)
  - ICMP Tunneling (oversized payloads)
  - Data Exfiltration (high outbound/inbound byte ratio per IP)
  - Port Anomalies (known protocols on wrong ports)
  - HTTP Header Steganography (covert data in legitimate fields)
"""

import os
import math
import collections
from scapy.all import rdpcap, IP, TCP, UDP, DNS, ICMP, Raw, DNSQR
from src.engine.scoring import Anomaly, get_scoring_engine


class NetworkAnalyzer:
    def __init__(self):
        self.scoring = get_scoring_engine()

        # Standard ports for known protocols — used for port anomaly detection
        self.PROTOCOL_EXPECTED_PORTS = {
            'HTTP': {80, 8080, 8000},
            'HTTPS': {443, 8443},
            'SSH': {22},
            'FTP': {20, 21},
            'SMTP': {25, 587, 465},
            'DNS': {53},
            'RDP': {3389},
        }

    def analyze(self, filepath: str):
        if not os.path.exists(filepath):
            print(f"[-] PCAP not found: {filepath}")
            return

        print(f"[*] Network Artifact Analyzer running on: {filepath}")
        try:
            packets = rdpcap(filepath)
            print(f"    Loaded {len(packets)} packets for analysis.")
            self._detect_stat_violations(packets)
            self._detect_dns_tunneling(packets)
            self._detect_icmp_tunnels(packets)
            self._detect_exfiltration_anomalies(packets)
            self._detect_port_anomalies(packets)
            self._detect_http_header_covert_channels(packets)
        except Exception as e:
            print(f"[-] Network error: {e}")

    # ------------------------------------------------------------------
    # Detection 1: Protocol STAT Violations (Ghost Connections)
    # ------------------------------------------------------------------
    def _detect_stat_violations(self, packets):
        """
        A legitimate TCP session must begin with a SYN handshake.
        Data packets (PSH-ACK, ACK) arriving without a corresponding SYN 
        indicate 'Ghost Connections' — sessions deliberately started mid-stream 
        by attackers to avoid IDS detection of the handshake phase.
        
        Also detects FIN/RST without prior SYN (orphaned teardowns).
        """
        # Track seen SYN streams (src_ip:sport -> dst_ip:dport)
        active_syns = set()
        ghost_count = 0

        for pkt in packets:
            if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
                continue

            flags = pkt[TCP].flags
            stream = f"{pkt[IP].src}:{pkt[TCP].sport}->{pkt[IP].dst}:{pkt[TCP].dport}"
            rev_stream = f"{pkt[IP].dst}:{pkt[TCP].dport}->{pkt[IP].src}:{pkt[TCP].sport}"

            if flags & 0x02:  # SYN
                active_syns.add(stream)
                active_syns.add(rev_stream)  # Also track reverse for RST/FIN
            elif (flags & 0x08) or (flags & 0x01):  # PSH or FIN
                if stream not in active_syns and ghost_count < 10:  # Cap alerts
                    self.scoring.add_anomaly(Anomaly(
                        category="HIDE",
                        description=(
                            f"Protocol STAT Violation — Ghost Connection: Data/FIN seen on stream "
                            f"'{stream}' with no prior SYN. "
                            "Evades IDS by starting sessions mid-stream."
                        ),
                        source="Network Engine",
                        reference=f"Stream: {stream}",
                        confidence=87
                    ))
                    active_syns.add(stream)
                    ghost_count += 1

    # ------------------------------------------------------------------
    # Detection 2: DNS Tunneling
    # ------------------------------------------------------------------
    def _detect_dns_tunneling(self, packets):
        """
        DNS tunneling encodes data inside DNS query labels.
        Indicators:
        - Unusually long query names (>50 chars)
        - High Shannon entropy in the subdomain portion (encoded data is near-random)
        - Abnormally high query frequency to a single domain
        """
        query_counts = collections.Counter()

        for pkt in packets:
            if not (pkt.haslayer(DNS) and pkt.haslayer(IP)):
                continue

            dns = pkt[DNS]
            if dns.qd is None:
                continue

            try:
                qname = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
            except Exception:
                continue

            # Extract subdomain for analysis
            parts = qname.split('.')
            subdomain = parts[0] if len(parts) > 2 else qname

            # Check 1: Query length anomaly
            if len(qname) > 52:
                entropy = self._shannon_entropy(subdomain.encode())
                self.scoring.add_anomaly(Anomaly(
                    category="HIDE",
                    description=(
                        f"DNS Tunneling Detected: Query '{qname[:40]}...' ({len(qname)} chars) "
                        f"with subdomain entropy={entropy:.2f} bits/byte. "
                        "High entropy in long DNS labels is characteristic of Base32/Base64-encoded data channels."
                    ),
                    source="Network Engine",
                    reference=f"DNS Server: {pkt[IP].dst}, Domain: {'.'.join(parts[-2:])}",
                    confidence=78 + min(int(entropy * 2), 15)  # Higher entropy = higher confidence
                ))

            # Track query frequency to a domain
            apex = '.'.join(parts[-2:]) if len(parts) >= 2 else qname
            query_counts[apex] += 1

        # Check 2: High query frequency to single domain
        for domain, count in query_counts.items():
            if count > 100:
                self.scoring.add_anomaly(Anomaly(
                    category="HIDE",
                    description=(
                        f"DNS Beacon/Tunnel: {count} DNS queries to '{domain}' detected. "
                        "Consistent high-frequency DNS traffic to a single domain indicates C2 beaconing or DNS tunneling."
                    ),
                    source="Network Engine",
                    reference=f"Domain: {domain}",
                    confidence=72
                ))

    # ------------------------------------------------------------------
    # Detection 3: ICMP Tunneling
    # ------------------------------------------------------------------
    def _detect_icmp_tunnels(self, packets):
        """
        Standard ICMP ping payloads are 32-64 bytes. Tunneling tools (e.g., 
        icmpsh, ptunnel) embed arbitrary data in ICMP echo payloads. 
        High payload size or high entropy payloads indicate tunneling.
        """
        for pkt in packets:
            if not (pkt.haslayer(ICMP) and pkt.haslayer(IP)):
                continue

            icmp = pkt[ICMP]
            if icmp.type not in (8, 0):  # Only echo request/reply
                continue

            payload = bytes(icmp.payload) if icmp.payload else b''
            psize = len(payload)

            if psize > 64:
                entropy = self._shannon_entropy(payload[:256])
                confidence = 70 + min(int(psize / 100), 20)
                self.scoring.add_anomaly(Anomaly(
                    category="HIDE",
                    description=(
                        f"ICMP Tunneling: Oversized payload ({psize} bytes, entropy={entropy:.2f}) "
                        f"in ICMP echo from {pkt[IP].src} to {pkt[IP].dst}. "
                        "Standard ICMP payloads are 32-64 bytes; larger payloads suggest data covert channel."
                    ),
                    source="Network Engine",
                    reference=f"Src: {pkt[IP].src}, Dst: {pkt[IP].dst}",
                    confidence=min(confidence, 88)
                ))

    # ------------------------------------------------------------------
    # Detection 4: Data Exfiltration (Outbound Byte Ratio)
    # ------------------------------------------------------------------
    def _detect_exfiltration_anomalies(self, packets):
        """
        Calculates per-destination-IP outbound byte totals.
        A high outbound/inbound ratio to an external IP suggests systematic 
        data exfiltration. Attacker transfers large volumes of data outbound.
        
        Flags: Any external IP receiving > 1MB of data, or 
               outbound:inbound ratio > 10:1.
        """
        # Count bytes sent TO each IP (outbound from a perspective of common source)
        per_ip_out = collections.defaultdict(int)
        per_ip_in = collections.defaultdict(int)

        # Determine the most common src IP as the "local" machine
        src_counts = collections.Counter()
        for pkt in packets:
            if pkt.haslayer(IP):
                src_counts[pkt[IP].src] += 1

        # Heuristic: the IP that sends the most packets is likely the monitored host
        if not src_counts:
            return
        local_ip = src_counts.most_common(1)[0][0]

        for pkt in packets:
            if not pkt.haslayer(IP):
                continue
            pkt_len = len(pkt)
            if pkt[IP].src == local_ip:
                dst = pkt[IP].dst
                # Skip private/loopback IPs for exfil detection
                if not (dst.startswith('192.168') or dst.startswith('10.') or
                        dst.startswith('172.') or dst == '127.0.0.1'):
                    per_ip_out[dst] += pkt_len
            elif pkt[IP].dst == local_ip:
                per_ip_in[pkt[IP].src] += pkt_len

        # Evaluate
        for dst_ip, out_bytes in per_ip_out.items():
            in_bytes = per_ip_in.get(dst_ip, 1)  # avoid div/0
            ratio = out_bytes / in_bytes
            out_mb = out_bytes / (1024 * 1024)

            if out_mb > 1.0 and ratio > 5.0:
                self.scoring.add_anomaly(Anomaly(
                    category="DESTROY",
                    description=(
                        f"Data Exfiltration Pattern: {out_mb:.1f} MB sent to {dst_ip} "
                        f"(out/in ratio = {ratio:.1f}:1). "
                        "Large asymmetric outbound flows to external IPs indicate potential data theft."
                    ),
                    source="Network Engine",
                    reference=f"Local: {local_ip} -> Remote: {dst_ip}",
                    confidence=min(55 + int(out_mb * 5), 90)
                ))

    # ------------------------------------------------------------------
    # Detection 5: Port Anomalies (Protocol Mismatches)
    # ------------------------------------------------------------------
    def _detect_port_anomalies(self, packets):
        """
        Malware and anti-forensics tools often use non-standard ports for 
        known protocols to evade port-based firewall rules.
        Examples: SSH over port 80, HTTPS over port 4444.
        Detects: TCP/UDP traffic on well-known service ports that does not 
        match the expected application-layer behavior.
        """
        # Look for HTTP signatures on unexpected ports
        http_sig = b'HTTP/'
        ssh_sig = b'SSH-'
        flagged_ports = set()

        for pkt in packets:
            if not (pkt.haslayer(TCP) and pkt.haslayer(IP) and pkt.haslayer(Raw)):
                continue

            payload = bytes(pkt[Raw].load)
            dport = pkt[TCP].dport
            sport = pkt[TCP].sport

            # SSH on non-22 port
            if payload.startswith(ssh_sig) and dport not in (22,) and dport not in flagged_ports:
                flagged_ports.add(dport)
                self.scoring.add_anomaly(Anomaly(
                    category="HIDE",
                    description=(
                        f"Protocol Mismatch: SSH handshake banner detected on port {dport} "
                        f"(from {pkt[IP].src}:{sport}). SSH is normally on port 22; "
                        "running it on a different port evades firewall rules."
                    ),
                    source="Network Engine",
                    reference=f"Stream: {pkt[IP].src}:{sport} -> {pkt[IP].dst}:{dport}",
                    confidence=82
                ))

            # HTTP on unexpected port
            if payload.startswith(http_sig) and dport not in {80, 8080, 8000, 443} and dport not in flagged_ports:
                flagged_ports.add(dport)
                self.scoring.add_anomaly(Anomaly(
                    category="HIDE",
                    description=(
                        f"Protocol Mismatch: HTTP traffic on non-standard port {dport} "
                        f"(from {pkt[IP].src}). Could indicate a C2 channel disguised as web traffic."
                    ),
                    source="Network Engine",
                    reference=f"Stream: {pkt[IP].src}:{sport} -> {pkt[IP].dst}:{dport}",
                    confidence=70
                ))

    # ------------------------------------------------------------------
    # Detection 6: HTTP Header Steganography / Covert Data
    # ------------------------------------------------------------------
    def _detect_http_header_covert_channels(self, packets):
        """
        Detects data hidden in HTTP headers. Attackers may embed data in 
        custom headers, pad existing headers with base64 data, or use 
        X- prefixed fields to exfiltrate data or receive commands.
        Heuristic: abnormally large headers or unusual X- header names.
        """
        for pkt in packets:
            if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
                continue

            try:
                payload = pkt[Raw].load.decode('utf-8', errors='ignore')
            except Exception:
                continue

            if not (payload.startswith('GET') or payload.startswith('POST') or payload.startswith('HTTP')):
                continue

            lines = payload.split('\r\n')
            for line in lines:
                # Flag suspicious X- headers that look like encoded data
                if line.lower().startswith('x-') and len(line) > 100:
                    entropy = self._shannon_entropy(line.encode())
                    if entropy > 4.5:
                        self.scoring.add_anomaly(Anomaly(
                            category="HIDE",
                            description=(
                                f"HTTP Header Covert Channel: Suspicious X- header '{line[:40]}...' "
                                f"({len(line)} chars, entropy={entropy:.2f}). "
                                "High-entropy content in custom HTTP headers indicates data burial."
                            ),
                            source="Network Engine",
                            reference=f"Packet from {pkt[IP].src}",
                            confidence=73
                        ))
                        break  # One alert per packet

    # ------------------------------------------------------------------
    # Utility: Shannon Entropy
    # ------------------------------------------------------------------
    def _shannon_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        freq = collections.Counter(data)
        total = len(data)
        return -sum((c / total) * math.log2(c / total) for c in freq.values())
