"""
Mock Artifact Generator for Anti-Forensics Analysis Framework
==============================================================
Generates test artifacts containing deliberate anti-forensic patterns
to validate all four detection engines.
"""
import os
import pandas as pd
import numpy as np
from scapy.all import IP, TCP, UDP, DNS, DNSQR, ICMP, Ether, Raw, wrpcap


def generate_mock_pcap(filename="test_network.pcap"):
    print(f"[*] Generating Mock PCAP: {filename}")
    packets = []

    # 1. Normal TCP handshake for context
    p_syn = Ether()/IP(src="192.168.1.5", dst="8.8.8.8")/TCP(sport=54321, dport=80, flags="S", seq=100)
    p_synack = Ether()/IP(src="8.8.8.8", dst="192.168.1.5")/TCP(sport=80, dport=54321, flags="SA", seq=500, ack=101)
    p_ack = Ether()/IP(src="192.168.1.5", dst="8.8.8.8")/TCP(sport=54321, dport=80, flags="A", seq=101, ack=501)
    packets.extend([p_syn, p_synack, p_ack])

    # 2. Ghost Connection (PSH-ACK without SYN)
    ghost = Ether()/IP(src="10.5.0.99", dst="203.0.113.5")/TCP(sport=4444, dport=443, flags="PA", seq=9999)/Raw(load=b"EXFIL_DATA_BURST")
    packets.append(ghost)

    # 3. DNS Tunneling (long high-entropy query)
    encoded_data = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3QgdHVubmVs"  # base64 data
    dns_tunnel = Ether()/IP(src="192.168.1.5", dst="8.8.8.8")/UDP(sport=12345, dport=53)/DNS(
        rd=1, qd=DNSQR(qname=f"{encoded_data}.evil-c2-domain.com")
    )
    packets.append(dns_tunnel)

    # 4. ICMP Tunneling (oversized payload)
    icmp_tunnel = Ether()/IP(src="192.168.1.5", dst="203.0.113.1")/ICMP(type=8)/Raw(load=b"A" * 512)
    packets.append(icmp_tunnel)

    # 5. SSH on non-standard port
    ssh_mismatch = Ether()/IP(src="192.168.1.5", dst="203.0.113.2")/TCP(sport=11111, dport=80, flags="PA")/Raw(load=b"SSH-2.0-OpenSSH_8.4 evil_backdoor\r\n")
    packets.append(ssh_mismatch)

    # 6. Simulate exfiltration: many large packets to one external IP
    for i in range(30):
        exfil = Ether()/IP(src="192.168.1.5", dst="45.33.32.156")/TCP(sport=54000, dport=4443, flags="PA")/Raw(load=os.urandom(1400))
        packets.append(exfil)

    wrpcap(filename, packets)
    print(f"    Written {len(packets)} packets.")


def generate_mock_timeline(filename="test_timeline.csv"):
    print(f"[*] Generating Mock Timeline: {filename}")
    data = []

    # 1. Normal entries
    for i in range(20):
        data.append({
            'file_path': f'/home/user/document_{i}.docx',
            'timestamp':         '2026-02-20 09:15:33',
            '$SI_Created':       '2026-02-20 09:15:33',
            '$FN_Created':       '2026-02-20 09:15:33',
            'creation_time':     '2026-02-20 09:15:33',
            'modification_time': '2026-02-20 09:18:00',
            'access_time':       '2026-02-20 10:00:00',
        })

    # 2. $SI vs $FN Mismatch — Classic Timestomping
    data.append({
        'file_path':         '/windows/system32/evil.exe',
        'timestamp':         '2019-01-01 00:00:00',  # Backdated
        '$SI_Created':       '2019-01-01 00:00:00',  # Stomped $SI
        '$FN_Created':       '2026-02-25 14:32:00',  # Real $FN preserved
        'creation_time':     '2019-01-01 00:00:00',
        'modification_time': '2019-01-01 00:01:00',
        'access_time':       '2026-02-25 14:35:00',
    })

    # 3. Impossible Sequence (modified before created)
    data.append({
        'file_path':         '/tmp/payload.bin',
        'timestamp':         '2026-02-26 08:00:00',
        '$SI_Created':       '2026-02-26 08:00:00',
        '$FN_Created':       '2026-02-26 08:00:00',
        'creation_time':     '2026-02-26 08:00:00',
        'modification_time': '2026-02-24 06:00:00',  # Before creation!
        'access_time':       '2026-02-26 08:05:00',
    })

    # 4. Mass Timestamp Clustering (bulk timestomping)
    for i in range(120):
        data.append({
            'file_path':         f'/var/tmp/junk_{i}.log',
            'timestamp':         '2020-01-01 00:00:00',  # All identical
            '$SI_Created':       '2020-01-01 00:00:00',
            '$FN_Created':       '2020-01-01 00:00:00',
            'creation_time':     '2020-01-01 00:00:00',
            'modification_time': '2020-01-01 00:00:00',
            'access_time':       '2020-01-01 00:00:00',
        })

    # 5. Prefetch Paradox
    data.append({
        'file_path':           '/windows/prefetch/SDELETE.EXE-ABCDEF.pf',
        'timestamp':           '2026-02-27 22:00:00',
        '$SI_Created':         '2019-01-01 00:00:00',
        '$FN_Created':         '2019-01-01 00:00:00',
        'creation_time':       '2026-02-27 23:00:00',  # Created after execution
        'modification_time':   '2026-02-27 23:01:00',
        'access_time':         '2026-02-27 23:01:00',
        'prefetch_exec_time':  '2026-02-27 22:00:00',  # Executed before creation!
    })

    pd.DataFrame(data).to_csv(filename, index=False)
    print(f"    Written {len(data)} timeline records.")


def generate_mock_storage(filename="test_storage.img"):
    print(f"[*] Generating Mock Storage Image: {filename}")
    block = 4096
    with open(filename, 'wb') as f:
        # Block 0: Zero-fill wipe (0x00)
        f.write(b'\x00' * block)
        # Block 1: One-fill wipe (0xFF)
        f.write(b'\xff' * block)
        # Block 2: DoD 5220 alternating (0x55)
        f.write(b'\x55' * block)
        # Block 3: Gutmann pattern (repetitive)
        f.write(b'\x92\x49\x24' * (block // 3 + 1))
        # Block 4: High-entropy (VeraCrypt/hidden volume simulation)
        f.write(os.urandom(block))
        f.write(os.urandom(block))  # Block 5: continued high entropy
        f.write(os.urandom(block))  # Block 6: 3 consecutive → triggers detection
        # Block 7: Normal data with slack anomaly padding
        normal = b'Normal file system content here... ' * 50
        f.write(normal[:block])
    print(f"    Written mock image with 8 blocks.")


def generate_mock_directory(dirname="test_files"):
    print(f"[*] Generating Mock File Directory with Masquerade: {dirname}")
    os.makedirs(dirname, exist_ok=True)

    # 1. Normal PDF
    with open(os.path.join(dirname, "report.pdf"), 'wb') as f:
        f.write(b'%PDF-1.4 normal content')

    # 2. EXE disguised as .txt (masquerade)
    with open(os.path.join(dirname, "readme.txt"), 'wb') as f:
        f.write(b'MZ\x90\x00' + b'\x00' * 100)  # PE header in .txt file

    # 3. Normal text
    with open(os.path.join(dirname, "notes.txt"), 'w') as f:
        f.write("This is a real text file with no suspicious content.")

    # 4. High-entropy slack space file
    with open(os.path.join(dirname, "config.dat"), 'wb') as f:
        f.write(b'CFG:active=1\n')  # Small but...
        # The tail bytes are high-entropy (simulate data stashed in slack)
        f.write(os.urandom(200))
    print(f"    Created {dirname}/ with 4 files.")


def generate_mock_memory(filename="test_memory.vmem"):
    print(f"[*] Generating Mock Memory Dump: {filename}")
    with open(filename, 'wb') as f:
        # Simulate normal memory pages
        f.write(b'\x00' * 4096)
        # Simulate PE image of a suspicious tool in memory
        f.write(b'MZ' + b'\x00' * 58 + b'PE\x00\x00')
        f.write(b'timestomp_loaded_in_memory\x00')
        f.write(b'KeBugCheckEx_hook_detected\x00')
        f.write(b'wevtutil cl System\x00')  # Event log clear command
        f.write(b'\x00' * 1024)
        # Simulate IsDebuggerPresent check (anti-forensic)
        f.write(b'IsDebuggerPresent\x00NtSetDebugFilter\x00')
        f.write(b'\x00' * 512)
    print(f"    Written mock memory dump.")


if __name__ == "__main__":
    generate_mock_pcap()
    generate_mock_timeline()
    generate_mock_storage()
    generate_mock_directory()
    generate_mock_memory()
    print("\n[+] All mock artifacts generated successfully.")
    print("    Run: python main.py static -f test_network.pcap")
    print("    Run: python main.py static -f test_timeline.csv")
    print("    Run: python main.py static -f test_storage.img")
    print("    Run: python main.py static -f test_memory.vmem")
