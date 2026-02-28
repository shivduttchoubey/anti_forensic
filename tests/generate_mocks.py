import os
import pandas as pd
import numpy as np
from scapy.all import IP, TCP, wrpcap, Ether

def generate_mock_pcap(filename="test_network.pcap"):
    print(f"[*] Generating Mock PCAP: {filename}")
    packets = []
    # 1. Normal Handshake
    p1 = Ether()/IP(src="192.168.1.5", dst="8.8.8.8")/TCP(sport=1234, dport=80, flags="S", seq=100)
    p2 = Ether()/IP(src="8.8.8.8", dst="192.168.1.5")/TCP(sport=80, dport=1234, flags="SA", seq=500, ack=101)
    packets.extend([p1, p2])
    
    # 2. Ghost Connection (PSH-ACK without SYN)
    ghost = Ether()/IP(src="10.0.0.5", dst="1.1.1.1")/TCP(sport=4444, dport=443, flags="PA", seq=1000)
    packets.append(ghost)
    
    wrpcap(filename, packets)

def generate_mock_timeline(filename="test_timeline.csv"):
    print(f"[*] Generating Mock Timeline: {filename}")
    data = []
    # 1. Normal entries
    for i in range(10):
        data.append({
            'file_path': f'/home/user/doc_{i}.txt',
            'timestamp': '2026-02-28 10:00:00',
            '$SI_Created': '2026-02-28 10:00:00',
            '$FN_Created': '2026-02-28 10:00:00',
            'creation_time': '2026-02-28 10:00:00',
            'modification_time': '2026-02-28 10:05:00'
        })
    
    # 2. SI vs FN Mismatch (Timestomping)
    data.append({
        'file_path': '/windows/system32/cmd.exe',
        'timestamp': '2020-01-01 00:00:00',
        '$SI_Created': '2020-01-01 00:00:00', # Stomped
        '$FN_Created': '2024-05-20 12:30:00', # Real
        'creation_time': '2020-01-01 00:00:00',
        'modification_time': '2020-01-01 00:01:00'
    })
    
    # 3. Mass Clustering
    for i in range(600):
        data.append({
            'file_path': f'/tmp/junk_{i}.tmp',
            'timestamp': '2026-02-28 00:00:00', # Cluster point
            '$SI_Created': '2026-02-28 00:00:00',
            '$FN_Created': '2026-02-28 00:00:00'
        })
        
    pd.DataFrame(data).to_csv(filename, index=False)

def generate_mock_storage(filename="test_storage.img"):
    print(f"[*] Generating Mock Storage Image: {filename}")
    block_size = 4096
    with open(filename, 'wb') as f:
        # 1. All Zeros (Wiped)
        f.write(b'\x00' * block_size)
        # 2. All Ones (Wiped)
        f.write(b'\xFF' * block_size)
        # 3. High Entropy (Hidden Volume simulation)
        f.write(os.urandom(block_size))
        # 4. Patterned Wipe (0xA5 repetitive)
        f.write(b'\xA5\x5A' * (block_size // 2))
        # 5. Fill rest with junk
        f.write(b'Normal partition data placeholder' * 10)

def generate_mock_memory(filename="test_memory.vmem"):
    print(f"[*] Generating Mock memory: {filename}")
    with open(filename, 'wb') as f:
        f.write(b'System RAM header\n')
        f.write(b'Process: svchost.exe\n')
        # Collection Prevention Trigger
        f.write(b'TRIGGER_ACTION: CRASH_ON_FORENSIC_TOOL_DETECTED_BSOD_0x0000003B\n')
        f.write(b'\x00' * 1024)

if __name__ == "__main__":
    generate_mock_pcap()
    generate_mock_timeline()
    generate_mock_storage()
    generate_mock_memory()
    print("[+] All mock artifacts generated.")
