import os
from src.analyzers.temporal import TemporalAnalyzer
from src.analyzers.storage import StorageAnalyzer
from src.analyzers.network import NetworkAnalyzer
from src.analyzers.main_memory import MainMemoryAnalyzer

class UniversalParser:
    def __init__(self):
        self.temporal = TemporalAnalyzer()
        self.storage = StorageAnalyzer()
        self.network = NetworkAnalyzer()
        self.memory = MainMemoryAnalyzer()

    def parse(self, filepath: str):
        ext = os.path.splitext(filepath)[1].lower()
        
        # Route based on extension
        if ext in ['.pcap', '.pcapng']:
            self.network.analyze(filepath)
        elif ext in ['.raw', '.mem', '.vmem', '.dmp']:
            self.memory.analyze(filepath)
        elif ext in ['.img', '.dd', '.e01', '.pcap']: # pcap might be routed twice if needed, but let's stick to disk
            self.storage.analyze(filepath)
        elif ext in ['.csv', '.log', '.txt']:
            self.temporal.analyze(filepath)
        else:
            # Fallback: try storage analysis on unknown blobs
            print(f"[*] Unknown extension {ext}, attempting generic storage scan.")
            self.storage.analyze(filepath)
