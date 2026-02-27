import os
from src.analyzers.network import NetworkAnalyzer
from src.analyzers.storage import StorageAnalyzer
from src.analyzers.temporal import TemporalAnalyzer
from src.analyzers.memory import MemoryAnalyzer

class UniversalParser:
    def __init__(self):
        self.net_analyzer = NetworkAnalyzer()
        self.storage_analyzer = StorageAnalyzer()
        self.temporal_analyzer = TemporalAnalyzer()
        self.memory_analyzer = MemoryAnalyzer()

    def parse(self, filepath: str):
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Source not found: {filepath}")

        ext = os.path.splitext(filepath)[1].lower()

        if ext in ['.pcap', '.pcapng']:
            print(f"[+] Routing to Network Analyzer: {filepath}")
            self.net_analyzer.analyze(filepath)
        elif ext in ['.raw', '.dd', '.img', '.e01']:
            print(f"[+] Routing to Storage Analyzer: {filepath}")
            self.storage_analyzer.analyze(filepath)
        elif ext in ['.vmem', '.mem', '.dmp']:
            print(f"[+] Routing to Memory Analyzer: {filepath}")
            self.memory_analyzer.analyze(filepath)
        elif ext in ['.log', '.evt', '.evtx', '.csv', '.json']:
            print(f"[+] Routing to Temporal/Log Analyzer: {filepath}")
            self.temporal_analyzer.analyze(filepath)
        else:
            print(f"[-] Unknown format. Falling back to generic Temporal parsing: {filepath}")
            self.temporal_analyzer.analyze(filepath)

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        parser = UniversalParser()
        parser.parse(sys.argv[1])
