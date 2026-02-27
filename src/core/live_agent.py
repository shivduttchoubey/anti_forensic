import sys
import time
import os
import threading
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from src.engine.scoring import Anomaly, get_scoring_engine

class AntiForensicFSHandler(FileSystemEventHandler):
    def __init__(self, agent):
        self.agent = agent
        self.scoring = get_scoring_engine()

    def on_deleted(self, event):
        if event.is_directory: return
        # Simple heuristic: If it's a known log file or tool output being deleted
        # it might be an anti-forensic DESTROY action
        filepath = event.src_path.lower()
        if any(ext in filepath for ext in ['.log', '.json', '.evtx', '.pcap']):
             anomaly = Anomaly(
                 category="DESTROY",
                 description=f"Potential evidence destruction: Deleted file {event.src_path}",
                 source="live_fs",
                 reference=event.src_path,
                 confidence=0.8
             )
             self.scoring.add_anomaly(anomaly)
             self.agent.trigger_snapshot(f"File Deletion: {event.src_path}")

    def on_modified(self, event):
        if event.is_directory: return
        # Simplified: Lots of modifications rapidly might trigger an alert
        pass

class LiveAgent:
    def __init__(self, watch_dir="."):
         self.watch_dir = watch_dir
         self.observer = Observer()
         self.scoring = get_scoring_engine()
         self.running = False
         
    def start(self):
        print(f"[*] Starting Live Agent monitoring directory: {self.watch_dir}")
        self.running = True
        
        # 1. Start FS Monitoring
        event_handler = AntiForensicFSHandler(self)
        self.observer.schedule(event_handler, self.watch_dir, recursive=True)
        self.observer.start()
        
        # 2. Start Process/Network Monitoring Thread
        self.monitor_thread = threading.Thread(target=self._monitor_system, daemon=True)
        self.monitor_thread.start()
        
        try:
             while self.running:
                 time.sleep(1)
        except KeyboardInterrupt:
             self.stop()

    def stop(self):
        print("[*] Stopping Live Agent...")
        self.running = False
        self.observer.stop()
        self.observer.join()

    def _monitor_system(self):
         """ Monitors for anti-analysis tools or unexpected network connections """
         # List of known anti-forensic or analysis tools
         SUSPICIOUS_TOOLS = ['sdelete', 'wireshark', 'dumpcap', 'tcpdump', 'procmon']
         
         while self.running:
             try:
                 for proc in psutil.process_iter(['name', 'cmdline']):
                      name = proc.info.get('name', '').lower()
                      if any(tool in name for tool in SUSPICIOUS_TOOLS):
                          anomaly = Anomaly(
                             category="PREVENT",
                             description=f"Anti-forensic / analysis tool detected: {name}",
                             source="live_sys",
                             reference=f"PID: {proc.pid}",
                             confidence=0.9
                          )
                          # Avoid spamming
                          if not any(a.reference == anomaly.reference for a in self.scoring.anomalies):
                              self.scoring.add_anomaly(anomaly)
                              self.trigger_snapshot(f"Suspicious Process: {name}")
                              
                 # Sleep to prevent high CPU usage
                 time.sleep(5)
             except Exception as e:
                 print(f"[-] Live monitoring error: {e}")
                 time.sleep(5)

    def trigger_snapshot(self, reason: str):
         print(f"[!!!] TRIGGER ACTIVATED: {reason}")
         print("[*] Taking volatile memory snapshot (Simulated)...")
         # In reality, we'd call DumpIt, winpmem, or similar here.
         # subprocess.run(["winpmem.exe", "snapshot.raw"])
         
         anomaly = Anomaly(
             category="PREVENT",
             description=f"Automated memory snapshot triggered due to: {reason}",
             source="live_agent",
             reference="snapshot.raw",
             confidence=1.0
         )
         self.scoring.add_anomaly(anomaly)

if __name__ == "__main__":
    agent = LiveAgent()
    agent.start()
