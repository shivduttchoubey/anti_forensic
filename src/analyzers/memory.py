import subprocess
import os
import json
from src.engine.scoring import Anomaly, get_scoring_engine

class MemoryAnalyzer:
    def __init__(self):
        self.scoring = get_scoring_engine()

    def analyze(self, filepath: str):
        if not os.path.exists(filepath):
            print(f"[-] Memory Dump not found: {filepath}")
            return
            
        print(f"[*] Analyzing Memory Dump: {filepath}")
        
        # Volatility 3 wrapper
        # For this hackathon/MVP, we'll run a few key plugins as a subprocess to keep it isolated
        
        # 1. Check for hidden processes
        self._run_volatility_plugin(filepath, "windows.pslist.PsList", "FABRICATE", "Checking process list")
        self._run_volatility_plugin(filepath, "windows.psscan.PsScan", "HIDE", "Scanning for hidden/unlinked processes")
        
        # 2. Check for maliciously modified memory regions (injection)
        self._run_volatility_plugin(filepath, "windows.malfind.Malfind", "MODIFY", "Checking for injected code")

    def _run_volatility_plugin(self, filepath: str, plugin: str, category: str, description: str):
        try:
            # Assumes volatility3 'vol' is in PATH or accessible as python script
            # e.g., vol -f <file> <plugin>
            # For JSON output: vol -r pretty -f <file> <plugin>
            
            cmd = ["vol", "-f", filepath, plugin]
            print(f"    Running: {' '.join(cmd)}")
            
            # Note: Running full memory forensics can be very slow.
            # Timeout set to 300s (5mins) just in case
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                 # In a full implementation, we'd parse the output or use JSON out.
                 # Here we'll just check if there's any output beyond headers
                 lines = result.stdout.strip().split('\n')
                 
                 # Very naive parsing for MVP
                 data_lines = [l for l in lines if not l.startswith('*') and not l.startswith('PID') and l.strip()]
                 
                 if len(data_lines) > 2: # Found some actual hits
                     anomaly = Anomaly(
                        category=category,
                        description=f"{description} returned {len(data_lines)} potential hits (Plugin: {plugin})",
                        source="memory",
                        reference=f"Memory dump: {filepath}, Volatility Trace",
                        confidence=0.75
                    )
                     self.scoring.add_anomaly(anomaly)
                     print(f"[!] Memory Anomaly: {anomaly.description}")
            else:
                 print(f"[-] Volatility error for {plugin}: {result.stderr}")
                 
        except FileNotFoundError:
             print("[-] Volatility3 'vol' executable not found in PATH.")
        except subprocess.TimeoutExpired:
             print(f"[-] Volatility plugin {plugin} timed out.")
        except Exception as e:
             print(f"[-] Error running memory analysis: {e}")
