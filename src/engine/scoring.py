import json
import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict

@dataclass
class Anomaly:
    category: str # DESTROY, MODIFY, HIDE, FABRICATE, PREVENT
    description: str
    source: str # e.g., 'Temporal Engine', 'Storage Engine', etc.
    reference: str # Sector, packet ID, memory address, file path
    confidence: int # 0 to 100
    timestamp: str = "" # When detected

class UnifiedScoringEngine:
    def __init__(self):
        self.anomalies: List[Anomaly] = []

    def get_valid_categories(self):
         return ["DESTROY", "MODIFY", "HIDE", "FABRICATE", "PREVENT"]

    def add_anomaly(self, anomaly: Anomaly):
        if anomaly.category not in self.get_valid_categories():
            # Raise error for invalid base categories
            raise ValueError(f"Invalid anti-forensic category: {anomaly.category}")
        
        # Ensure confidence is within 0-100 as per arch
        anomaly.confidence = max(0, min(100, anomaly.confidence))
        
        if not anomaly.timestamp:
            anomaly.timestamp = datetime.datetime.now().isoformat()
            
        self.anomalies.append(anomaly)

    def generate_report(self) -> Dict:
        # Sort anomalies by confidence descending for investigator efficiency
        sorted_anomalies = sorted(self.anomalies, key=lambda x: x.confidence, reverse=True)
        
        report = {
            "DESTROY": [],
            "MODIFY": [],
            "HIDE": [],
            "FABRICATE": [],
            "PREVENT": [],
            "metadata": {
                "total_count": len(self.anomalies),
                "generation_time": datetime.datetime.now().isoformat()
            }
        }
        for anomaly in sorted_anomalies:
            report[anomaly.category].append(asdict(anomaly))
        
        return report

# Single global instance for easier access across engines
_engine = UnifiedScoringEngine()
def get_scoring_engine():
    return _engine
