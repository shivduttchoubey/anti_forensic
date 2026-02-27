import json
from dataclasses import dataclass, asdict
from typing import List, Dict

@dataclass
class Anomaly:
    category: str # DESTROY, MODIFY, HIDE, FABRICATE, PREVENT
    description: str
    source: str # e.g., 'network', 'storage', 'memory', 'temporal', 'live'
    reference: str # Sector, packet ID, volatile address, file path
    confidence: float # 0.0 to 1.0

class UnifiedScoringEngine:
    def __init__(self):
        self.anomalies: List[Anomaly] = []

    def get_valid_categories(self):
         return ["DESTROY", "MODIFY", "HIDE", "FABRICATE", "PREVENT"]

    def add_anomaly(self, anomaly: Anomaly):
        if anomaly.category not in self.get_valid_categories():
            raise ValueError(f"Invalid category: {anomaly.category}")
        self.anomalies.append(anomaly)

    def generate_report(self) -> Dict:
        report = {
            "DESTROY": [],
            "MODIFY": [],
            "HIDE": [],
            "FABRICATE": [],
            "PREVENT": [],
            "total_anomalies": len(self.anomalies)
        }
        for anomaly in self.anomalies:
            report[anomaly.category].append(asdict(anomaly))
        
        return report

# Initialize a global instance for live updates if needed, though passing it around is usually better.
_engine = UnifiedScoringEngine()
def get_scoring_engine():
    return _engine
