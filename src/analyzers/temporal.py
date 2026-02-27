import pandas as pd
from src.engine.scoring import Anomaly, get_scoring_engine
import os

class TemporalAnalyzer:
    def __init__(self):
        self.scoring = get_scoring_engine()

    def analyze(self, filepath: str):
        if not os.path.exists(filepath):
            print(f"[-] Log/Timeline not found: {filepath}")
            return
            
        print(f"[*] Analyzing Temporal Data (Logs/Timeline): {filepath}")
        
        try:
            # We attempt to read as CSV. For a real engine, we'd need more
            # robust parsing for evtx or log formats using Plaso/log2timeline output
            if filepath.endswith('.csv'):
                df = pd.read_csv(filepath)
                self._detect_timestamp_clustering(df, filepath)
                self._detect_impossible_sequences(df, filepath)
            else:
                 print(f"[-] Temporal analyzer currently only supports CSV timeline format. Got: {filepath}")
        except Exception as e:
            print(f"[-] Error analyzing temporal data: {e}")

    def _detect_timestamp_clustering(self, df, filepath):
        """
        Detects bulk "timestomping" by looking for an unnaturally high number 
        of timestamp modifications within the same exact second.
        Assumes a 'timestamp' column and 'event_type' column.
        """
        # Simplified simulation
        if 'timestamp' not in df.columns:
            return
            
        # Group by exact second
        counts = df.groupby('timestamp').size()
        
        # If more than 1000 events happen in the exact same second, that's highly suspicious
        THRESHOLD = 1000
        suspicious_times = counts[counts > THRESHOLD]
        
        for time_val, count in suspicious_times.items():
            anomaly = Anomaly(
                category="MODIFY",
                description=f"Timestamp Clustering (Timestomping) Detected. {count} events occurred precisely at {time_val}.",
                source="temporal",
                reference=f"File: {filepath} at {time_val}",
                confidence=0.9
            )
            self.scoring.add_anomaly(anomaly)
            print(f"[!] Temporal Anomaly: {anomaly.description}")

    def _detect_impossible_sequences(self, df, filepath):
        """
        Detects effect before cause (e.g., file accessed before it was created).
        Assumes columns: 'file_path', 'creation_time', 'access_time'
        """
        if not all(col in df.columns for col in ['file_path', 'creation_time', 'access_time']):
            return

        try:
            df['creation_time'] = pd.to_datetime(df['creation_time'])
            df['access_time'] = pd.to_datetime(df['access_time'])
            
            # Find where accessed before created (impossible unless timestomped or clock skew)
            impossible = df[df['access_time'] < df['creation_time']]
            
            for _, row in impossible.iterrows():
                anomaly = Anomaly(
                    category="FABRICATE",
                    description=f"Impossible Event Sequence: '{row['file_path']}' accessed before creation.",
                    source="temporal",
                    reference=f"File: {filepath} Line: {row.name}",
                    confidence=0.85
                )
                self.scoring.add_anomaly(anomaly)
                print(f"[!] Temporal Anomaly: {anomaly.description}")
        except Exception as e:
            print(f"[-] Error in impossible sequence detection: {e}")
