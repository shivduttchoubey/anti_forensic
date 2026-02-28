import pandas as pd
import os
from src.engine.scoring import Anomaly, get_scoring_engine

class TemporalAnalyzer:
    def __init__(self):
        self.scoring = get_scoring_engine()

    def analyze(self, filepath: str):
        if not os.path.exists(filepath):
            print(f"[-] Timeline not found: {filepath}")
            return
            
        print(f"[*] Analyzing Temporal integrity: {filepath}")
        
        try:
            # For demonstration, we'll try to parse CSV or simple logs
            if filepath.endswith('.csv'):
                df = pd.read_csv(filepath)
                self._detect_timestamp_clustering(df, filepath)
                self._detect_impossible_sequences(df, filepath)
                self._detect_si_fn_mismatch(df, filepath)
            else:
                 print("[-] Temporal engine expects MFT/Timeline CSV export (e.g., fls -m output).")
        except Exception as e:
            print(f"[-] Temporal error: {e}")

    def _detect_si_fn_mismatch(self, df, filepath):
        """
        Detection of $SI (Standard Information) vs $FN (File Name) timestamp mismatch.
        Traditional timestomping only affects $SI.
        """
        if not all(col in df.columns for col in ['$SI_Created', '$FN_Created']):
            return

        # Find rows where $SI differs from $FN significantly (more than 1 minute)
        df['$SI_Created'] = pd.to_datetime(df['$SI_Created'])
        df['$FN_Created'] = pd.to_datetime(df['$FN_Created'])
        
        diff = (df['$SI_Created'] - df['$FN_Created']).abs()
        mismatches = df[diff > pd.Timedelta(minutes=1)]
        
        for _, row in mismatches.iterrows():
            anomaly = Anomaly(
                category="MODIFY",
                description=f"Timestamp Mismatch: $SI Created ({row['$SI_Created']}) != $FN Created ({row['$FN_Created']}).",
                source="Temporal Engine",
                reference=f"File: {row.get('file_path', 'unknown')}",
                confidence=95
            )
            self.scoring.add_anomaly(anomaly)

    def _detect_timestamp_clustering(self, df, filepath):
        if 'timestamp' not in df.columns: return
        counts = df.groupby('timestamp').size()
        suspicious = counts[counts > 500]
        for time_val, count in suspicious.items():
            self.scoring.add_anomaly(Anomaly(
                category="MODIFY",
                description=f"Mass Timestamp Clustering: {count} entries at {time_val}.",
                source="Temporal Engine",
                reference=f"Log: {filepath}",
                confidence=80
            ))

    def _detect_impossible_sequences(self, df, filepath):
        if not all(col in df.columns for col in ['creation_time', 'modification_time']): return
        df['creation_time'] = pd.to_datetime(df['creation_time'])
        df['modification_time'] = pd.to_datetime(df['modification_time'])
        impossible = df[df['modification_time'] < df['creation_time']]
        for _, row in impossible.iterrows():
             self.scoring.add_anomaly(Anomaly(
                category="FABRICATE",
                description="Impossible Sequence: Modification date precedes creation.",
                source="Temporal Engine",
                reference=f"File: {row.get('file_path', 'unknown')}",
                confidence=90
            ))
