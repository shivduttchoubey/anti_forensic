"""
Engine 1: Temporal Integrity Analyzer
======================================
Detects anti-forensic manipulation of timestamps across NTFS, logs, and filesystem.

Key Detections:
  - $SI vs $FN timestamp mismatch (traditional timestomping)
  - Mass timestamp clustering (bulk timestomping with tools like Timestomp.exe)
  - Impossible/paradoxical event sequences (effect before cause)
  - Uniform/round timestamps indicating scripted modification
  - Prefetch execution vs. file creation time paradoxes
"""

import pandas as pd
import numpy as np
import os
from datetime import datetime, timedelta
from src.engine.scoring import Anomaly, get_scoring_engine


class TemporalAnalyzer:
    def __init__(self):
        self.scoring = get_scoring_engine()

    def analyze(self, filepath: str):
        if not os.path.exists(filepath):
            print(f"[-] Timeline not found: {filepath}")
            return

        print(f"[*] Temporal Integrity Analyzer running on: {filepath}")

        try:
            if filepath.endswith('.csv'):
                df = pd.read_csv(filepath)
                print(f"    Loaded {len(df)} records for temporal analysis.")
                self._detect_si_fn_mismatch(df, filepath)
                self._detect_timestamp_clustering(df, filepath)
                self._detect_impossible_sequences(df, filepath)
                self._detect_round_timestamps(df, filepath)
                self._detect_clock_drift(df, filepath)
                self._detect_prefetch_paradox(df, filepath)
            else:
                print("[-] Temporal engine expects a CSV timeline (e.g., from fls, log2timeline/plaso, or MFTECmd).")
        except Exception as e:
            print(f"[-] Temporal error: {e}")

    # ------------------------------------------------------------------
    # Detection 1: $SI vs $FN Timestamp Mismatch
    # ------------------------------------------------------------------
    def _detect_si_fn_mismatch(self, df: pd.DataFrame, filepath: str):
        """
        Traditional timestomping tools (Timestomp.exe, Metasploit) only update 
        $STANDARD_INFORMATION ($SI). The $FILE_NAME ($FN) attribute, written by 
        the NTFS kernel, is left with the original timestamp.
        A mismatch of >60 seconds is a strong indicator of timestomping.
        """
        required = ['$SI_Created', '$FN_Created']
        if not all(c in df.columns for c in required):
            return

        df['$SI_Created'] = pd.to_datetime(df['$SI_Created'], errors='coerce')
        df['$FN_Created'] = pd.to_datetime(df['$FN_Created'], errors='coerce')
        df.dropna(subset=required, inplace=True)

        diff = (df['$SI_Created'] - df['$FN_Created']).abs()
        # More than 1 minute difference is forensically significant
        mismatches = df[diff > pd.Timedelta(minutes=1)]

        print(f"    [SI/FN] Checked {len(df)} entries, found {len(mismatches)} mismatch(es).")
        for _, row in mismatches.iterrows():
            delta_str = str(diff[row.name])
            self.scoring.add_anomaly(Anomaly(
                category="MODIFY",
                description=(
                    f"$SI/$FN Mismatch (Timestomping): $SI_Created='{row['$SI_Created']}' "
                    f"vs $FN_Created='{row['$FN_Created']}' (delta={delta_str}). "
                    "Classic signature of Timestomp.exe or Metasploit timestomp module."
                ),
                source="Temporal Engine",
                reference=f"File: {row.get('file_path', 'unknown')}",
                confidence=95
            ))

    # ------------------------------------------------------------------
    # Detection 2: Mass Timestamp Clustering (Bulk Timestomping)
    # ------------------------------------------------------------------
    def _detect_timestamp_clustering(self, df: pd.DataFrame, filepath: str):
        """
        Bulk timestomping tools modify hundreds or thousands of files to the 
        same exact timestamp simultaneously. A clustering of >50 files at one 
        exact timestamp (to the second) is highly suspicious in a real filesystem.
        """
        if 'timestamp' not in df.columns:
            return

        counts = df.groupby('timestamp').size()
        # In genuine usage, >50 files sharing an identical timestamp per second is anomalous
        suspicious = counts[counts > 50]

        for time_val, count in suspicious.items():
            self.scoring.add_anomaly(Anomaly(
                category="MODIFY",
                description=(
                    f"Mass Timestamp Clustering: {count} file records share the exact timestamp "
                    f"'{time_val}'. Typical of bulk timestomping via scripted tools."
                ),
                source="Temporal Engine",
                reference=f"Timeline: {filepath}",
                confidence=85
            ))

    # ------------------------------------------------------------------
    # Detection 3: Impossible/Paradoxical Event Sequences
    # ------------------------------------------------------------------
    def _detect_impossible_sequences(self, df: pd.DataFrame, filepath: str):
        """
        Checks for causality violations in file metadata.
        - Modification time < Creation time (file was modified before it existed)
        - Access time < Creation time (file was read before it was written)
        These are physically impossible on a healthy filesystem and indicate fabrication.
        """
        if 'creation_time' not in df.columns:
            return

        df['creation_time'] = pd.to_datetime(df['creation_time'], errors='coerce')

        if 'modification_time' in df.columns:
            df['modification_time'] = pd.to_datetime(df['modification_time'], errors='coerce')
            impossible_mod = df[df['modification_time'] < df['creation_time']].dropna(subset=['modification_time'])
            for _, row in impossible_mod.iterrows():
                self.scoring.add_anomaly(Anomaly(
                    category="FABRICATE",
                    description=(
                        f"Impossible Sequence: Modification ({row['modification_time']}) "
                        f"precedes Creation ({row['creation_time']}). Indicates timestamp fabrication."
                    ),
                    source="Temporal Engine",
                    reference=f"File: {row.get('file_path', 'unknown')}",
                    confidence=92
                ))

        if 'access_time' in df.columns:
            df['access_time'] = pd.to_datetime(df['access_time'], errors='coerce')
            impossible_acc = df[df['access_time'] < df['creation_time']].dropna(subset=['access_time'])
            for _, row in impossible_acc.iterrows():
                self.scoring.add_anomaly(Anomaly(
                    category="FABRICATE",
                    description=(
                        f"Impossible Sequence: Access time ({row['access_time']}) "
                        f"precedes Creation ({row['creation_time']}). Cannot access a non-existent file."
                    ),
                    source="Temporal Engine",
                    reference=f"File: {row.get('file_path', 'unknown')}",
                    confidence=90
                ))

    # ------------------------------------------------------------------
    # Detection 4: Uniform / Round Timestamps
    # ------------------------------------------------------------------
    def _detect_round_timestamps(self, df: pd.DataFrame, filepath: str):
        """
        Scripted timestamp manipulation often produces 'round' timestamps 
        (e.g., 2019-01-01 00:00:00, or timestamps with zeroed sub-second fields).
        A high prevalence of midnight/epoch-level timestamps is suspicious.
        """
        if 'timestamp' not in df.columns:
            return

        try:
            ts = pd.to_datetime(df['timestamp'], errors='coerce').dropna()
            # Detect midnight timestamps (00:00:00)
            midnight_count = ts[(ts.dt.hour == 0) & (ts.dt.minute == 0) & (ts.dt.second == 0)].count()
            ratio = midnight_count / len(ts) if len(ts) > 0 else 0

            if ratio > 0.15 and midnight_count > 10:  # >15% of all timestamps at midnight
                self.scoring.add_anomaly(Anomaly(
                    category="MODIFY",
                    description=(
                        f"Uniform 'Round' Timestamps: {midnight_count} records ({ratio:.1%}) have "
                        "a 00:00:00 time component. Strongly suggests scripted bulk timestamp modification."
                    ),
                    source="Temporal Engine",
                    reference=f"Timeline: {filepath}",
                    confidence=75
                ))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Detection 5: System Clock Drift
    # ------------------------------------------------------------------
    def _detect_clock_drift(self, df: pd.DataFrame, filepath: str):
        """
        Detects abrupt jumps in a time-ordered event sequence that suggest 
        the system clock was manually altered. A legitimate system clock 
        drifts by < 1 second/day via NTP; sudden jumps of hours are malicious.
        """
        if 'timestamp' not in df.columns:
            return

        try:
            ts = pd.to_datetime(df['timestamp'], errors='coerce').dropna().sort_values()
            diffs = ts.diff().dropna()
            # Flag backward jumps (negative deltas mean clock was rolled back)
            backward_jumps = diffs[diffs < pd.Timedelta(0)]
            for idx, jump in backward_jumps.items():
                self.scoring.add_anomaly(Anomaly(
                    category="FABRICATE",
                    description=(
                        f"System Clock Rollback Detected: Event at index {idx} is "
                        f"{abs(jump)} BEFORE the preceding event. Indicates clock manipulation."
                    ),
                    source="Temporal Engine",
                    reference=f"Timeline: {filepath}, index: {idx}",
                    confidence=82
                ))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Detection 6: Prefetch Execution vs File Creation Paradox
    # ------------------------------------------------------------------
    def _detect_prefetch_paradox(self, df: pd.DataFrame, filepath: str):
        """
        Windows Prefetch records when a binary was executed. If a Prefetch file 
        shows execution of a tool BEFORE the tool's own file creation timestamp, 
        it proves the creation timestamp was backdated (timestomped) after execution.
        """
        if not all(c in df.columns for c in ['file_path', 'prefetch_exec_time', 'creation_time']):
            return

        df['prefetch_exec_time'] = pd.to_datetime(df['prefetch_exec_time'], errors='coerce')
        df['creation_time'] = pd.to_datetime(df['creation_time'], errors='coerce')
        df.dropna(subset=['prefetch_exec_time', 'creation_time'], inplace=True)

        paradox = df[df['prefetch_exec_time'] < df['creation_time']]
        for _, row in paradox.iterrows():
            self.scoring.add_anomaly(Anomaly(
                category="FABRICATE",
                description=(
                    f"Prefetch Paradox: '{row['file_path']}' was executed "
                    f"at {row['prefetch_exec_time']} but has a creation time of {row['creation_time']}. "
                    "The creation timestamp was backdated AFTER execution."
                ),
                source="Temporal Engine",
                reference=f"File: {row.get('file_path', 'unknown')}",
                confidence=97
            ))
