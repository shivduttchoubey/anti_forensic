"""
Engine 4: Main Memory Analysis Engine
========================================
Analyzes RAM dumps for anti-forensic evidence using Volatility3 and
independent heuristic scanning.

Key Detections:
  - Collection Prevention: Anti-forensic crash triggers / BSOD hooks
  - DKOM (Direct Kernel Object Manipulation): Hiding processes by unlinking EPROCESS
  - PSList vs PSScan discrepancy: Processes visible in scan but not in list (rootkit)
  - Code Injection / Process Hollowing: Memory regions marked RWX with PE signatures
  - Kernel Hooks: Callbacks and SSDT modifications
  - Suspicious String Indicators: Anti-forensics tool signatures in memory strings
"""

import subprocess
import os
import sys
import json
import re
from src.engine.scoring import Anomaly, get_scoring_engine

# Known anti-forensic and suspicious tool strings to detect in memory
ANTIFORENSIC_SIGNATURES = [
    (b'Timestomp',          'Timestomping tool'),
    (b'WEVTUTIL',           'Windows Event Log Clearing utility'),
    (b'wevtutil cl',        'Active Event Log Clear command'),
    (b'cipher /w',          'Windows data overwrite utility'),
    (b'sdelete',            'Sysinternals SDelete secure-erase tool'),
    (b'steghide',           'Steganography tool (steghide)'),
    (b'veracrypt',          'VeraCrypt encrypted container utility'),
    (b'TrueCrypt',          'TrueCrypt encrypted container utility'),
    (b'DetachThread',       'Anti-debug / anti-forensic API call'),
    (b'IsDebuggerPresent',  'Anti-debug check — common in evasive malware'),
    (b'NtSetDebugFilter',   'Anti-debug NT call'),
    (b'ZwQuerySystemInfo',  'System enumeration for rootkit detection evasion'),
    (b'BSOD_TRIGGERED',     'Deliberate crash trigger'),
    (b'KeBugCheck',         'Kernel crash trigger (KeBugCheck)'),
    (b'ObDeregisterCallback','Kernel callback deregistration — rootkit technique'),
    (b'NtUnloadDriver',     'Driver unloading — used to hide rootkit drivers'),
]


class MainMemoryAnalyzer:
    def __init__(self):
        self.scoring = get_scoring_engine()
        self._vol3_available = self._check_volatility()

    def _check_volatility(self) -> bool:
        """Check if Volatility3 is available on this system."""
        try:
            result = subprocess.run(
                [sys.executable, '-m', 'volatility3', '--version'],
                capture_output=True, timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False

    def analyze(self, filepath: str):
        if not os.path.exists(filepath):
            print(f"[-] Memory dump not found: {filepath}")
            return

        print(f"[*] Main Memory Engine running on: {filepath}")

        # 1. Fast heuristic string scan (works on any raw memory file)
        self._scan_memory_strings(filepath)

        # 2. Collection Prevention / Anti-forensic trigger scan
        self._check_collection_prevention(filepath)

        # 3. Volatility3 deep analysis (if available)
        if self._vol3_available:
            print("    [Vol3] Volatility3 available — running deep analysis.")
            self._run_dkom_detection(filepath)
            self._run_pslist_vs_psscan(filepath)
            self._run_malfind(filepath)
        else:
            print("    [Vol3] Volatility3 not installed — using heuristic scan only.")
            self._heuristic_process_scan(filepath)

    # ------------------------------------------------------------------
    # Detection 1: Anti-Forensic Tool String Signatures in Memory
    # ------------------------------------------------------------------
    def _scan_memory_strings(self, filepath: str):
        """
        Scans the RAM dump for known anti-forensic tool and API strings.
        Even if a process was terminated, its memory may retain string artifacts.
        This technique is analogous to bulk string extraction (like 'strings -a').
        """
        print("    [Memory] Scanning memory strings for anti-forensic signatures...")
        found_sigs = []

        try:
            chunk_size = 4 * 1024 * 1024  # 4MB chunks to avoid loading entire dump
            with open(filepath, 'rb') as f:
                chunk_idx = 0
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    chunk_lower = chunk.lower()
                    for sig, desc in ANTIFORENSIC_SIGNATURES:
                        if sig.lower() in chunk_lower:
                            offset = chunk.lower().find(sig.lower())
                            global_offset = chunk_idx * chunk_size + offset
                            key = sig.decode('utf-8', errors='ignore')
                            if key not in found_sigs:  # Deduplicate
                                found_sigs.append(key)
                                self.scoring.add_anomaly(Anomaly(
                                    category="PREVENT",
                                    description=(
                                        f"Anti-Forensic Signature in Memory: '{key}' ({desc}) "
                                        f"found at offset 0x{global_offset:08X}. "
                                        "Tool artifacts remain in RAM even after process termination."
                                    ),
                                    source="Main Memory Engine",
                                    reference=f"Dump: {filepath}, Offset: 0x{global_offset:08X}",
                                    confidence=82
                                ))
                    chunk_idx += 1
                    if chunk_idx > 256:  # Cap at 1GB scan
                        break
        except Exception as e:
            print(f"    [-] String scan error: {e}")

        print(f"    [Memory] Found {len(found_sigs)} anti-forensic signature(s).")

    # ------------------------------------------------------------------
    # Detection 2: Collection Prevention (BSOD/Crash Triggers)
    # ------------------------------------------------------------------
    def _check_collection_prevention(self, filepath: str):
        """
        Some rootkits implement 'dead man's switch' — if a forensic tool 
        is attached (e.g., WinPmem, DumpIt) the kernel driver triggers a BSOD 
        via KeBugCheck or triggers process termination.
        Detects: KeBugCheck call patterns, crash-on-attach hooks.
        """
        crash_indicators = [
            b'KeBugCheckEx',
            b'KeBugCheck2',
            b'\x6a\x00\xff\x15',  # CALL [KeBugCheck] x86 opcode pattern
            b'DbgBreakPoint',
            b'RtlAssert',
            b'FORENSIC_DETECTION_CRASH',
        ]

        try:
            with open(filepath, 'rb') as f:
                # Scan first 20MB (kernel structures are typically in low memory)
                data = f.read(20 * 1024 * 1024)

            for indicator in crash_indicators:
                if indicator in data:
                    offset = data.find(indicator)
                    label = indicator.decode('utf-8', errors='replace')
                    self.scoring.add_anomaly(Anomaly(
                        category="PREVENT",
                        description=(
                            f"Collection Prevention Indicator: '{label}' found at offset 0x{offset:08X}. "
                            "KeBugCheck or DbgBreakPoint in unexpected memory regions indicates "
                            "anti-forensic 'dead man's switch' or anti-debugging protection."
                        ),
                        source="Main Memory Engine",
                        reference=f"Dump: {filepath}, Offset: 0x{offset:08X}",
                        confidence=80
                    ))
                    break  # One alert for the category
        except Exception as e:
            print(f"    [-] Collection prevention check error: {e}")

    # ------------------------------------------------------------------
    # Detection 3 (Vol3): DKOM — PSList vs PSScan Discrepancy
    # ------------------------------------------------------------------
    def _run_pslist_vs_psscan(self, filepath: str):
        """
        DKOM rootkits hide processes by unlinking the target EPROCESS from the 
        doubly-linked list (PsActiveProcessHead). 
        PSList traverses the linked list → misses hidden processes.
        PSScan does pool tag scanning → finds ALL EPROCESS blocks including unlinked ones.
        
        Any process in PSScan but NOT in PSList = DKOM-hidden process.
        """
        print("    [Vol3] Running PSList vs PSScan correlation (DKOM detection)...")
        try:
            pslist_pids = self._run_vol3_plugin(filepath, "windows.pslist.PsList")
            psscan_pids = self._run_vol3_plugin(filepath, "windows.psscan.PsScan")

            pslist_set = set(p.get('PID') for p in pslist_pids)
            psscan_set = set(p.get('PID') for p in psscan_pids)

            hidden = psscan_set - pslist_set
            for pid in hidden:
                proc_info = next((p for p in psscan_pids if p.get('PID') == pid), {})
                self.scoring.add_anomaly(Anomaly(
                    category="HIDE",
                    description=(
                        f"DKOM-Hidden Process Detected: PID {pid} "
                        f"('{proc_info.get('ImageFileName', 'unknown')}') "
                        "found by PSScan pool-tag method but ABSENT from PSList traversal. "
                        "Classic EPROCESS-unlinking rootkit technique."
                    ),
                    source="Main Memory Engine",
                    reference=f"Dump: {filepath}, PID: {pid}",
                    confidence=95
                ))

        except Exception as e:
            print(f"    [-] DKOM detection error: {e}")

    # ------------------------------------------------------------------
    # Detection 4 (Vol3): Code Injection / Process Hollowing (Malfind)
    # ------------------------------------------------------------------
    def _run_malfind(self, filepath: str):
        """
        Malfind identifies memory regions that are:
        - Marked as executable (PAGE_EXECUTE_*)
        - Contain PE header signatures (MZ / 0x4D5A)
        - Not backed by a file on disk
        
        This is the definitive signature of:
        - Process Injection (DLL injection, reflective loading)
        - Process Hollowing (legit process replaced with malware)
        - Shellcode regions
        """
        print("    [Vol3] Running Malfind (injection/hollowing detection)...")
        try:
            results = self._run_vol3_plugin(filepath, "windows.malfind.Malfind")
            for finding in results:
                pid = finding.get('PID', 'unknown')
                proc = finding.get('Process', 'unknown')
                addr = finding.get('Start VPN', 'unknown')
                protection = finding.get('VadTag', 'unknown')
                self.scoring.add_anomaly(Anomaly(
                    category="MODIFY",
                    description=(
                        f"Code Injection/Hollowing: PID {pid} ('{proc}') has suspicious "
                        f"executable memory at 0x{addr:016X} with no file backing. "
                        f"Protection: {protection}. Indicates process injection or hollowing."
                    ),
                    source="Main Memory Engine",
                    reference=f"Dump: {filepath}, PID: {pid}, Addr: 0x{addr:016X}",
                    confidence=90
                ))
        except Exception as e:
            print(f"    [-] Malfind error: {e}")

    # ------------------------------------------------------------------
    # Detection 5 (Vol3): Kernel Callbacks and DKOM
    # ------------------------------------------------------------------
    def _run_dkom_detection(self, filepath: str):
        """
        Detects modifications to kernel callback tables. Rootkits register 
        (or deregister) PsSetCreateProcessNotifyRoutine callbacks to intercept 
        or block forensic tools from loading.
        """
        print("    [Vol3] Running Kernel Callback analysis...")
        try:
            results = self._run_vol3_plugin(filepath, "windows.callbacks.Callbacks")
            suspicious_owners = {'unknown', '', 'N/A'}
            for cb in results:
                owner = cb.get('Module', 'unknown')
                if owner.lower() in suspicious_owners:
                    cb_type = cb.get('Type', 'unknown')
                    addr = cb.get('Callback', 'unknown')
                    self.scoring.add_anomaly(Anomaly(
                        category="PREVENT",
                        description=(
                            f"Suspicious Kernel Callback: Type='{cb_type}' at {addr} "
                            f"owned by unknown/unsigned module. "
                            "Rootkits use kernel callbacks to intercept forensic tool execution."
                        ),
                        source="Main Memory Engine",
                        reference=f"Dump: {filepath}, Callback: {addr}",
                        confidence=85
                    ))
        except Exception as e:
            print(f"    [-] Callback analysis error: {e}")

    # ------------------------------------------------------------------
    # Fallback: Heuristic Process Scan (No Volatility)
    # ------------------------------------------------------------------
    def _heuristic_process_scan(self, filepath: str):
        """
        Without Volatility, search for known process name strings and 
        Windows PE structures that suggest injected or hidden processes.
        Looks for MZ headers (0x4D5A) at page boundaries in the dump.
        """
        print("    [Memory] Heuristic PE header scan (no Volatility)...")
        try:
            page_size = 4096
            mz_header = b'MZ'
            suspicious_procs = [
                b'sdelete', b'timestomp', b'nmap', b'psexec',
                b'mimikatz', b'wipe', b'eraser', b'bleachbit'
            ]
            pe_count = 0

            with open(filepath, 'rb') as f:
                offset = 0
                while pe_count < 50:
                    data = f.read(page_size)
                    if not data:
                        break

                    if data[:2] == mz_header:
                        pe_count += 1
                        # Check for suspicious names near the PE header
                        context = data[:256].lower()
                        for sp in suspicious_procs:
                            if sp in context:
                                self.scoring.add_anomaly(Anomaly(
                                    category="HIDE",
                                    description=(
                                        f"Suspicious Executable in Memory: PE header at "
                                        f"offset 0x{offset:08X} contains reference to '{sp.decode()}'. "
                                        "Could indicate a hidden or injected process."
                                    ),
                                    source="Main Memory Engine",
                                    reference=f"Dump: {filepath}, Offset: 0x{offset:08X}",
                                    confidence=70
                                ))
                    offset += page_size

        except Exception as e:
            print(f"    [-] Heuristic scan error: {e}")

    # ------------------------------------------------------------------
    # Helper: Run Volatility3 Plugin
    # ------------------------------------------------------------------
    def _run_vol3_plugin(self, filepath: str, plugin: str) -> list:
        """
        Executes a Volatility3 plugin and parses the JSON output.
        Returns a list of row dicts.
        """
        try:
            result = subprocess.run(
                [sys.executable, '-m', 'volatility3',
                 '-f', filepath,
                 '-r', 'json',
                 plugin],
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode != 0 or not result.stdout.strip():
                return []

            parsed = json.loads(result.stdout)
            # Vol3 JSON output: {"rows": [...], "columns": [...]}
            rows = parsed.get('rows', [])
            cols = parsed.get('columns', [])
            if cols:
                return [dict(zip(cols, row)) for row in rows]
            return rows
        except Exception:
            return []
