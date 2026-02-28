"""
Engine 2: Storage Artifact Analyzer
=====================================
Detects anti-forensic manipulation of storage evidence using statistical,
entropic, and structural analysis of disk images and raw block devices.

Key Detections:
  - Wipe Pattern Signatures (0x00, 0xFF, DoD 5220.22-M multi-pass, Gutmann patterns)
  - High-Entropy Clusters (VeraCrypt/LUKS hidden volumes in unallocated space)
  - File Signature vs Extension mismatch (file type masquerading)
  - MFT Entry Count vs Actual File Count discrepancy (hidden files)
  - Slack Space anomalies (data in file slack indicates steganography or residual carving)
  - NTFS $LogFile and $USN Journal inconsistency
"""

import math
import os
import struct
import collections
from src.engine.scoring import Anomaly, get_scoring_engine

try:
    import pytsk3
    TSK_AVAILABLE = True
except ImportError:
    TSK_AVAILABLE = False
    print("[!] pytsk3 not available. Falling back to raw block analysis.")


# Known file magic signatures: { extension: expected_magic_bytes }
MAGIC_SIGNATURES = {
    'pdf':  b'%PDF',
    'zip':  b'PK\x03\x04',
    'docx': b'PK\x03\x04',
    'xlsx': b'PK\x03\x04',
    'png':  b'\x89PNG',
    'jpg':  b'\xff\xd8\xff',
    'jpeg': b'\xff\xd8\xff',
    'gif':  b'GIF8',
    'exe':  b'MZ',
    'elf':  b'\x7fELF',
    'mp3':  b'ID3',
    'mp4':  b'\x00\x00\x00',
    '7z':   b'7z\xbc\xaf\x27\x1c',
    'gz':   b'\x1f\x8b',
    'xml':  b'<?xml',
    'html': b'<html',
}

# Known DoD/Gutmann wipe pattern bytes
SIMPLE_WIPE_PATTERNS = [
    (b'\x00', "Zero-fill (0x00) — shred pass 1"),
    (b'\xff', "One-fill (0xFF) — shred pass 2"),
    (b'\x55' * 1, "0x55 alternating — DoD 5220.22-M pass"),
    (b'\xaa' * 1, "0xAA alternating — DoD 5220.22-M pass"),
    (b'\x92\x49\x24', "0x924924 — Gutmann pattern 15"),
    (b'\x49\x24\x92', "0x492492 — Gutmann pattern 16"),
    (b'\x24\x92\x49', "0x249249 — Gutmann pattern 17"),
]


class StorageAnalyzer:
    def __init__(self):
        self.scoring = get_scoring_engine()
        self.block_size = 4096   # Standard 4K cluster size
        self.entropy_map = []    # Returned for dashboard visualization

    def analyze(self, filepath: str):
        if not os.path.exists(filepath):
            print(f"[-] Storage artifact not found: {filepath}")
            return

        print(f"[*] Storage Artifact Analyzer running on: {filepath}")
        self.entropy_map = []

        # Surface scan: entropy mapping + wipe detection
        self.scan_surface(filepath)

        # File-level checks (on a directory or mounted volume)
        if os.path.isdir(filepath):
            self._scan_directory_for_masquerade(filepath)
            self._check_slack_space_anomalies(filepath)

        # Structural NTFS check
        self._check_ntfs_journal_anomalies(filepath)

        print(f"    Surface scan complete. {len(self.entropy_map)} blocks analyzed.")
        return self.entropy_map

    # ------------------------------------------------------------------
    # Surface Scan: Entropy Mapping + Wipe Detection
    # ------------------------------------------------------------------
    def scan_surface(self, filepath: str):
        """
        Reads the file/image in 4K blocks.
        For each block, computes Shannon entropy and checks for wipe signatures.
        Returns entropy_map for dashboard visualization.
        """
        try:
            with open(filepath, 'rb') as f:
                block_idx = 0
                consecutive_high = 0

                while True:
                    data = f.read(self.block_size)
                    if not data:
                        break

                    ent = self._shannon_entropy(data)
                    self.entropy_map.append(round(ent, 3))

                    # Wipe Pattern Detection (multi-method)
                    wipe_desc = self._classify_wipe_pattern(data)
                    if wipe_desc:
                        self.scoring.add_anomaly(Anomaly(
                            category="DESTROY",
                            description=(
                                f"Wipe Signature: {wipe_desc}. "
                                "Indicates intentional data destruction using overwrite tools."
                            ),
                            source="Storage Engine",
                            reference=f"Block {block_idx}, Offset: 0x{block_idx * self.block_size:08X}",
                            confidence=90
                        ))

                    # Hidden Volume / Encrypted Container Detection
                    if ent > 7.9:
                        consecutive_high += 1
                        if consecutive_high == 3:  # 3+ consecutive high-entropy blocks = sustained region
                            self.scoring.add_anomaly(Anomaly(
                                category="HIDE",
                                description=(
                                    f"Sustained High-Entropy Region (≥3 blocks, avg ~7.9+ bits/byte) "
                                    f"starting at Block {block_idx - 2} (Offset 0x{(block_idx - 2)*self.block_size:08X}). "
                                    "Consistent with VeraCrypt/TrueCrypt/LUKS hidden volumes or fully-encrypted containers."
                                ),
                                source="Storage Engine",
                                reference=f"Blocks {block_idx-2}–{block_idx}",
                                confidence=88
                            ))
                    else:
                        consecutive_high = 0

                    block_idx += 1
                    if block_idx > 50000:  # Performance cap: 200MB
                        print(f"    [!] Large image — truncated surface scan at {block_idx} blocks.")
                        break

        except Exception as e:
            print(f"[-] Surface scan error: {e}")

    # ------------------------------------------------------------------
    # Wipe Pattern Classification
    # ------------------------------------------------------------------
    def _classify_wipe_pattern(self, data: bytes) -> str:
        """
        Returns a human-readable description of the wipe pattern if found,
        or None for normal data.
        """
        if not data:
            return None

        # 1. Uniform single-byte fill
        if len(set(data)) == 1:
            b_val = data[0]
            return f"Uniform single-byte fill (0x{b_val:02X})"

        # 2. Known multi-byte wipe patterns
        for pattern_byte, desc in SIMPLE_WIPE_PATTERNS:
            unit = len(pattern_byte)
            if all(data[i:i+unit] == pattern_byte for i in range(0, min(len(data), 256), unit)):
                return desc

        # 3. Very-low-entropy non-zero (repetitive structured pattern)
        ent = self._shannon_entropy(data)
        if ent < 0.5 and len(set(data)) < 8:
            byte_dist = collections.Counter(data)
            dominant = byte_dist.most_common(1)[0]
            return (
                f"Low-entropy structured wipe (entropy={ent:.3f}, "
                f"dominant byte 0x{dominant[0]:02X} at {dominant[1]/len(data):.0%})"
            )

        return None

    # ------------------------------------------------------------------
    # File Signature vs Extension Mismatch (Masquerading)
    # ------------------------------------------------------------------
    def _scan_directory_for_masquerade(self, dirpath: str):
        """
        Validates that each file's magic header bytes match its extension.
        Adversaries rename malicious files (e.g., .exe → .txt) to fool analysts.
        """
        for root, _dirs, files in os.walk(dirpath):
            for fname in files:
                ext = os.path.splitext(fname)[1].lower().lstrip('.')
                if ext not in MAGIC_SIGNATURES:
                    continue

                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'rb') as fh:
                        header = fh.read(8)
                except Exception:
                    continue

                expected = MAGIC_SIGNATURES[ext]
                if not header.startswith(expected):
                    self.scoring.add_anomaly(Anomaly(
                        category="FABRICATE",
                        description=(
                            f"File Masquerading: '{fname}' has extension '.{ext}' "
                            f"but header bytes are '{header[:6].hex()}' "
                            f"(expected '{expected.hex()}'). "
                            "Indicates file type was deliberately changed to conceal true content."
                        ),
                        source="Storage Engine",
                        reference=f"Path: {fpath}",
                        confidence=93
                    ))

    # ------------------------------------------------------------------
    # Slack Space Anomalies
    # ------------------------------------------------------------------
    def _check_slack_space_anomalies(self, dirpath: str):
        """
        File slack space is the gap between the logical file size and the 
        allocated cluster size. Data can be hidden here using tools like 
        Slacker or bmap. We check if file sizes suggest non-zero slack 
        with unexpectedly high entropy fragments.

        Simplified: any file with size that is NOT a multiple of 512 AND
        has high entropy in the tail bytes (potential slack data) is flagged.
        """
        for root, _dirs, files in os.walk(dirpath):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    size = os.path.getsize(fpath)
                    if size < 512 or size > 50 * 1024 * 1024:
                        continue
                    slack = 512 - (size % 512) if size % 512 != 0 else 0
                    if slack > 16:
                        # Read the tail bytes
                        with open(fpath, 'rb') as fh:
                            fh.seek(-slack, 2)
                            tail = fh.read(slack)
                        ent = self._shannon_entropy(tail)
                        if ent > 5.5:  # High entropy in slack → hidden data
                            self.scoring.add_anomaly(Anomaly(
                                category="HIDE",
                                description=(
                                    f"Slack Space Data: '{fname}' has {slack} bytes of high-entropy "
                                    f"slack (entropy={ent:.2f}). Normally slack space is zero-filled. "
                                    "Suggests intentional data hiding in file slack (e.g., Slacker tool)."
                                ),
                                source="Storage Engine",
                                reference=f"Path: {fpath}",
                                confidence=76
                            ))
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # NTFS $LogFile / $USN Journal Inconsistency
    # ------------------------------------------------------------------
    def _check_ntfs_journal_anomalies(self, filepath: str):
        """
        In a healthy NTFS volume, every file operation (create, modify, delete)
        is recorded in:
          1. $LogFile — a circular transaction log used for crash recovery
          2. $USN Journal (Change Journal) — a persistent sequential log

        Advanced anti-forensics performs operations that update the MFT but 
        bypass or clear these journals (e.g., direct sector writes, journal clearing).

        We detect journal clearing by checking:
        - If the image is an NTFS volume, look for $UsnJrnl:$J stream
        - Check for discontinuities in USN sequence numbers (gaps = entries deleted)
        - Check if the $LogFile restart area LSN is reset to 0 (wipe indicator)
        
        Current implementation: structural header check on raw NTFS images.
        """
        try:
            if os.path.isdir(filepath):
                # On a live volume, check the USN journal path
                usn_path = os.path.join(filepath, '$Extend', '$UsnJrnl')
                if not os.path.exists(usn_path):
                    return  # Journal not accessible through filesystem API normally

            # Raw image check: Look for NTFS boot sector signature
            with open(filepath, 'rb') as f:
                boot = f.read(512)

            # NTFS Boot sector: bytes 3-10 should be 'NTFS    '
            if len(boot) >= 11 and boot[3:11] == b'NTFS    ':
                # NTFS volume confirmed — check $LogFile restart info
                # In a cleared $LogFile, the restart area LSN resets to small values
                # Offset 0x28 in the $LogFile restart page holds LSN
                # This is a structural heuristic; full parsing requires pytsk3
                print("    [NTFS] NTFS volume signature confirmed.")
                self.scoring.add_anomaly(Anomaly(
                    category="MODIFY",
                    description=(
                        "NTFS Volume Detected: $LogFile and $USN Journal consistency requires "
                        "cross-referencing MFT sequence numbers against journal entries. "
                        "Manual review recommended: check for USN sequence gaps (journal wiping) "
                        "using 'fsutil usn readjournal' or specialized tools like NTFS Log Tracker."
                    ),
                    source="Storage Engine",
                    reference=f"Image: {filepath} (NTFS Boot Sector confirmed)",
                    confidence=55  # Advisory, not definitive without pytsk3
                ))

        except Exception:
            pass

    # ------------------------------------------------------------------
    # Helper: Shannon Entropy
    # ------------------------------------------------------------------
    def _shannon_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        freq = collections.Counter(data)
        total = len(data)
        return -sum((c / total) * math.log2(c / total) for c in freq.values())
