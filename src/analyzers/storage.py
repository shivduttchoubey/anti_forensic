import math
import os
from src.engine.scoring import Anomaly, get_scoring_engine

# PyTSK3 is optional if it fails to build on the host, we fall back to raw file reading
try:
    import pytsk3
    TSK_AVAILABLE = True
except ImportError:
    TSK_AVAILABLE = False
    print("[!] pytsk3 not available. Falling back to basic raw file entropy checks.")

class StorageAnalyzer:
    def __init__(self):
        self.scoring = get_scoring_engine()

    def analyze(self, filepath: str):
        if not os.path.exists(filepath):
            print(f"[-] Storage image not found: {filepath}")
            return
            
        print(f"[*] Analyzing Storage Image: {filepath}")
        
        if TSK_AVAILABLE:
            self._analyze_with_tsk(filepath)
        else:
            self._analyze_raw(filepath)

    def _analyze_with_tsk(self, filepath: str):
        try:
            img_info = pytsk3.Img_Info(filepath)
            # Try to open as a volume system (partition table)
            try:
                vol_sys = pytsk3.Volume_Info(img_info)
                for part in vol_sys:
                    if part.flags == pytsk3.TSK_VS_PART_FLAG_ALLOC:
                        self._process_fs(img_info, part.start * vol_sys.info.block_size)
            except IOError:
                # No partition table, might be a direct filesystem image
                self._process_fs(img_info, 0)
        except Exception as e:
            print(f"[-] Storage Analysis error: {e}")
            
    def _process_fs(self, img_info, offset):
        try:
            fs_info = pytsk3.FS_Info(img_info, offset=offset)
            root_dir = fs_info.open_dir(path="/")
            self._recurse_dir(fs_info, root_dir, "/")
        except Exception as e:
            pass # Not a recognized filesystem or other error

    def _recurse_dir(self, fs_info, directory, path):
         for entry in directory:
             if entry.info.name.name in [b".", b".."]: continue
             
             name = entry.info.name.name.decode('utf-8', errors='replace')
             full_path = os.path.join(path, name)
             
             if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                 try:
                     sub_dir = fs_info.open_dir(inode=entry.info.meta.addr)
                     self._recurse_dir(fs_info, sub_dir, full_path)
                 except: pass
             elif entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG:
                 self._check_entropy_tsk(entry, full_path)

    def _check_entropy_tsk(self, file_entry, path):
        """ Checks entropy of a specific file inside the image """
        size = file_entry.info.meta.size
        # Skip empty files or huge files for performance in this prototype
        if size == 0 or size > 100 * 1024 * 1024: 
            return
            
        try:
            file_data = file_entry.read_random(0, size)
            entropy = self._calculate_entropy(file_data)
            
            # High entropy usually means encrypted or compressed
            if entropy > 7.9:
                anomaly = Anomaly(
                    category="HIDE",
                    description=f"High entropy detected (Encrypted/Obfuscated file). Entropy: {entropy:.2f}",
                    source="storage",
                    reference=f"File: {path} (Inode: {file_entry.info.meta.addr})",
                    confidence=0.8
                )
                self.scoring.add_anomaly(anomaly)
                
            # If the file extension is 'txt' but entropy is high -> Mismatch
            if path.lower().endswith('.txt') and entropy > 7.5:
                 anomaly = Anomaly(
                    category="FABRICATE",
                    description=f"Type Mismatch: High entropy in apparent text file.",
                    source="storage",
                    reference=f"File: {path}",
                    confidence=0.9
                )
                 self.scoring.add_anomaly(anomaly)
                 
        except Exception:
            pass

    def _analyze_raw(self, filepath: str):
        """ Fallback when PyTSK3 is not installed. Checks blocks of the raw file. """
        CHUNK_SIZE = 1024 * 1024 # 1MB chunks
        with open(filepath, 'rb') as f:
            chunk_idx = 0
            while True:
                data = f.read(CHUNK_SIZE)
                if not data: break
                
                entropy = self._calculate_entropy(data)
                if entropy > 7.95:
                    anomaly = Anomaly(
                        category="HIDE",
                        description=f"High entropy sector block detected.",
                        source="storage",
                        reference=f"File: {filepath}, Chunk offset: {chunk_idx * CHUNK_SIZE}",
                        confidence=0.7
                    )
                    self.scoring.add_anomaly(anomaly)
                chunk_idx += 1

    def _calculate_entropy(self, data):
        if not data: return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy
