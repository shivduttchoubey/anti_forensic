"""
╔══════════════════════════════════════════════════════════════════╗
║          DISKENTROPY — Forensic Volume Analyzer                  ║
║          Tkinter GUI | NTFS-aware | Hidden Volume Detection      ║
║          Live USB Support | SSD TRIM Simulation                  ║
║          Requirements: pip install pillow numpy matplotlib       ║
╚══════════════════════════════════════════════════════════════════╝

USAGE:
  Windows : Run as Administrator  →  python disk_entropy_analyzer.py
  Linux   : sudo python disk_entropy_analyzer.py
            (or: sudo usermod -aG disk $USER  then re-login)
  macOS   : sudo python disk_entropy_analyzer.py
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import struct
import math
import os
import json
import subprocess
import platform
from datetime import datetime

import numpy as np
from PIL import Image, ImageTk
import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

# ──────────────────────────────────────────────────────────────────
#  THEME
# ──────────────────────────────────────────────────────────────────
BG        = "#040810"
PANEL     = "#080f1a"
BORDER    = "#0a2040"
ACCENT    = "#00ffe7"
ACCENT2   = "#ff6b00"
ACCENT3   = "#7b2fff"
DANGER    = "#ff2255"
SAFE      = "#00ff88"
WARN      = "#ffcc00"
TEXT      = "#8ab4cc"
TEXT_BR   = "#cdeeff"
FONT_MONO = ("Courier New", 9)
FONT_HEAD = ("Courier New", 8, "bold")


# ──────────────────────────────────────────────────────────────────
#  HELPERS
# ──────────────────────────────────────────────────────────────────

def fmt_bytes(b):
    if b < 1024:    return f"{b} B"
    if b < 1 << 20: return f"{b / 1024:.1f} KB"
    if b < 1 << 30: return f"{b / 1048576:.2f} MB"
    return f"{b / 1073741824:.2f} GB"


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq   = np.frombuffer(data, dtype=np.uint8)
    counts = np.bincount(freq, minlength=256).astype(np.float64)
    counts = counts[counts > 0]
    p      = counts / len(data)
    return float(-np.sum(p * np.log2(p)))


def simulate_ssd_trim(data: bytearray, block_size: int):
    num_blocks = len(data) // block_size
    result     = bytearray(data)
    trimmed    = 0
    for i in range(2, num_blocks - 2):
        blk = data[i * block_size:(i + 1) * block_size]
        if shannon_entropy(bytes(blk)) < 0.5:
            result[i * block_size:(i + 1) * block_size] = b'\x00' * block_size
            trimmed += 1
    return result, trimmed


# ──────────────────────────────────────────────────────────────────
#  NTFS PARSER
# ──────────────────────────────────────────────────────────────────

class NTFSParser:
    def __init__(self, data: bytes):
        self.data                = data
        self.valid               = False
        self.block_size          = 4096
        self.sector_size         = 512
        self.sectors_per_cluster = 8
        self.total_sectors       = 0
        self.total_clusters      = 0
        self.volume_size         = 0
        self.oem_id              = ""
        self.mft_offset          = 0
        self._parse()

    def _parse(self):
        if len(self.data) < 512:
            return
        try:
            self.oem_id = self.data[3:11].decode("ascii", errors="replace").strip()
            self.sector_size = struct.unpack_from("<H", self.data, 11)[0]
            if self.sector_size not in (512, 1024, 2048, 4096):
                self.sector_size = 512
            spc = struct.unpack_from("B", self.data, 13)[0]
            if spc == 0:  spc = 8
            if spc > 128: spc = 2 ** (256 - spc)
            self.sectors_per_cluster = spc
            self.block_size = self.sector_size * self.sectors_per_cluster
            if "NTFS" not in self.oem_id:
                return
            self.total_sectors  = struct.unpack_from("<Q", self.data, 40)[0]
            self.total_clusters = (self.total_sectors // self.sectors_per_cluster
                                   if self.sectors_per_cluster else 0)
            self.mft_offset     = struct.unpack_from("<Q", self.data, 48)[0] * self.block_size
            self.volume_size    = self.total_sectors * self.sector_size
            self.valid          = True
        except Exception:
            self.valid = False

    def summary(self):
        return "\n".join([
            f"OEM ID         : {self.oem_id}",
            f"Valid NTFS     : {self.valid}",
            f"Sector Size    : {self.sector_size} B",
            f"Sectors/Cluster: {self.sectors_per_cluster}",
            (f"Cluster Size   : {self.block_size} B  ({self.block_size // 1024} KB)"
             if self.block_size >= 1024 else f"Cluster Size   : {self.block_size} B"),
            f"Total Sectors  : {self.total_sectors:,}",
            f"Total Clusters : {self.total_clusters:,}",
            f"Volume Size    : {fmt_bytes(self.volume_size)}",
            f"MFT Offset     : 0x{self.mft_offset:016X}",
        ])


# ──────────────────────────────────────────────────────────────────
#  ANALYSIS CORE
# ──────────────────────────────────────────────────────────────────

class DiskAnalysis:
    def __init__(self):
        self.blocks           = []
        self.trim_zones       = []
        self.anomaly_regions  = []
        self.hidden_vol_cands = []
        self.ntfs             = None
        self.raw_size         = 0
        self.block_size       = 4096
        self.trim_applied     = False

    def run(self, data: bytes, block_size: int, threshold: float,
            noise_filter: int, apply_trim: bool, progress_cb=None):

        self.raw_size   = len(data)
        self.block_size = block_size
        self.ntfs       = NTFSParser(data[:512])

        if apply_trim:
            if progress_cb: progress_cb(2, "Simulating SSD TRIM…")
            data, _ = simulate_ssd_trim(bytearray(data), block_size)
            self.trim_applied = True
        else:
            self.trim_applied = False

        num_blocks = len(data) // block_size
        if progress_cb: progress_cb(5, f"Computing entropy for {num_blocks} blocks…")

        blocks = []
        for i in range(num_blocks):
            blk    = data[i * block_size:(i + 1) * block_size]
            H      = shannon_entropy(bytes(blk))
            zeroed = all(b == 0 for b in blk)
            blocks.append({"index": i, "offset": i * block_size,
                           "size": block_size, "entropy": H, "zeroed": zeroed})
            if i % max(1, num_blocks // 40) == 0 and progress_cb:
                progress_cb(5 + int(i / num_blocks * 60),
                            f"Block {i}/{num_blocks}")

        self.blocks = blocks
        if progress_cb: progress_cb(68, "Detecting TRIM zones…")
        self.trim_zones = self._detect_trim(blocks, noise_filter)
        if progress_cb: progress_cb(78, "Detecting anomalies…")
        self.anomaly_regions = self._detect_anomalies(blocks, self.trim_zones,
                                                       threshold, noise_filter)
        if progress_cb: progress_cb(90, "Classifying hidden volume candidates…")
        self.hidden_vol_cands = self._classify_hv(self.anomaly_regions,
                                                   self.trim_zones, block_size)
        if progress_cb: progress_cb(100, "Done.")

    def _detect_trim(self, blocks, noise_filter):
        zones, in_zone, start = [], False, 0
        for i, b in enumerate(blocks):
            if b["zeroed"] and not in_zone:
                in_zone, start = True, i
            elif not b["zeroed"] and in_zone:
                if i - start >= noise_filter:
                    zones.append({"start_block": start, "end_block": i - 1,
                                  "start": blocks[start]["offset"],
                                  "end":   blocks[i - 1]["offset"] + blocks[i - 1]["size"],
                                  "block_count": i - start})
                in_zone = False
        if in_zone and len(blocks) - start >= noise_filter:
            zones.append({"start_block": start, "end_block": len(blocks) - 1,
                          "start": blocks[start]["offset"],
                          "end":   blocks[-1]["offset"] + blocks[-1]["size"],
                          "block_count": len(blocks) - start})
        return zones

    def _detect_anomalies(self, blocks, trim_zones, threshold, noise_filter):
        trim_set = set()
        for z in trim_zones:
            for i in range(z["start_block"], z["end_block"] + 1):
                trim_set.add(i)
        anomalies, in_anom, start, entrs = [], False, 0, []
        for i, b in enumerate(blocks):
            is_anom = i not in trim_set and b["entropy"] >= threshold
            if is_anom and not in_anom:
                in_anom, start, entrs = True, i, [b["entropy"]]
            elif is_anom and in_anom:
                entrs.append(b["entropy"])
            elif not is_anom and in_anom:
                if i - start >= noise_filter:
                    avg = sum(entrs) / len(entrs)
                    anomalies.append({
                        "start_block": start, "end_block": i - 1,
                        "start":  blocks[start]["offset"],
                        "end":    blocks[i - 1]["offset"] + blocks[i - 1]["size"],
                        "size":   blocks[i - 1]["offset"] + blocks[i - 1]["size"] - blocks[start]["offset"],
                        "avg_entropy": avg, "max_entropy": max(entrs),
                        "block_count": i - start,
                    })
                in_anom, entrs = False, []
        return anomalies

    def _classify_hv(self, anomalies, trim_zones, block_size):
        candidates = []
        for a in anomalies:
            conf, reasons = 0, []
            lt = next((z for z in trim_zones if z["end"] <= a["start"]
                       and a["start"] - z["end"] < block_size * 5), None)
            rt = next((z for z in trim_zones if z["start"] >= a["end"]
                       and z["start"] - a["end"] < block_size * 5), None)
            if a["avg_entropy"] > 7.8:   conf += 40; reasons.append("max-entropy")
            elif a["avg_entropy"] > 7.5: conf += 25; reasons.append("high-entropy")
            if lt:        conf += 25; reasons.append("left-TRIM-bounded")
            if rt:        conf += 25; reasons.append("right-TRIM-bounded")
            if lt and rt: conf += 10; reasons.append("double-bounded")
            if a["start"] % 512  == 0: conf += 5; reasons.append("512-aligned")
            if a["start"] % 4096 == 0: conf += 5; reasons.append("4K-aligned")
            if conf >= 40:
                candidates.append({**a, "confidence": min(conf, 99),
                                   "reasons": reasons,
                                   "left_trim": lt, "right_trim": rt})
        return candidates


# ──────────────────────────────────────────────────────────────────
#  TREEMAP CANVAS
# ──────────────────────────────────────────────────────────────────

class TreemapCanvas(tk.Canvas):
    COLORS = {
        "zeroed":    "#030a14",
        "low":       "#0a2040",
        "medium":    "#1a5060",
        "high":      "#00ffe7",
        "anomalous": "#ff6b00",
        "max":       "#ff2255",
        "hidden":    "#7b2fff",
    }

    def __init__(self, parent, analysis, **kwargs):
        super().__init__(parent, bg=BG, highlightthickness=0, **kwargs)
        self.analysis = analysis
        self.tooltip  = None      # list of two canvas IDs: [rect, text]
        self._hv_set  = set()
        self._cell    = 8
        self._cols    = 1
        self.bind("<Configure>", lambda e: self.render())
        self.bind("<Motion>",    self._on_hover)
        self.bind("<Leave>",     self._on_leave)

    def render(self):
        self.delete("all")
        if not self.analysis.blocks:
            W, H = self.winfo_width(), self.winfo_height()
            self.create_text(W // 2, H // 2,
                             text="[ Load a disk image or scan USB to begin ]",
                             fill=BORDER, font=FONT_MONO)
            return

        self._hv_set = set()
        for hv in self.analysis.hidden_vol_cands:
            for i in range(hv["start_block"], hv["end_block"] + 1):
                self._hv_set.add(i)

        W    = self.winfo_width()
        H    = self.winfo_height()
        n    = len(self.analysis.blocks)
        cell = max(4, int(math.sqrt(W * H / n)))
        cols = max(1, W // cell)
        self._cell = cell
        self._cols = cols

        for b in self.analysis.blocks:
            i   = b["index"]
            col = i % cols
            row = i // cols
            self.create_rectangle(
                col * cell, row * cell,
                col * cell + cell - 1, row * cell + cell - 1,
                fill=self._color(b), outline=BORDER, width=0)

        for z in self.analysis.trim_zones:
            for i in range(z["start_block"], min(z["end_block"] + 1, n)):
                col = i % cols; row = i // cols
                self.create_rectangle(
                    col * cell, row * cell,
                    col * cell + cell - 1, row * cell + cell - 1,
                    fill="", outline=WARN, width=1)

        for hv in self.analysis.hidden_vol_cands:
            xs = [(b % cols) * cell for b in range(hv["start_block"], hv["end_block"] + 1)]
            ys = [(b // cols) * cell for b in range(hv["start_block"], hv["end_block"] + 1)]
            if xs:
                self.create_rectangle(
                    min(xs), min(ys), max(xs) + cell, max(ys) + cell,
                    fill="", outline=ACCENT3, width=2, dash=(6, 3))

        self.create_text(self.winfo_width() // 2, 12,
                         text="Disk Block Visualization (Treemap)",
                         fill=TEXT_BR, font=("Courier New", 10, "bold"))

    def _color(self, b):
        if b["zeroed"]:                return self.COLORS["zeroed"]
        if b["index"] in self._hv_set: return self.COLORS["hidden"]
        H = b["entropy"]
        if H < 1.0: return self.COLORS["low"]
        if H < 4.0: return self.COLORS["medium"]
        if H < 7.2: return self.COLORS["high"]
        if H < 7.8: return self.COLORS["anomalous"]
        return self.COLORS["max"]

    def _on_hover(self, event):
        if not self.analysis.blocks:
            return
        col = event.x // self._cell
        row = event.y // self._cell
        idx = row * self._cols + col
        if idx < 0 or idx >= len(self.analysis.blocks):
            return
        b      = self.analysis.blocks[idx]
        hv     = next((h for h in self.analysis.hidden_vol_cands
                       if h["start_block"] <= idx <= h["end_block"]), None)
        status = ("HIDDEN VOL CANDIDATE" if hv
                  else "TRIM ZONE" if b["zeroed"] else "NORMAL")
        tip = (
            f"Block ID: {b['index']}\n"
            f"Offset: 0x{b['offset']:08X}\n"
            f"Size: {fmt_bytes(b['size'])}\n"
            f"Entropy: {b['entropy']:.4f}\n"
            f"\nMAC-B Timestamps (from disk metadata):\n"
            f"  M (Modified): Not available\n"
            f"  C (Changed):  Not available\n"
            f"  A (Accessed): Not available\n"
            f"  B (Birth):    Not available\n"
            f"\nStatus: {status}"
        )
        self._show_tooltip(event.x + 14, event.y + 14, tip)

    def _on_leave(self, event):
        if self.tooltip:
            for item in self.tooltip:
                self.delete(item)
            self.tooltip = None

    def _show_tooltip(self, x, y, text):
        if self.tooltip:
            for item in self.tooltip:
                self.delete(item)
            self.tooltip = None

        lines = text.split("\n")
        w = max(len(l) for l in lines) * 7 + 16
        h = len(lines) * 14 + 12
        cw = self.winfo_width()
        ch = self.winfo_height()
        if x + w > cw: x = cw - w - 4
        if y + h > ch: y = ch - h - 4

        r = self.create_rectangle(x, y, x + w, y + h,
                                  fill="#050d18", outline=ACCENT, width=1)
        t = self.create_text(x + 8, y + 8, text=text,
                             fill=TEXT_BR, font=("Courier New", 8), anchor="nw")
        self.tooltip = [r, t]


# ──────────────────────────────────────────────────────────────────
#  MATPLOTLIB FIGURES
# ──────────────────────────────────────────────────────────────────

def make_entropy_figure(analysis):
    fig = Figure(figsize=(10, 1.8), facecolor=PANEL, tight_layout=True)
    ax  = fig.add_subplot(111)
    ax.set_facecolor(BG)
    if not analysis.blocks:
        ax.text(0.5, 0.5, "No data", ha="center", va="center",
                color=TEXT, transform=ax.transAxes)
        return fig

    n      = len(analysis.blocks)
    ys     = np.array([b["entropy"] for b in analysis.blocks])
    hv_set = set()
    for hv in analysis.hidden_vol_cands:
        for i in range(hv["start_block"], hv["end_block"] + 1):
            hv_set.add(i)

    colors = []
    for i, b in enumerate(analysis.blocks):
        if b["zeroed"]:          colors.append(BORDER)
        elif i in hv_set:        colors.append(ACCENT3)
        elif b["entropy"] > 7.8: colors.append(DANGER)
        elif b["entropy"] > 7.2: colors.append(ACCENT2)
        elif b["entropy"] > 6.5: colors.append(ACCENT)
        elif b["entropy"] > 4.0: colors.append("#1a5060")
        else:                    colors.append("#0a2040")

    ax.bar(np.arange(n), ys, width=1.0, color=colors, linewidth=0)
    ax.axhline(7.2, color=DANGER, linewidth=0.6, linestyle="--", alpha=0.7)
    for z in analysis.trim_zones:
        ax.axvspan(z["start_block"], z["end_block"], alpha=0.15, color=WARN)
    for hv in analysis.hidden_vol_cands:
        ax.axvspan(hv["start_block"], hv["end_block"], alpha=0.2, color=ACCENT3)
    ax.set_xlim(0, n)
    ax.set_ylim(0, 8.2)
    ax.set_ylabel("H (bits)", color=TEXT, fontsize=7)
    ax.tick_params(colors=TEXT, labelsize=6)
    for sp in ax.spines.values(): sp.set_edgecolor(BORDER)
    ax.set_title("Entropy Heatmap — Full Volume", color=TEXT_BR, fontsize=8, pad=4)
    return fig


def make_histogram_figure(analysis):
    fig = Figure(figsize=(5, 2.2), facecolor=PANEL, tight_layout=True)
    ax  = fig.add_subplot(111)
    ax.set_facecolor(BG)
    if not analysis.blocks:
        return fig
    entrs         = [b["entropy"] for b in analysis.blocks]
    counts, edges = np.histogram(entrs, bins=32, range=(0, 8))
    centers       = (edges[:-1] + edges[1:]) / 2
    c_colors      = [ACCENT3 if e > 7.2 else ACCENT if e > 6.5 else "#1a5060"
                     for e in centers]
    ax.bar(centers, counts, width=edges[1] - edges[0], color=c_colors, linewidth=0)
    ax.set_xlabel("Entropy (bits)", color=TEXT, fontsize=7)
    ax.set_ylabel("Blocks",         color=TEXT, fontsize=7)
    ax.tick_params(colors=TEXT, labelsize=6)
    for sp in ax.spines.values(): sp.set_edgecolor(BORDER)
    ax.set_title("Entropy Distribution", color=TEXT_BR, fontsize=8, pad=4)
    return fig


def make_zone_figure(analysis):
    fig = Figure(figsize=(5, 2.2), facecolor=PANEL, tight_layout=True)
    ax  = fig.add_subplot(111)
    ax.set_facecolor(BG)
    if not analysis.hidden_vol_cands:
        ax.text(0.5, 0.5, "No hidden vol candidate found", ha="center",
                va="center", color=TEXT, transform=ax.transAxes, fontsize=8)
        return fig
    hv  = analysis.hidden_vol_cands[0]
    pad = max(10, (hv["end_block"] - hv["start_block"]) // 4)
    s   = max(0, hv["start_block"] - pad)
    e   = min(len(analysis.blocks) - 1, hv["end_block"] + pad)
    blks = analysis.blocks[s:e + 1]
    xs   = np.arange(len(blks))
    ys   = np.array([b["entropy"] for b in blks])
    ax.fill_between(xs, ys, alpha=0.4, color=ACCENT)
    ax.plot(xs, ys, color=ACCENT, linewidth=0.8)
    lb = hv["start_block"] - s
    rb = hv["end_block"]   - s
    ax.axvspan(lb, rb, alpha=0.25, color=ACCENT3)
    ax.axvline(lb, color=ACCENT3, linewidth=1.5, linestyle="--")
    ax.axvline(rb, color=ACCENT3, linewidth=1.5, linestyle="--")
    ax.axhline(7.2, color=DANGER, linewidth=0.5, linestyle=":")
    ax.set_ylim(0, 8.5)
    ax.set_xlim(0, len(blks))
    ax.tick_params(colors=TEXT, labelsize=6)
    for sp in ax.spines.values(): sp.set_edgecolor(BORDER)
    ax.set_title(f"Zone Zoom — HV @ 0x{hv['start']:08X}",
                 color=TEXT_BR, fontsize=8)
    return fig


# ──────────────────────────────────────────────────────────────────
#  MAIN APPLICATION
# ──────────────────────────────────────────────────────────────────

class App(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("DiskEntropy — Forensic Volume Analyzer")
        self.configure(bg=BG)
        self.geometry("1300x880")
        self.minsize(1000, 700)

        self.analysis      = DiskAnalysis()
        self.file_path     = None
        self._scan_thread  = None
        self._usb_map      = {}

        self._build_ui()
        self._log("DiskEntropy forensic engine initialized", "info")
        self._log("Shannon entropy calculator : READY", "ok")
        self._log("TRIM zone detector         : READY", "ok")
        self._log("Hidden volume classifier   : READY", "ok")
        self._log("Awaiting disk image or USB device…", "warn")

    # ── UI BUILD ───────────────────────────────────────────────────

    def _build_ui(self):
        self._build_header()
        body = tk.PanedWindow(self, orient=tk.HORIZONTAL, bg=BG,
                              sashwidth=4, sashrelief=tk.FLAT, bd=0)
        body.pack(fill=tk.BOTH, expand=True)
        body.add(self._build_sidebar(body), minsize=260, width=290)
        body.add(self._build_content(body), minsize=700)

    def _build_header(self):
        hdr = tk.Frame(self, bg="#040e1a", height=46)
        hdr.pack(fill=tk.X)
        hdr.pack_propagate(False)
        tk.Label(hdr, text="DISK",    fg=ACCENT,  bg="#040e1a",
                 font=("Courier New", 16, "bold")).pack(side=tk.LEFT, padx=(18, 0))
        tk.Label(hdr, text="ENTROPY", fg=ACCENT2, bg="#040e1a",
                 font=("Courier New", 16, "bold")).pack(side=tk.LEFT)
        tk.Label(hdr, text="  FORENSIC VOLUME ANALYZER v2.2",
                 fg=TEXT, bg="#040e1a",
                 font=("Courier New", 9)).pack(side=tk.LEFT)
        self._status_var = tk.StringVar(value="NO VOLUME LOADED")
        tk.Label(hdr, textvariable=self._status_var, fg=WARN,
                 bg="#040e1a", font=FONT_HEAD).pack(side=tk.RIGHT, padx=18)
        tk.Frame(self, bg=BORDER, height=1).pack(fill=tk.X)

    def _build_sidebar(self, parent):
        frame = tk.Frame(parent, bg=PANEL, width=290)
        frame.pack_propagate(False)
        pad = dict(padx=12, pady=3)

        # ── Volume Source ──────────────────────────────────────────
        self._section(frame, "▸ VOLUME SOURCE")
        bf = tk.Frame(frame, bg=PANEL)
        bf.pack(fill=tk.X, **pad)
        self._btn(bf, "⬆  OPEN DISK IMAGE", self._open_file
                  ).pack(fill=tk.X, pady=2)
        self._btn(bf, "▶  SIMULATE VOLUME",  self._simulate, accent=True
                  ).pack(fill=tk.X, pady=2)
        self._file_lbl = tk.Label(frame, text="No file loaded",
                                  fg=TEXT, bg=PANEL,
                                  font=("Courier New", 8),
                                  wraplength=250, justify=tk.LEFT)
        self._file_lbl.pack(**pad)

        # ── Live USB ───────────────────────────────────────────────
        self._section(frame, "▸ LIVE USB DEVICE")

        self._usb_var = tk.StringVar(value="— select device —")

        sty = ttk.Style()
        sty.theme_use("default")
        sty.configure("Dark.TCombobox",
                       fieldbackground=PANEL, background=PANEL,
                       foreground=TEXT, selectbackground=BORDER,
                       arrowcolor=ACCENT)

        self._usb_dropdown = ttk.Combobox(
            frame, textvariable=self._usb_var,
            state="readonly", font=("Courier New", 8),
            style="Dark.TCombobox")
        self._usb_dropdown.pack(fill=tk.X, padx=12, pady=2)

        uf = tk.Frame(frame, bg=PANEL)
        uf.pack(fill=tk.X, padx=12, pady=2)
        self._btn(uf, "↻ REFRESH",  self._refresh_usb
                  ).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 2))
        self._btn(uf, "⚡ SCAN USB", self._scan_usb, danger=True
                  ).pack(side=tk.LEFT, fill=tk.X, expand=True)

        self._usb_size_lbl = tk.Label(frame, text="",
                                      fg=TEXT, bg=PANEL,
                                      font=("Courier New", 7))
        self._usb_size_lbl.pack(padx=12, anchor=tk.W)
        self._refresh_usb()

        # ── Scan Parameters ────────────────────────────────────────
        self._section(frame, "▸ SCAN PARAMETERS")

        self._apply_trim = tk.BooleanVar(value=True)
        tk.Checkbutton(frame, text="Simulate SSD TRIM",
                       variable=self._apply_trim,
                       fg=TEXT, bg=PANEL, selectcolor=BG,
                       activebackground=PANEL, activeforeground=ACCENT,
                       font=FONT_MONO).pack(anchor=tk.W, padx=12)

        tk.Label(frame, text="Anomaly Threshold (H ≥)",
                 fg=TEXT, bg=PANEL, font=FONT_MONO).pack(anchor=tk.W, padx=12)
        self._thresh_var = tk.DoubleVar(value=72)
        self._thresh_lbl = tk.Label(frame, text="7.2",
                                    fg=ACCENT, bg=PANEL, font=FONT_MONO)
        self._thresh_lbl.pack(anchor=tk.E, padx=12)
        tk.Scale(frame, from_=50, to=99, orient=tk.HORIZONTAL,
                 variable=self._thresh_var, resolution=1,
                 command=lambda v: self._thresh_lbl.config(
                     text=f"{float(v)/10:.1f}"),
                 bg=PANEL, fg=TEXT, highlightthickness=0,
                 troughcolor=BG, activebackground=ACCENT,
                 showvalue=False).pack(fill=tk.X, padx=12)

        tk.Label(frame, text="Noise Filter (min blocks)",
                 fg=TEXT, bg=PANEL, font=FONT_MONO).pack(anchor=tk.W, padx=12)
        self._noise_var = tk.IntVar(value=3)
        self._noise_lbl = tk.Label(frame, text="3",
                                   fg=ACCENT, bg=PANEL, font=FONT_MONO)
        self._noise_lbl.pack(anchor=tk.E, padx=12)
        tk.Scale(frame, from_=1, to=20, orient=tk.HORIZONTAL,
                 variable=self._noise_var, resolution=1,
                 command=lambda v: self._noise_lbl.config(text=str(v)),
                 bg=PANEL, fg=TEXT, highlightthickness=0,
                 troughcolor=BG, activebackground=ACCENT,
                 showvalue=False).pack(fill=tk.X, padx=12)

        # ── Legend ─────────────────────────────────────────────────
        self._section(frame, "▸ LEGEND")
        for color, label in [
            (TreemapCanvas.COLORS["zeroed"],    "Zeroed / TRIM  (0.0)"),
            (TreemapCanvas.COLORS["low"],       "Low Entropy    (< 4.0)"),
            (TreemapCanvas.COLORS["medium"],    "Medium         (4.0–6.5)"),
            (TreemapCanvas.COLORS["high"],      "High           (6.5–7.5)"),
            (TreemapCanvas.COLORS["anomalous"], "Anomalous      (7.5–7.9)"),
            (TreemapCanvas.COLORS["max"],       "Max Entropy    (≈ 8.0)"),
            (TreemapCanvas.COLORS["hidden"],    "Hidden Vol Candidate"),
        ]:
            row = tk.Frame(frame, bg=PANEL)
            row.pack(fill=tk.X, padx=14, pady=1)
            tk.Label(row, text="  ", bg=color, width=3).pack(side=tk.LEFT)
            tk.Label(row, text=f"  {label}", fg=TEXT, bg=PANEL,
                     font=("Courier New", 8)).pack(side=tk.LEFT)

        # ── Stats ──────────────────────────────────────────────────
        self._section(frame, "▸ VOLUME STATS")
        self._stat_vars = {
            k: tk.StringVar(value="—")
            for k in ["Blocks", "Anomalies", "Avg Entropy",
                      "TRIM Zones", "HV Candidates"]
        }
        for k, v in self._stat_vars.items():
            row = tk.Frame(frame, bg=PANEL)
            row.pack(fill=tk.X, padx=14, pady=1)
            tk.Label(row, text=k + ":", fg=TEXT, bg=PANEL,
                     font=("Courier New", 8), width=14,
                     anchor=tk.W).pack(side=tk.LEFT)
            tk.Label(row, textvariable=v, fg=ACCENT, bg=PANEL,
                     font=("Courier New", 8, "bold")).pack(side=tk.LEFT)

        # ── Bottom buttons ─────────────────────────────────────────
        bot = tk.Frame(frame, bg=PANEL)
        bot.pack(fill=tk.X, padx=12, pady=8, side=tk.BOTTOM)
        self._btn(bot, "↓  EXPORT REPORT",
                  self._export_report).pack(fill=tk.X, pady=2)
        self._btn(bot, "⚡  RUN ANALYSIS",
                  self._run_analysis, danger=True).pack(fill=tk.X, pady=2)

        self._prog_var = tk.DoubleVar(value=0)
        self._prog_lbl = tk.StringVar(value="")
        tk.Label(frame, textvariable=self._prog_lbl, fg=TEXT,
                 bg=PANEL, font=("Courier New", 7)).pack(padx=12, anchor=tk.W)
        sty2 = ttk.Style()
        sty2.configure("green.Horizontal.TProgressbar",
                        troughcolor=BG, background=ACCENT, thickness=4)
        ttk.Progressbar(frame, variable=self._prog_var, maximum=100,
                        style="green.Horizontal.TProgressbar"
                        ).pack(fill=tk.X, padx=12, pady=(0, 4))

        return frame

    def _build_content(self, parent):
        frame = tk.Frame(parent, bg=BG)

        self._banner_frame = tk.Frame(frame, bg=BG)
        self._banner_frame.pack(fill=tk.X, padx=12, pady=(8, 0))

        self._ntfs_lbl = tk.Label(
            frame, text="NTFS: No volume loaded.",
            fg=TEXT, bg=PANEL, font=("Courier New", 8),
            anchor=tk.W, justify=tk.LEFT, padx=8, pady=4)
        self._ntfs_lbl.pack(fill=tk.X, padx=12, pady=4)

        sty = ttk.Style()
        sty.configure("Dark.TNotebook",     background=BG,    borderwidth=0)
        sty.configure("Dark.TNotebook.Tab", background=PANEL, foreground=TEXT,
                       font=("Courier New", 8), padding=[10, 4])
        sty.map("Dark.TNotebook.Tab",
                background=[("selected", BG)],
                foreground=[("selected", ACCENT)])

        nb = ttk.Notebook(frame, style="Dark.TNotebook")
        nb.pack(fill=tk.BOTH, expand=True, padx=12, pady=4)

        # Tab 1 — Treemap
        t1 = tk.Frame(nb, bg=BG)
        nb.add(t1, text="  TREEMAP  ")
        self._treemap = TreemapCanvas(t1, self.analysis, height=320)
        self._treemap.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        # Tab 2 — Entropy Map
        t2 = tk.Frame(nb, bg=BG)
        nb.add(t2, text="  ENTROPY MAP  ")
        self._heatmap_frame = t2

        # Tab 3 — Histogram & Zoom
        t3 = tk.Frame(nb, bg=BG)
        nb.add(t3, text="  HISTOGRAM & ZOOM  ")
        self._hist_frame = tk.Frame(t3, bg=BG)
        self._zoom_frame = tk.Frame(t3, bg=BG)
        self._hist_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._zoom_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Tab 4 — Anomaly Table
        t4 = tk.Frame(nb, bg=BG)
        nb.add(t4, text="  ANOMALIES  ")
        self._build_anomaly_table(t4)

        # Tab 5 — Log
        t5 = tk.Frame(nb, bg=BG)
        nb.add(t5, text="  LOG  ")
        self._log_text = tk.Text(
            t5, bg=PANEL, fg=TEXT, font=("Courier New", 8),
            state=tk.DISABLED, relief=tk.FLAT,
            insertbackground=ACCENT, wrap=tk.WORD)
        sb = tk.Scrollbar(t5, command=self._log_text.yview, bg=PANEL)
        self._log_text.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self._log_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        for tag, fg in [("ok", SAFE), ("warn", WARN), ("err", DANGER),
                        ("info", ACCENT), ("ts", ACCENT3)]:
            self._log_text.tag_config(tag, foreground=fg)

        return frame

    def _build_anomaly_table(self, parent):
        cols = ("OFFSET", "SIZE", "AVG H", "MAX H", "BLOCKS", "TYPE", "CONFIDENCE")
        sty  = ttk.Style()
        sty.configure("Dark.Treeview",
                       background=PANEL, foreground=TEXT,
                       fieldbackground=PANEL, rowheight=20,
                       font=("Courier New", 8))
        sty.configure("Dark.Treeview.Heading",
                       background=BG, foreground=ACCENT,
                       font=("Courier New", 8, "bold"))
        sty.map("Dark.Treeview", background=[("selected", BORDER)])
        self._anom_tree = ttk.Treeview(parent, columns=cols,
                                        show="headings", style="Dark.Treeview")
        for c, w in zip(cols, [110, 70, 60, 60, 60, 130, 80]):
            self._anom_tree.heading(c, text=c)
            self._anom_tree.column(c, width=w, minwidth=w, anchor=tk.CENTER)
        sb = tk.Scrollbar(parent, command=self._anom_tree.yview, bg=PANEL)
        self._anom_tree.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self._anom_tree.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

    # ── HELPERS ────────────────────────────────────────────────────

    def _section(self, parent, title):
        tk.Label(parent, text=title, fg=ACCENT, bg=PANEL,
                 font=("Courier New", 8, "bold")
                 ).pack(anchor=tk.W, padx=12, pady=(10, 2))
        tk.Frame(parent, bg=BORDER, height=1).pack(fill=tk.X, padx=12)

    def _btn(self, parent, text, cmd, accent=False, danger=False):
        fg  = DANGER if danger else (ACCENT if accent else TEXT)
        bdr = DANGER if danger else (ACCENT if accent else BORDER)
        return tk.Button(
            parent, text=text, command=cmd,
            fg=fg, bg=PANEL, activeforeground=BG,
            activebackground=fg, relief=tk.FLAT,
            font=("Courier New", 8, "bold"), bd=1,
            highlightthickness=1, highlightbackground=bdr,
            cursor="hand2", padx=6, pady=4)

    def _log(self, msg, tag="info"):
        ts = datetime.now().strftime("%H:%M:%S")
        self._log_text.configure(state=tk.NORMAL)
        self._log_text.insert(tk.END, f"[{ts}] ", "ts")
        self._log_text.insert(tk.END, msg + "\n", tag)
        self._log_text.see(tk.END)
        self._log_text.configure(state=tk.DISABLED)

    def _set_progress(self, pct, msg):
        self._prog_var.set(pct)
        self._prog_lbl.set(msg)

    # ── USB METHODS ────────────────────────────────────────────────

    def _list_usb_devices(self):
        devices = []
        system  = platform.system()

        if system == "Windows":
            import string, ctypes
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for letter in string.ascii_uppercase:
                if bitmask & 1:
                    path  = f"{letter}:\\"
                    dtype = ctypes.windll.kernel32.GetDriveTypeW(path)
                    if dtype == 2:   # DRIVE_REMOVABLE
                        try:
                            total = ctypes.c_ulonglong(0)
                            ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                                path, None, ctypes.byref(total), None)
                            label = f"{letter}: [USB]  {fmt_bytes(total.value)}"
                        except Exception:
                            label = f"{letter}: [USB]"
                        devices.append((label, f"\\\\.\\{letter}:"))
                bitmask >>= 1

        elif system == "Linux":
            try:
                out  = subprocess.check_output(
                    ["lsblk", "-o", "NAME,SIZE,RM,TYPE,MOUNTPOINT", "-J"],
                    stderr=subprocess.DEVNULL)
                data = json.loads(out)
                for dev in data.get("blockdevices", []):
                    if dev.get("rm") in (True, "1", 1):
                        name = dev["name"]; size = dev.get("size", "?")
                        if dev.get("type", "") in ("disk", "part"):
                            devices.append(
                                (f"/dev/{name}  [{size}] USB disk",
                                 f"/dev/{name}"))
                        for child in dev.get("children", []):
                            cn = child["name"]; cs = child.get("size", "?")
                            devices.append(
                                (f"/dev/{cn}  [{cs}] partition",
                                 f"/dev/{cn}"))
            except Exception as ex:
                self._log(f"lsblk error: {ex}", "warn")

        elif system == "Darwin":
            try:
                import plistlib
                out = subprocess.check_output(
                    ["diskutil", "list", "-plist", "external"],
                    stderr=subprocess.DEVNULL)
                pl = plistlib.loads(out)
                for disk in pl.get("AllDisksAndPartitions", []):
                    did  = disk.get("DeviceIdentifier", "")
                    size = disk.get("Size", 0)
                    devices.append(
                        (f"/dev/r{did}  [{fmt_bytes(size)}] USB",
                         f"/dev/r{did}"))
                    for part in disk.get("Partitions", []):
                        pid  = part.get("DeviceIdentifier", "")
                        psz  = part.get("Size", 0)
                        devices.append(
                            (f"/dev/r{pid}  [{fmt_bytes(psz)}] partition",
                             f"/dev/r{pid}"))
            except Exception as ex:
                self._log(f"diskutil error: {ex}", "warn")

        return devices

    def _read_usb_device(self, device_path: str,
                         max_bytes: int = 64 * 1024 * 1024) -> bytes:
        try:
            with open(device_path, "rb", buffering=0) as f:
                return f.read(max_bytes)
        except PermissionError:
            hint = ("Run as Administrator."
                    if platform.system() == "Windows"
                    else "Run with sudo, or: sudo usermod -aG disk $USER")
            raise PermissionError(
                f"Permission denied: {device_path}\n{hint}")

    def _refresh_usb(self):
        if hasattr(self, '_log_text'):
            self._log("Scanning for USB devices…", "info")
        devices      = self._list_usb_devices()
        self._usb_map = {label: path for label, path in devices}
        labels        = list(self._usb_map.keys()) or ["— no USB devices found —"]
        self._usb_dropdown["values"] = labels
        self._usb_dropdown.set(labels[0])
        if hasattr(self, '_log_text'):
            self._log(f"Found {len(devices)} USB device(s).",
                    "ok" if devices else "warn")
    def _scan_usb(self):
        label = self._usb_var.get()
        if label.startswith("—"):
            messagebox.showwarning("No Device",
                                   "Select a USB device first.\n"
                                   "Click ↻ REFRESH to detect devices.")
            return
        device_path = self._usb_map.get(label)
        if not device_path:
            return
        self._log(f"Reading USB: {device_path}", "info")
        self._status_var.set("READING USB…")

        def worker():
            try:
                data = self._read_usb_device(device_path)
                sz   = len(data)
                self.after(0, lambda: self._usb_size_lbl.config(
                    text=f"Read: {fmt_bytes(sz)}"))
                self.after(0, lambda: self._log(
                    f"USB read complete: {fmt_bytes(sz)}", "ok"))
                self.after(0, lambda: self._run_analysis_from_bytes(data))
            except PermissionError as e:
                self.after(0, lambda: self._log(str(e), "err"))
                self.after(0, lambda: messagebox.showerror(
                    "Permission Denied", str(e)))
            except Exception as e:
                self.after(0, lambda: self._log(
                    f"USB read error: {e}", "err"))

        threading.Thread(target=worker, daemon=True).start()

    # ── FILE / SIMULATE ────────────────────────────────────────────

    def _open_file(self):
        path = filedialog.askopenfilename(
            title="Open Disk Image",
            filetypes=[
                ("Disk Images", "*.img *.raw *.dd *.bin *.iso *.vc *.vhd"),
                ("All files", "*.*")])
        if not path:
            return
        self.file_path = path
        size = os.path.getsize(path)
        self._file_lbl.config(
            text=f"{os.path.basename(path)}\n{fmt_bytes(size)}")
        self._log(f"Loaded: {os.path.basename(path)} ({fmt_bytes(size)})", "ok")
        self._status_var.set("VOLUME LOADED")
        self._run_analysis()

    def _simulate(self):
        self.file_path = None
        self._file_lbl.config(text="[Simulated VeraCrypt volume]")
        self._log("Generating simulated VeraCrypt volume…", "info")
        self._status_var.set("SIMULATED VOLUME")
        self._run_analysis(simulate=True)

    # ── ANALYSIS ───────────────────────────────────────────────────

    def _run_analysis(self, simulate=False):
        if self._scan_thread and self._scan_thread.is_alive():
            return

        def worker():
            try:
                if simulate:
                    data = self._gen_sim_volume()
                elif self.file_path:
                    MAX = 64 * 1024 * 1024
                    with open(self.file_path, "rb") as f:
                        data = f.read(MAX)
                    if os.path.getsize(self.file_path) > MAX:
                        self.after(0, lambda: self._log(
                            "File truncated to 64 MB.", "warn"))
                else:
                    return
                self.after(0, lambda: self._run_analysis_from_bytes(data))
            except Exception as ex:
                self.after(0, lambda: self._log(f"ERROR: {ex}", "err"))

        self._scan_thread = threading.Thread(target=worker, daemon=True)
        self._scan_thread.start()

    def _run_analysis_from_bytes(self, data: bytes):
        if self._scan_thread and self._scan_thread.is_alive():
            return

        def worker():
            try:
                ntfs       = NTFSParser(data[:512])
                block_size = (ntfs.block_size
                              if ntfs.block_size and ntfs.block_size >= 512
                              else 4096)
                thresh     = self._thresh_var.get() / 10
                noise      = self._noise_var.get()
                trim       = self._apply_trim.get()

                self.after(0, lambda: self._log(
                    f"Block size: {block_size} B | NTFS valid: {ntfs.valid}",
                    "info"))
                self.after(0, lambda: self._ntfs_lbl.config(
                    text=ntfs.summary(), justify=tk.LEFT, anchor=tk.W))

                self.analysis.run(
                    data, block_size, thresh, noise, trim,
                    progress_cb=lambda p, m: self.after(
                        0, lambda p=p, m=m: self._set_progress(p, m)))
                self.after(0, self._update_ui)
            except Exception as ex:
                self.after(0, lambda: self._log(f"ERROR: {ex}", "err"))

        self._scan_thread = threading.Thread(target=worker, daemon=True)
        self._scan_thread.start()

    # ── UPDATE UI ──────────────────────────────────────────────────

    def _update_ui(self):
        a   = self.analysis
        avg = (sum(b["entropy"] for b in a.blocks) / len(a.blocks)
               if a.blocks else 0)

        self._stat_vars["Blocks"].set(str(len(a.blocks)))
        self._stat_vars["Anomalies"].set(str(len(a.anomaly_regions)))
        self._stat_vars["Avg Entropy"].set(f"{avg:.4f}")
        self._stat_vars["TRIM Zones"].set(str(len(a.trim_zones)))
        self._stat_vars["HV Candidates"].set(str(len(a.hidden_vol_cands)))

        for w in self._banner_frame.winfo_children():
            w.destroy()
        if a.trim_zones:
            tk.Label(
                self._banner_frame,
                text=(f"⚠  {len(a.trim_zones)} TRIM ZONE(S) "
                      f"— SSD artifact: zeroed unallocated space"),
                fg=WARN, bg="#1a1500",
                font=("Courier New", 8), padx=8, pady=4
            ).pack(fill=tk.X, pady=2)
        if a.hidden_vol_cands:
            tk.Label(
                self._banner_frame,
                text=(f"◈  {len(a.hidden_vol_cands)} HIDDEN VOLUME CANDIDATE(S)"
                      f" — High-entropy island bounded by TRIM zones"),
                fg="#c4a0ff", bg="#0d0820",
                font=("Courier New", 8, "bold"), padx=8, pady=4
            ).pack(fill=tk.X, pady=2)

        # Treemap
        self._treemap.analysis = a
        self._treemap.render()

        # Entropy heatmap
        for w in self._heatmap_frame.winfo_children():
            w.destroy()
        fc = FigureCanvasTkAgg(make_entropy_figure(a),
                               master=self._heatmap_frame)
        fc.draw()
        fc.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Histogram
        for w in self._hist_frame.winfo_children():
            w.destroy()
        fc2 = FigureCanvasTkAgg(make_histogram_figure(a),
                                master=self._hist_frame)
        fc2.draw()
        fc2.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Zone zoom
        for w in self._zoom_frame.winfo_children():
            w.destroy()
        fc3 = FigureCanvasTkAgg(make_zone_figure(a),
                                master=self._zoom_frame)
        fc3.draw()
        fc3.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Anomaly table
        for row in self._anom_tree.get_children():
            self._anom_tree.delete(row)
        for r in a.anomaly_regions:
            hv   = next((h for h in a.hidden_vol_cands
                         if h["start_block"] == r["start_block"]), None)
            t    = "HIDDEN VOL" if hv else "ANOMALY"
            conf = (hv["confidence"] if hv
                    else min(int(50 + r["avg_entropy"] * 5), 99))
            tag  = "hv" if hv else "anom"
            self._anom_tree.insert("", tk.END, tags=(tag,), values=(
                f"0x{r['start']:08X}",
                fmt_bytes(r["size"]),
                f"{r['avg_entropy']:.4f}",
                f"{r['max_entropy']:.4f}",
                r["block_count"],
                t,
                f"{conf}%",
            ))
        self._anom_tree.tag_configure(
            "hv",   background="#0d0820", foreground="#c4a0ff")
        self._anom_tree.tag_configure(
            "anom", background="#1a0308", foreground=DANGER)

        self._status_var.set(
            "⚠ HIDDEN VOL DETECTED" if a.hidden_vol_cands else "SCAN COMPLETE")

        self._log(
            f"Analysis complete — {len(a.blocks)} blocks | "
            f"{len(a.anomaly_regions)} anomalies | "
            f"{len(a.hidden_vol_cands)} HV candidates", "ok")
        for hv in a.hidden_vol_cands:
            self._log(
                f"  HV @ 0x{hv['start']:08X}–0x{hv['end']:08X}  "
                f"({fmt_bytes(hv['size'])})  "
                f"H={hv['avg_entropy']:.4f}  conf={hv['confidence']}%  "
                f"[{', '.join(hv['reasons'])}]", "err")

    # ── SIMULATION ─────────────────────────────────────────────────

    def _gen_sim_volume(self):
        import random
        SIZE = 4 * 1024 * 1024
        buf  = bytearray(SIZE)

        # Fake NTFS BPB
        buf[3:11] = b"NTFS    "
        struct.pack_into("<H", buf, 11, 512)
        struct.pack_into("B",  buf, 13, 8)
        struct.pack_into("<Q", buf, 40, SIZE // 512)

        rng = random.Random(42)

        # Header padding
        for i in range(1024, 65536):
            buf[i] = (i * 7 + 13) % 256

        # Outer vol — filesystem (mixed low entropy)
        for i in range(65536, 200000):
            buf[i] = 0 if rng.random() < 0.3 else rng.randint(0, 127)
        for i in range(200000, 700000):
            buf[i] = rng.randint(0, 199)

        # TRIM zone 700K–1.2M  (zeros, bytearray default)

        # Hidden volume — max entropy (os.urandom = real random)
        buf[1_200_000:2_800_000] = os.urandom(1_600_000)

        # TRIM zone 2.8M–3.5M  (zeros)

        # More outer data
        for i in range(3_500_000, 3_900_000):
            buf[i] = rng.randint(0, 179)

        # Backup header
        for i in range(SIZE - 1024, SIZE):
            buf[i] = rng.randint(0, 255)

        return bytes(buf)

    # ── EXPORT ─────────────────────────────────────────────────────

    def _export_report(self):
        if not self.analysis.blocks:
            messagebox.showwarning("No Data", "Run analysis first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text report", "*.txt"), ("JSON", "*.json")],
            title="Export Report")
        if not path:
            return

        a   = self.analysis
        avg = sum(b["entropy"] for b in a.blocks) / len(a.blocks)

        if path.endswith(".json"):
            with open(path, "w") as f:
                json.dump({
                    "generated":             datetime.now().isoformat(),
                    "volume_size":           a.raw_size,
                    "block_size":            a.block_size,
                    "ntfs_valid":            a.ntfs.valid if a.ntfs else False,
                    "blocks_analyzed":       len(a.blocks),
                    "avg_entropy":           avg,
                    "trim_zones":            a.trim_zones,
                    "anomalies":             a.anomaly_regions,
                    "hidden_vol_candidates": a.hidden_vol_cands,
                }, f, indent=2)
        else:
            lines = [
                "DISKENTROPY FORENSIC REPORT",
                "=" * 60,
                f"Generated    : {datetime.now().isoformat()}",
                f"Volume size  : {fmt_bytes(a.raw_size)}",
                f"Block size   : {a.block_size} B",
                f"NTFS valid   : {a.ntfs.valid if a.ntfs else 'N/A'}",
                "",
                "NTFS DETAILS", "─" * 40,
                a.ntfs.summary() if a.ntfs else "N/A",
                "",
                f"TRIM ZONES ({len(a.trim_zones)})", "─" * 40,
            ]
            for z in a.trim_zones:
                lines.append(
                    f"  0x{z['start']:08X} – 0x{z['end']:08X}"
                    f"  ({fmt_bytes(z['end'] - z['start'])})")
            lines += [
                "", f"ANOMALOUS REGIONS ({len(a.anomaly_regions)})", "─" * 40]
            for r in a.anomaly_regions:
                lines.append(
                    f"  0x{r['start']:08X}"
                    f"  size={fmt_bytes(r['size'])}"
                    f"  H_avg={r['avg_entropy']:.4f}"
                    f"  blocks={r['block_count']}")
            lines += [
                "", f"HIDDEN VOLUME CANDIDATES ({len(a.hidden_vol_cands)})",
                "─" * 40]
            for hv in a.hidden_vol_cands:
                lines += [
                    f"  START       : 0x{hv['start']:08X}",
                    f"  END         : 0x{hv['end']:08X}",
                    f"  SIZE        : {fmt_bytes(hv['size'])}",
                    f"  AVG ENTROPY : {hv['avg_entropy']:.6f}",
                    f"  CONFIDENCE  : {hv['confidence']}%",
                    f"  INDICATORS  : {', '.join(hv['reasons'])}",
                    "",
                ]
            with open(path, "w") as f:
                f.write("\n".join(lines))

        self._log(f"Report exported: {os.path.basename(path)}", "ok")
        messagebox.showinfo("Exported", f"Report saved:\n{path}")


# ──────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = App()
    app.mainloop()
