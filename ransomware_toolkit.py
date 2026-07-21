#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows Ransomware Detection Toolkit - Linux / cross-platform edition.

One self-contained Python 3 script (standard library only - no pip installs).
It shares the SAME data/ folder as the PowerShell version, so updating the IOC
lists updates both. Read-only and non-destructive: it never deletes, changes or
quarantines your files (only its own reports and, in watch mode, its own
canaries which it cleans up again).

Modes (menu, or --mode):
  quick   - scan user home folders (Desktop, Documents, Downloads, ...)
  full    - scan the whole filesystem (skips /proc /sys /dev ...); root advised
  custom  - scan paths you pass with --path
  watch   - real-time early warning (canary decoys + change-burst, polling)
  update  - fetch the latest ransomware extensions from update-sources.txt

Detection layers (single pass):
  1 extension match   (data/extensions.txt curated = high, extensions-auto.txt
                       community = low, only via entropy)
  2 ransom-note name  (data/ransom-note-names.txt)
  3 ransom-note text  (data/note-keywords.txt)
  4 Shannon entropy   (likely-encrypted; skips naturally high-entropy formats)
  5 mass-change / mass-rename / note-spread heuristics

Usage:
  ./ransomware_toolkit.py                 # interactive menu
  ./ransomware_toolkit.py --mode quick --open-report
  ./ransomware_toolkit.py --mode custom --path /srv/share /mnt/data
  ./ransomware_toolkit.py --mode watch --path /home/me/Documents
  ./ransomware_toolkit.py --mode update
"""

import os
import sys
import re
import math
import json
import time
import html
import uuid
import shutil
import fnmatch
import socket
import signal
import getpass
import platform
import argparse
import subprocess
import webbrowser
import urllib.request
from collections import Counter
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VERSION = "3.2-py"

# Colours (disabled when not a TTY)
_TTY = sys.stdout.isatty()
def _c(code, s):
    return f"\033[{code}m{s}\033[0m" if _TTY else s
def info(m):  print(_c("90", "[*] ") + m)
def ok(m):    print(_c("32", "[+] " + m))
def warn(m):  print(_c("33", "[!] " + m))
def bad(m):   print(_c("31", "[X] " + m))

# Formats that are high-entropy by design -> never flagged as "encrypted"
NATURAL_HIGH_ENTROPY = set(x.lower() for x in [
    ".zip", ".7z", ".rar", ".gz", ".bz2", ".xz", ".tar", ".tgz", ".cab", ".jar", ".apk", ".z", ".lz4", ".zst", ".br",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tiff", ".tif", ".heic", ".heif", ".ico", ".jfif",
    ".cr2", ".nef", ".arw", ".dng", ".raw", ".orf", ".rw2", ".raf", ".srw", ".psd", ".psb", ".ai", ".eps", ".indd",
    ".mp3", ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flac", ".aac", ".ogg", ".webm", ".m4a", ".m4v", ".opus", ".wma",
    ".3gp", ".mpg", ".mpeg", ".ts", ".m2ts", ".vob",
    ".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".epub",
    ".exe", ".dll", ".msi", ".iso", ".dmg", ".pkg", ".deb", ".rpm", ".wim", ".esd",
    ".vhd", ".vhdx", ".vmdk", ".vdi", ".ova", ".bin", ".dat", ".db", ".sqlite", ".mdb", ".accdb",
    ".gpg", ".pgp", ".asc", ".pfx", ".p12", ".pem", ".crt", ".cer", ".kdbx", ".jks", ".keystore",
    ".crx", ".nupkg", ".whl", ".torrent", ".so", ".o", ".a", ".ko", ".dylib",
    ".pack", ".wasm", ".pyc", ".class", ".node", ".car", ".nib", ".icns",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".pb", ".glb", ".gltf", ".fbx", ".blend", ".3mf", ".f3d", ".usdz", ".stl",
    ".h5", ".pt", ".pth", ".onnx", ".tflite", ".safetensors", ".gguf", ".ggml", ".pmml",
    ".numbers", ".pages", ".key",
])
TEXT_EXTENSIONS = set(x.lower() for x in
    [".txt", ".html", ".htm", ".hta", ".rtf", ".md", ".log", ".nfo", ".readme", ".conf", ".cfg", ".sh"])

# Definitive ransom-note phrases. A text file with NO note-like name needs >=2 of
# these to be flagged, so security docs that merely mention "bitcoin"/"private key"
# do not false-positive.
STRONG_KEYWORDS = set([
    "your files have been encrypted", "all your files are encrypted", "your files are encrypted",
    "files have been encrypted", "have been encrypted", "we have encrypted",
    "decrypt your files", "decrypt all your files", "buy decryptor", "buy the decrypt",
    "your network has been", "your data has been", "we have downloaded", "data has been stolen",
    "restore your files", "recover your files", "pay the ransom", "you have 72 hours", "you have 48 hours",
])

# Pseudo / virtual filesystems to skip during a full scan
PRUNE_DIRS = {"/proc", "/sys", "/dev", "/run", "/snap", "/var/run", "/var/lock",
              "/sys/kernel", "/proc/sys"}

IDENTIFY_URLS_DEFAULT = {
    "idRansomware": "https://id-ransomware.malwarehunterteam.com/",
    "cryptoSheriff": "https://www.nomoreransom.org/crypto-sheriff.php",
}

# ---------------------------------------------------------------------------
# IOC loading
# ---------------------------------------------------------------------------
def _wildcard_re(pattern):
    return re.compile(fnmatch.translate(pattern), re.IGNORECASE)

def load_ioc(data_dir):
    ext_exact, ext_auto = set(), set()
    ext_wild, note_re, keywords = [], [], []

    ext_file  = os.path.join(data_dir, "extensions.txt")
    auto_file = os.path.join(data_dir, "extensions-auto.txt")
    note_file = os.path.join(data_dir, "ransom-note-names.txt")
    kw_file   = os.path.join(data_dir, "note-keywords.txt")

    if os.path.isfile(ext_file):
        for raw in _read_lines(ext_file):
            l = raw.strip()
            if not l or l.startswith("#"):
                continue
            if "*" in l:
                ext_wild.append(_wildcard_re(l))
            else:
                ext_exact.add(l.lower())
    if os.path.isfile(auto_file):
        for raw in _read_lines(auto_file):
            l = raw.strip().lower()
            if not l or l.startswith("#") or "*" in l:
                continue
            if l not in ext_exact:
                ext_auto.add(l)
    if os.path.isfile(note_file):
        for raw in _read_lines(note_file):
            l = raw.strip()
            if not l or l.startswith("#"):
                continue
            note_re.append(_wildcard_re(l))
    if os.path.isfile(kw_file):
        for raw in _read_lines(kw_file):
            l = raw.strip()
            if not l or l.startswith("#"):
                continue
            keywords.append(l.lower())

    return {"exact": ext_exact, "auto": ext_auto, "wild": ext_wild,
            "notes": note_re, "keywords": keywords}

def load_families(data_dir):
    path = os.path.join(data_dir, "families.json")
    res = {"by_ext": {}, "by_note": {}, "families": [], "urls": IDENTIFY_URLS_DEFAULT}
    if not os.path.isfile(path):
        return res
    try:
        with open(path, "r", encoding="utf-8") as f:
            j = json.load(f)
    except Exception:
        return res
    res["urls"] = j.get("identifyUrls", IDENTIFY_URLS_DEFAULT)
    res["families"] = j.get("families", [])
    for fam in res["families"]:
        for e in fam.get("extensions", []):
            res["by_ext"][e.lower()] = fam
        for n in fam.get("notes", []):
            res["by_note"][n.lower()] = fam
    return res

def _read_lines(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read().splitlines()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def file_entropy(path, sample=32768):
    try:
        with open(path, "rb") as f:
            data = f.read(sample)
    except OSError:
        return -1.0
    if not data:
        return -1.0
    n = len(data)
    ent = 0.0
    for c in Counter(data).values():
        p = c / n
        ent -= p * math.log2(p)
    return round(ent, 3)

def read_text_head(path, limit=200 * 1024):
    try:
        with open(path, "rb") as f:
            return f.read(limit).decode("utf-8", errors="ignore").lower()
    except OSError:
        return ""

def hostname():
    try:
        return socket.gethostname() or "host"
    except Exception:
        return "host"

def human_bytes(n):
    return n / (1024 ** 3)

def _run(cmd, timeout=4):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (out.stdout or "").strip()
    except Exception:
        return ""

def system_inventory():
    """Best-effort machine inventory. Every field is guarded; gathering it must
    never break a scan. Handy when the same scan is run across many devices."""
    inv = {}
    try: inv["hostname"] = socket.gethostname()
    except Exception: inv["hostname"] = os.environ.get("COMPUTERNAME") or "unknown"
    try:
        fq = socket.getfqdn()
        inv["fqdn"] = "" if (not fq or ".arpa" in fq or fq == inv["hostname"]) else fq
    except Exception:
        inv["fqdn"] = ""
    inv["os"] = platform.system()
    inv["os_release"] = platform.release()
    inv["os_version"] = platform.version()
    inv["platform"] = platform.platform()
    inv["arch"] = platform.machine()
    try: inv["user"] = getpass.getuser()
    except Exception: inv["user"] = os.environ.get("USER") or os.environ.get("USERNAME") or "?"
    inv["domain"] = os.environ.get("USERDOMAIN") or os.environ.get("USERDNSDOMAIN") or ""
    inv["cpu_cores"] = os.cpu_count() or 0
    inv["cpu"] = platform.processor() or ""
    inv["scan_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # RAM (bytes)
    ram = 0
    try:
        ram = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except Exception:
        try:
            import ctypes
            class MS(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
            m = MS(); m.dwLength = ctypes.sizeof(MS)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))  # type: ignore
            ram = m.ullTotalPhys
        except Exception:
            ram = 0
    inv["ram_gb"] = round(ram / (1024 ** 3), 1) if ram else 0

    # Model / serial (best-effort, OS-specific)
    inv["model"] = ""; inv["serial"] = ""
    sysname = platform.system()
    try:
        if sysname == "Darwin":
            hw = _run(["system_profiler", "SPHardwareDataType"])
            for line in hw.splitlines():
                s = line.strip()
                if s.startswith("Model Name") or s.startswith("Model Identifier") and not inv["model"]:
                    inv["model"] = s.split(":", 1)[1].strip()
                if s.startswith("Serial Number"):
                    inv["serial"] = s.split(":", 1)[1].strip()
        elif sysname == "Linux":
            for f, k in (("/sys/class/dmi/id/product_name", "model"),
                         ("/sys/class/dmi/id/product_serial", "serial")):
                try:
                    with open(f) as fh:
                        inv[k] = fh.read().strip()
                except Exception:
                    pass
        elif sysname == "Windows":
            inv["model"] = _run(["wmic", "computersystem", "get", "model"]).replace("Model", "").strip()
            inv["serial"] = _run(["wmic", "bios", "get", "serialnumber"]).replace("SerialNumber", "").strip()
    except Exception:
        pass

    # Disks (mount -> total/free GB), deduped by underlying device + size so
    # Time Machine / APFS snapshots don't flood the list
    disks = []
    try:
        seen_dev, seen_size = set(), set()
        candidates = ["/"] if sysname != "Windows" else [f"{c}:\\" for c in "CDEFG"]
        if sysname != "Windows":
            for base in ("/Volumes", "/mnt", "/media"):
                if os.path.isdir(base):
                    for d in os.scandir(base):
                        if d.is_dir(follow_symlinks=False) and "timemachine" not in d.name.lower():
                            candidates.append(d.path)
        for mp in candidates:
            try:
                if not os.path.exists(mp):
                    continue
                dev = os.stat(mp).st_dev
                if dev in seen_dev:
                    continue
                seen_dev.add(dev)
                du = shutil.disk_usage(mp)
                key = (round(du.total / 1e9), round(du.free / 1e9))
                if key in seen_size:
                    continue
                seen_size.add(key)
                disks.append({"mount": mp, "total_gb": round(du.total / (1024 ** 3), 1),
                              "free_gb": round(du.free / (1024 ** 3), 1)})
            except Exception:
                pass
    except Exception:
        pass
    inv["disks"] = disks[:8]

    # Network: IPs (drop loopback + link-local) + MAC
    ips = []
    try:
        for ai in socket.getaddrinfo(socket.gethostname(), None):
            ip = ai[4][0]
            if (ip and ip not in ips and not ip.startswith("127.")
                    and ip != "::1" and not ip.lower().startswith("fe80")):
                ips.append(ip)
    except Exception:
        pass
    try:
        if not ips:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80)); ips.append(s.getsockname()[0]); s.close()
    except Exception:
        pass
    inv["ips"] = ips
    try:
        mac = uuid.getnode()
        inv["mac"] = ":".join(f"{(mac >> e) & 0xff:02x}" for e in range(40, -1, -8))
    except Exception:
        inv["mac"] = ""

    # Uptime / boot (best-effort)
    inv["uptime"] = ""
    try:
        if sysname == "Linux":
            with open("/proc/uptime") as fh:
                secs = float(fh.read().split()[0])
                inv["uptime"] = f"{int(secs // 86400)}d {int((secs % 86400) // 3600)}h"
        elif sysname == "Darwin":
            bt = _run(["sysctl", "-n", "kern.boottime"])
            m = re.search(r"sec\s*=\s*(\d+)", bt)
            if m:
                secs = time.time() - int(m.group(1))
                inv["uptime"] = f"{int(secs // 86400)}d {int((secs % 86400) // 3600)}h"
    except Exception:
        pass

    return inv

def iter_home_dirs():
    roots = []
    for base in ("/home", "/Users", "/root"):
        if os.path.isdir(base):
            if base == "/root":
                roots.append(base)
            else:
                try:
                    for d in os.scandir(base):
                        if d.is_dir(follow_symlinks=False):
                            roots.append(d.path)
                except OSError:
                    pass
    home = os.path.expanduser("~")
    if home and home not in roots and os.path.isdir(home):
        roots.append(home)
    return roots

def resolve_targets(mode, paths):
    if paths:
        return [p for p in paths if os.path.exists(p)]
    if mode == "full":
        return ["/"]
    # quick: user folders
    targets = []
    for h in iter_home_dirs():
        for sub in ("Desktop", "Documents", "Downloads", "Pictures", "Videos", "Music"):
            p = os.path.join(h, sub)
            if os.path.isdir(p):
                targets.append(p)
        # also the home root itself if it has no standard subfolders
    if not targets:
        targets = [os.path.expanduser("~")]
    return targets

def walk_files(root, prune=None):
    """Yield file paths under root, single pass, pruning pseudo-fs and symlinked dirs."""
    prune = prune or set()
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False,
                                                onerror=lambda e: None):
        # prune pseudo filesystems and symlinked dirs
        keep = []
        for d in dirnames:
            full = os.path.join(dirpath, d)
            if full in prune or any(full == p or full.startswith(p + os.sep) for p in prune):
                continue
            if os.path.islink(full):
                continue
            keep.append(d)
        dirnames[:] = keep
        for name in filenames:
            yield os.path.join(dirpath, name)

# ---------------------------------------------------------------------------
# SCAN
# ---------------------------------------------------------------------------
def run_scan(cfg, targets, mode_label):
    started = time.time()
    print()
    print(_c("36", "=" * 64))
    print(_c("36", "  Ransomware SCAN  -  read-only, results saved next to this tool"))
    print(_c("36", "=" * 64))
    is_root = (hasattr(os, "geteuid") and os.geteuid() == 0)
    inv = system_inventory()
    info(f"Device        : {inv['hostname']}  ({inv.get('model') or inv['os']} {inv['os_release']}, "
         f"{inv.get('ram_gb','?')} GB RAM)  user {inv['user']}")
    info(f"Mode          : {mode_label}")
    info("Privilege     : " + ("root" if is_root else "normal user (some system files may be skipped)"))
    info(f"Report folder : {cfg['output_dir']}")

    ioc = load_ioc(cfg["data_dir"])
    fam_db = load_families(cfg["data_dir"])
    info("IOC loaded    : {} curated (+{} community) extensions, {} note patterns, {} keywords".format(
        len(ioc["exact"]) + len(ioc["wild"]), len(ioc["auto"]), len(ioc["notes"]), len(ioc["keywords"])))
    info("Targets       : " + " ; ".join(targets))
    print()

    os.makedirs(cfg["output_dir"], exist_ok=True)
    recent_cutoff = started - abs(cfg["recent_hours"]) * 3600
    max_bytes = cfg["max_mb"] * 1024 * 1024

    findings = []
    dir_stats = {}      # dir -> {"total":int,"recent":int,"ext":Counter}
    note_spread = {}    # note-name -> set(dirs)
    files_seen = 0
    bytes_seen = 0
    last_tick = time.time()

    prune = PRUNE_DIRS if mode_label == "Full" else set()
    # never scan the toolkit's own folder (its README/IOC lists/reports legitimately
    # contain ransomware keywords and extensions -> would self-false-positive)
    skip_prefixes = tuple(sorted(set(
        os.path.abspath(x) + os.sep for x in (SCRIPT_DIR, cfg["data_dir"], cfg["output_dir"]))))

    for target in targets:
        info(f"Scanning: {target}")
        base = target if os.path.isdir(target) else os.path.dirname(target)
        walker = walk_files(target, prune) if os.path.isdir(target) else iter([target])
        for path in walker:
            if path.startswith(skip_prefixes):
                continue
            try:
                st = os.stat(path, follow_symlinks=False)
            except OSError:
                continue
            if not (st.st_mode & 0o170000 == 0o100000):  # regular files only
                continue
            files_seen += 1
            size = st.st_size
            bytes_seen += size
            name = os.path.basename(path)
            ext = os.path.splitext(name)[1]
            ext_low = ext.lower()
            d = os.path.dirname(path)

            now = time.time()
            if now - last_tick >= 0.5 and _TTY:
                sys.stdout.write("\r\033[K" + _c("90", f"    {files_seen:,} files  |  {len(findings)} findings  |  {path[:70]}"))
                sys.stdout.flush()
                last_tick = now

            ds = dir_stats.get(d)
            if ds is None:
                ds = {"total": 0, "recent": 0, "susp": 0, "ext": Counter()}
                dir_stats[d] = ds
            ds["total"] += 1
            if st.st_mtime >= recent_cutoff:
                ds["recent"] += 1
            if ext_low:
                ds["ext"][ext_low] += 1

            # Layer 1: extension
            ext_hit = bool(ext_low and ext_low in ioc["exact"])
            if not ext_hit:
                for rx in ioc["wild"]:
                    if rx.match(name):
                        ext_hit = True
                        break
            auto_hit = bool(not ext_hit and ext_low and ext_low in ioc["auto"])
            susp_file = ext_hit
            if ext_hit:
                findings.append(_finding("High", "Extension", path,
                    f"Known ransomware extension '{ext}'", mtime=st.st_mtime))

            # Layer 2: ransom-note name
            note_hit = any(rx.match(name) for rx in ioc["notes"])

            # Layer 3: ransom-note content
            is_text = ext_low in TEXT_EXTENSIONS
            small = 0 < size <= 200 * 1024
            if small and (note_hit or is_text):
                content = read_text_head(path)
                kw_hits = [k for k in ioc["keywords"] if k in content]
                strong = [k for k in kw_hits if k in STRONG_KEYWORDS]
                if note_hit and kw_hits:
                    findings.append(_finding("High", "RansomNote", path,
                        "Ransom note (name + content). Keywords: " + ", ".join(kw_hits[:4]), mtime=st.st_mtime))
                    note_spread.setdefault(name.lower(), set()).add(d)   # only confirmed notes count for spread
                elif note_hit:
                    findings.append(_finding("Medium", "RansomNote", path,
                        "File name matches a ransom-note pattern (no keyword match)", mtime=st.st_mtime))
                elif len(strong) >= 2:
                    findings.append(_finding("Medium", "RansomNote", path,
                        "Text file with ransom-note wording. Keywords: " + ", ".join(strong[:4]), mtime=st.st_mtime))

            # Layer 4: entropy is a CONFIRMATION signal for the low-confidence
            # community list only. Curated extensions are already flagged by name;
            # a bare high-entropy file with an ordinary/odd extension (git objects,
            # fonts, binaries, media) is NOT ransomware on its own.
            if (auto_hit and not cfg["no_entropy"] and 1024 <= size <= max_bytes
                    and ext_low not in NATURAL_HIGH_ENTROPY):
                ent = file_entropy(path)
                if ent >= cfg["entropy_threshold"]:
                    susp_file = True
                    findings.append(_finding("High", "Encrypted", path,
                        f"Community-listed extension '{ext}' + high entropy {ent}/8.0 - likely encrypted",
                        entropy=ent, mtime=st.st_mtime))

            # count recently-modified SUSPICIOUS files per folder (for mass-change)
            if susp_file and st.st_mtime >= recent_cutoff:
                ds["susp"] += 1

    if _TTY:
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()

    # Layer 5: post-pass heuristics
    for d, ds in dir_stats.items():
        # Mass-change counts only recently-modified SUSPICIOUS files, so ordinary busy
        # folders (downloads, builds, active projects) no longer false-positive.
        if ds["susp"] >= 10:
            findings.append(_finding("High", "MassChange", d,
                f"{ds['susp']} recently-modified suspicious/encrypted files in this folder "
                f"(active encryption?)", mtime=recent_cutoff))
        # Mass-rename only fires when a hand-vetted ransomware extension dominates a
        # folder - a source-code (.ts) or photo (.heic) folder never triggers it.
        if ds["total"] >= 12:
            for e, cnt in ds["ext"].items():
                if e not in ioc["exact"]:
                    continue
                share = cnt / ds["total"]
                if share >= 0.6:
                    findings.append(_finding("High", "MassRename", d,
                        f"{share:.0%} of files ({cnt}/{ds['total']}) share the ransomware extension '{e}'",
                        mtime=recent_cutoff))
    for note, dirs in note_spread.items():
        if len(dirs) >= 3:
            findings.append(_finding("High", "NoteSpread", sorted(dirs)[0],
                f"Ransom note '{note}' found in {len(dirs)} different folders", mtime=recent_cutoff))

    # summary + verdict
    high   = [f for f in findings if f["severity"] == "High"]
    medium = [f for f in findings if f["severity"] == "Medium"]
    low    = [f for f in findings if f["severity"] == "Low"]

    verdict, vcolor = "CLEAN", "32"
    if high:
        verdict, vcolor = "RANSOMWARE INDICATORS FOUND", "31"
    elif medium:
        verdict, vcolor = "SUSPICIOUS - REVIEW NEEDED", "33"

    elapsed = time.time() - started
    print()
    print(_c("36", "-" * 64))
    print("  RESULT: " + _c(vcolor, verdict))
    print(_c("36", "-" * 64))
    info(f"Files scanned : {files_seen:,}  ({human_bytes(bytes_seen):.1f} GB)")
    info(f"Duration      : {_fmt_dur(elapsed)}")
    print(_c("31", f"  High   : {len(high)}"))
    print(_c("33", f"  Medium : {len(medium)}"))
    print(_c("90", f"  Low    : {len(low)}"))
    print()
    for f in high[:15]:
        bad(f"[{f['type']}] {f['path']}  ->  {f['detail']}")
    if len(high) > 15:
        bad(f"... and {len(high) - 15} more high-severity findings (see report)")

    likely = likely_families(findings, fam_db)
    if likely:
        print()
        print(_c("36", "  Likely ransomware family(ies):"))
        for fam in likely:
            tag = {"available": "FREE DECRYPTOR MAY EXIST", "maybe": "decryptor MAYBE - verify"}.get(
                fam.get("decryptor"), "no known free decryptor")
            print(_c("33", f"   - {fam['name']:<28} [{tag}]"))
            print(_c("90", f"       {fam.get('url','')}"))
        print(_c("90", "   (menu [7] opens ID Ransomware / No More Ransom to confirm)"))

    paths = write_reports(cfg, mode_label, targets, started, elapsed,
                          files_seen, bytes_seen, findings, high, medium, low, verdict, likely, inv)
    print()
    ok("Reports saved:")
    print(_c("36", "     " + paths["html"]))
    print(_c("90", "     " + paths["txt"]))
    print(_c("90", "     " + paths["json"]))
    if high:
        print()
        bad("ACTION: disconnect from network, do NOT reboot or pay, keep the report, call your IR/AV team.")
    if cfg["open_report"]:
        try:
            webbrowser.open("file://" + paths["html"])
        except Exception:
            pass
    return 2 if high else (1 if medium else 0)

def _finding(severity, ftype, path, detail, entropy=-1.0, mtime=None):
    return {"severity": severity, "type": ftype, "path": path, "detail": detail,
            "entropy": entropy, "modified": mtime}

def _fmt_dur(seconds):
    s = int(seconds)
    return f"{s // 3600:02d}:{(s % 3600) // 60:02d}:{s % 60:02d}"

def likely_families(findings, fam_db):
    seen, out = set(), []
    for f in findings:
        ext = os.path.splitext(f["path"])[1].lower()
        name = os.path.basename(f["path"]).lower()
        hit = fam_db["by_ext"].get(ext) or fam_db["by_note"].get(name)
        if hit and hit["name"] not in seen:
            seen.add(hit["name"])
            out.append(hit)
    return out

# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------
def write_reports(cfg, mode_label, targets, started, elapsed, files_seen, bytes_seen,
                  findings, high, medium, low, verdict, likely, inv=None):
    if inv is None:
        inv = system_inventory()
    stamp = datetime.fromtimestamp(started).strftime("%Y%m%d_%H%M%S")
    host = inv.get("hostname") or hostname()
    user = inv.get("user") or os.environ.get("USER") or os.environ.get("USERNAME") or "user"
    # Computer name FIRST in the file name -> reports from 50-60 devices sort and
    # identify by device at a glance.
    safe_host = re.sub(r"[^A-Za-z0-9._-]", "-", host) or "host"
    base = f"{safe_host}_RansomwareScan_{stamp}"
    txt_path  = os.path.join(cfg["output_dir"], base + ".txt")
    json_path = os.path.join(cfg["output_dir"], base + ".json")
    html_path = os.path.join(cfg["output_dir"], base + ".html")

    def mod_str(m):
        return datetime.fromtimestamp(m).strftime("%Y-%m-%d %H:%M") if m else "-"

    meta = {
        "tool": "Windows Ransomware Detection Toolkit", "version": VERSION, "platform": "linux/python",
        "computer": host, "user": user, "scanMode": mode_label, "targets": targets,
        "inventory": inv,
        "startedAt": datetime.fromtimestamp(started).isoformat(timespec="seconds"),
        "durationSec": int(elapsed), "filesScanned": files_seen, "bytesScanned": bytes_seen,
        "verdict": verdict, "counts": {"high": len(high), "medium": len(medium), "low": len(low)},
        "likelyFamilies": [{"name": f["name"], "decryptor": f.get("decryptor"),
                            "tool": f.get("tool"), "url": f.get("url")} for f in likely],
    }
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump({"meta": meta, "findings": findings}, jf, indent=2, default=str)

    # TXT
    lines = []
    lines.append("Windows Ransomware Detection Toolkit - Scan Report")
    lines.append("=================================================")
    lines.append(f"Computer   : {host}   User: {user}")
    lines.append("Started    : " + datetime.fromtimestamp(started).strftime("%Y-%m-%d %H:%M:%S"))
    lines.append(f"Mode       : {mode_label}   Platform: linux/python")
    lines.append("Targets    : " + " ; ".join(targets))
    lines.append(f"Files      : {files_seen:,}  ({human_bytes(bytes_seen):.1f} GB) in {_fmt_dur(elapsed)}")
    lines.append(f"VERDICT    : {verdict}")
    lines.append(f"Findings   : High={len(high)}  Medium={len(medium)}  Low={len(low)}")
    lines.append("")
    lines.append("--- Device inventory ---")
    lines.append(f"  Hostname : {inv.get('hostname','')}   FQDN: {inv.get('fqdn','')}")
    lines.append(f"  OS       : {inv.get('platform','')} ({inv.get('arch','')})")
    lines.append(f"  Model    : {inv.get('model','') or '-'}   Serial: {inv.get('serial','') or '-'}")
    lines.append(f"  CPU/RAM  : {inv.get('cpu_cores','?')} cores / {inv.get('ram_gb','?')} GB")
    lines.append(f"  User     : {inv.get('user','')}   Domain: {inv.get('domain','') or '-'}")
    lines.append(f"  Network  : {', '.join(inv.get('ips', [])) or '-'}   MAC: {inv.get('mac','') or '-'}")
    _disks = "  ".join(f"{d['mount']} {d['free_gb']}/{d['total_gb']}GB free" for d in inv.get("disks", []))
    lines.append(f"  Disks    : {_disks or '-'}")
    lines.append(f"  Uptime   : {inv.get('uptime','') or '-'}")
    lines.append("")
    if likely:
        lines.append("Likely family(ies) / decryptor:")
        for fam in likely:
            lines.append(f"  - {fam['name']}  [{fam.get('decryptor')}]")
            if fam.get("tool"):
                lines.append(f"      {fam['tool']}")
            lines.append(f"      {fam.get('url','')}")
        lines.append("")
    for sev in ("High", "Medium", "Low"):
        items = [f for f in findings if f["severity"] == sev]
        if not items:
            continue
        lines.append(f"[{sev}] ({len(items)})")
        lines.append("-" * 49)
        for f in items:
            lines.append(f"  {f['type']:<11} {f['path']}")
            lines.append(f"              {f['detail']}")
        lines.append("")
    with open(txt_path, "w", encoding="utf-8") as tf:
        tf.write("\n".join(lines))

    # HTML
    rows = []
    for sev in ("High", "Medium", "Low"):
        for f in (x for x in findings if x["severity"] == sev):
            cls = sev.lower()
            ent = f"{f['entropy']:.2f}" if f["entropy"] is not None and f["entropy"] >= 0 else "-"
            rows.append(
                f"<tr class='{cls}'><td><span class='badge {cls}'>{sev}</span></td>"
                f"<td>{html.escape(f['type'])}</td><td class='path'>{html.escape(f['path'])}</td>"
                f"<td>{html.escape(f['detail'])}</td><td>{ent}</td><td>{mod_str(f['modified'])}</td></tr>")
    fam_html = ""
    if likely:
        li = []
        for fam in likely:
            badge = {"available": "<span class='badge low'>decryptor may exist</span>",
                     "maybe": "<span class='badge medium'>decryptor maybe</span>"}.get(
                         fam.get("decryptor"), "<span class='badge high'>no free decryptor</span>")
            li.append(f"<li><b>{html.escape(fam['name'])}</b> {badge}<br>"
                      f"<span class='mut'>{html.escape(fam.get('tool',''))}</span> &middot; "
                      f"<a href='{html.escape(fam.get('url',''))}'>{html.escape(fam.get('url',''))}</a></li>")
        fam_html = "<div class='fam'><h3>Likely family &amp; decryptor (verify before trusting)</h3><ul>" + "".join(li) + "</ul></div>"
    disks_str = "; ".join(f"{d['mount']} {d['free_gb']}/{d['total_gb']} GB free" for d in inv.get("disks", [])) or "-"
    inv_rows = [
        ("Hostname", inv.get("hostname", "")), ("FQDN", inv.get("fqdn", "") or "-"),
        ("OS", f"{inv.get('platform','')} ({inv.get('arch','')})"),
        ("Model", inv.get("model", "") or "-"), ("Serial", inv.get("serial", "") or "-"),
        ("CPU / RAM", f"{inv.get('cpu_cores','?')} cores / {inv.get('ram_gb','?')} GB"),
        ("User", inv.get("user", "")), ("Domain", inv.get("domain", "") or "-"),
        ("IP address(es)", ", ".join(inv.get("ips", [])) or "-"), ("MAC", inv.get("mac", "") or "-"),
        ("Disks", disks_str), ("Uptime", inv.get("uptime", "") or "-"),
    ]
    inv_html = ("<div class='inv'><h3>Device inventory</h3><table class='invtbl'>"
                + "".join(f"<tr><td class='k'>{html.escape(k)}</td><td>{html.escape(str(v))}</td></tr>" for k, v in inv_rows)
                + "</table></div>")
    vclass = "high" if high else ("medium" if medium else "clean")
    started_str = datetime.fromtimestamp(started).strftime("%Y-%m-%d %H:%M:%S")
    doc = (HTML_HEAD.replace("__TITLE__", f"Ransomware Scan - {html.escape(host)} - {stamp}")
           + f"<h1>Windows Ransomware Detection Toolkit</h1>"
           + f"<div class='sub'>{html.escape(host)} &middot; user {html.escape(user)} &middot; mode {mode_label} "
             f"&middot; started {started_str} &middot; {files_seen:,} files in {_fmt_dur(elapsed)} &middot; linux/python</div>"
           + f"<div class='verdict {vclass}'>{verdict}</div>"
           + "<div class='cards'>"
           + f"<div class='card'><div class='n' style='color:#ff6b81'>{len(high)}</div><div class='l'>High</div></div>"
           + f"<div class='card'><div class='n' style='color:#ffcf6b'>{len(medium)}</div><div class='l'>Medium</div></div>"
           + f"<div class='card'><div class='n' style='color:#9fb2df'>{len(low)}</div><div class='l'>Low</div></div>"
           + f"<div class='card'><div class='n'>{files_seen:,}</div><div class='l'>Files</div></div></div>"
           + inv_html
           + fam_html
           + "<table><thead><tr><th>Severity</th><th>Type</th><th>Path</th><th>Detail</th><th>Entropy</th><th>Modified</th></tr></thead><tbody>"
           + "".join(rows)
           + "</tbody></table>"
           + "<div class='foot'>Detection &amp; alerting only - no files were modified.<br>"
             "If you see High findings: <b>disconnect from the network</b>, do not pay, do not reboot, "
             "and preserve this report for your IR/AV team.</div></div></body></html>")
    with open(html_path, "w", encoding="utf-8") as hf:
        hf.write(doc)

    return {"txt": txt_path, "json": json_path, "html": html_path}

HTML_HEAD = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>__TITLE__</title>
<style>
 :root{--bg:#0f1420;--card:#171d2b;--tx:#e6e9ef;--mut:#8b93a7;--line:#26304a}
 body{margin:0;font-family:Segoe UI,Roboto,Arial,sans-serif;background:var(--bg);color:var(--tx)}
 .wrap{max-width:1100px;margin:0 auto;padding:28px}
 h1{font-size:20px;margin:0 0 4px}.sub{color:var(--mut);font-size:13px;margin-bottom:20px}
 .verdict{padding:16px 20px;border-radius:12px;font-size:20px;font-weight:700;margin:18px 0}
 .verdict.high{background:#3a1620;color:#ff6b81;border:1px solid #5a1e2e}
 .verdict.medium{background:#3a2f16;color:#ffcf6b;border:1px solid #5a4a1e}
 .verdict.clean{background:#12321f;color:#5ee08a;border:1px solid #1e5a38}
 .cards{display:flex;gap:14px;flex-wrap:wrap;margin:16px 0}
 .card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 18px;min-width:120px}
 .card .n{font-size:26px;font-weight:700}.card .l{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.5px}
 table{width:100%;border-collapse:collapse;background:var(--card);border-radius:12px;overflow:hidden;font-size:13px}
 th,td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
 th{background:#1d2434;color:var(--mut);font-weight:600}
 td.path{font-family:Consolas,monospace;word-break:break-all;color:#bcd0ff}
 .badge{padding:2px 9px;border-radius:20px;font-size:11px;font-weight:700}
 .badge.high{background:#5a1e2e;color:#ff8ea0}.badge.medium{background:#5a4a1e;color:#ffdf9b}.badge.low{background:#2a3350;color:#9fb2df}
 tr.high td{background:rgba(90,30,46,.12)}
 .inv{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:6px 18px 14px;margin:16px 0}
 .inv h3{font-size:14px;color:var(--tx);margin:12px 0 8px}
 .invtbl{width:100%;font-size:13px;background:transparent}
 .invtbl td{border-bottom:1px solid var(--line);padding:6px 10px}
 .invtbl td.k{color:var(--mut);width:170px;white-space:nowrap}
 .fam{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:6px 18px 14px;margin:16px 0}
 .fam h3{font-size:14px;color:var(--tx);margin:12px 0 6px}
 .fam ul{margin:0;padding-left:18px}.fam li{margin:8px 0;font-size:13px;line-height:1.5}
 .fam a{color:#8fb6ff;word-break:break-all}.mut{color:var(--mut)}
 .foot{color:var(--mut);font-size:12px;margin-top:22px;line-height:1.6}
</style></head><body><div class="wrap">
"""

# ---------------------------------------------------------------------------
# WATCH (polling; no external deps)
# ---------------------------------------------------------------------------
CANARY_MARKER = "CANARY-WRDT-2f8a1c-DO-NOT-DELETE"
CANARY_NAMES = [".wrdt_canary_do_not_delete_1.docx", ".wrdt_canary_do_not_delete_2.xlsx",
                ".wrdt_canary_do_not_delete_3.jpg", ".wrdt_canary_do_not_delete_4.pdf"]

def run_watch(cfg, paths):
    os.makedirs(cfg["output_dir"], exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = os.path.join(cfg["output_dir"], f"RansomwareWatch_{hostname()}_{stamp}.log")

    def wlog(level, msg):
        line = f"[{datetime.now():%Y-%m-%d %H:%M:%S}] [{level}] {msg}"
        color = {"ALARM": "31", "WARN": "33", "OK": "32"}.get(level, "90")
        print(_c(color, line))
        with open(log_path, "a", encoding="utf-8") as lf:
            lf.write(line + "\n")

    def alarm(title, detail):
        print()
        print(_c("31", "#" * 64))
        print(_c("31", f"#  RANSOMWARE ALARM: {title}"))
        print(_c("31", "#" * 64))
        wlog("ALARM", f"{title} -- {detail}")
        print(_c("33", "  -> DISCONNECT from the network now.  Do NOT reboot.  Do NOT pay."))
        print(_c("33", "  -> Note the time, keep this log, contact your IR/AV team."))
        try:
            sys.stdout.write("\a")
            sys.stdout.flush()
        except Exception:
            pass

    if not paths:
        home = os.path.expanduser("~")
        paths = [os.path.join(home, s) for s in ("Desktop", "Documents", "Downloads", "Pictures")]
    paths = [p for p in paths if os.path.isdir(p)]
    if not paths:
        wlog("WARN", "No valid folders to watch.")
        return

    ioc = load_ioc(cfg["data_dir"])
    bad_ext = set(ioc["exact"])          # curated only for watch (avoid FP from community list)
    note_re = ioc["notes"]

    canary_content = (CANARY_MARKER + "\nCANARY FILE - Windows Ransomware Detection Toolkit\n"
                      "Do not delete, rename or edit this file. It is a decoy used to detect\n"
                      "ransomware activity: if a program modifies it, the monitor alarms.\n"
                      f"Created: {stamp}\n")

    def canary_paths():
        return [os.path.join(folder, n) for folder in paths for n in CANARY_NAMES]

    def remove_canaries(quiet=False):
        removed = 0
        for cp in canary_paths():
            if os.path.isfile(cp):
                try:
                    with open(cp, "r", encoding="utf-8", errors="ignore") as f:
                        if CANARY_MARKER in f.read():
                            os.remove(cp)
                            removed += 1
                except OSError:
                    pass
        if not quiet:
            wlog("INFO", f"Canary cleanup: removed {removed} decoy file(s).")

    canary_base = {}   # path -> (mtime, size)
    def plant_canaries():
        remove_canaries(quiet=True)
        planted = 0
        for cp in canary_paths():
            try:
                with open(cp, "w", encoding="utf-8") as f:
                    f.write(canary_content)
                st = os.stat(cp)
                canary_base[cp] = (st.st_mtime, st.st_size)
                planted += 1
            except OSError:
                pass
        wlog("OK", f"Planted {planted} canary files across {len(paths)} folder(s).")

    print()
    print(_c("36", "=" * 64))
    print(_c("36", "  Ransomware LIVE MONITOR - early warning (polling)"))
    print(_c("36", "=" * 64))
    wlog("INFO", "Watching: " + " ; ".join(paths))
    wlog("INFO", f"Burst rule: >{cfg['burst_threshold']} changes / {cfg['burst_window']}s   Log: {log_path}")
    plant_canaries()

    stop = {"flag": False}
    def handler(signum, frame):
        stop["flag"] = True
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

    last_poll = time.time()
    last_canary = last_drop = last_burst = 0.0   # independent cooldowns per alarm type
    cooldown = 15
    canary_set = set(canary_paths())
    wlog("OK", "Monitor armed. Press Ctrl+C to stop.")

    try:
        while not stop["flag"]:
            time.sleep(min(cfg["burst_window"], 3))
            now = time.time()
            # 1) canary check
            for cp in canary_paths():
                if cp not in canary_base:
                    continue
                tripped = None
                if not os.path.isfile(cp):
                    tripped = "deleted/renamed"
                else:
                    try:
                        st = os.stat(cp)
                        if (st.st_mtime, st.st_size) != canary_base[cp]:
                            tripped = "modified"
                    except OSError:
                        pass
                if tripped and now - last_canary >= cooldown:
                    last_canary = now
                    alarm("CANARY TRIPPED", f"Decoy file was {tripped}: {cp}")
            # 2) burst + bad drops since last poll
            changed = 0
            bad_drop = None
            for folder in paths:
                for p in walk_files(folder):
                    if p in canary_set:
                        continue
                    try:
                        st = os.stat(p, follow_symlinks=False)
                    except OSError:
                        continue
                    if st.st_mtime >= last_poll:
                        changed += 1
                        e = os.path.splitext(p)[1].lower()
                        nm = os.path.basename(p)
                        if bad_drop is None and (e in bad_ext or any(rx.match(nm) for rx in note_re)):
                            bad_drop = (p, e)
            if bad_drop and now - last_drop >= cooldown:
                last_drop = now
                alarm("SUSPICIOUS FILE", f"ransomware extension/note -> {bad_drop[0]}")
            if changed >= cfg["burst_threshold"] and now - last_burst >= cooldown:
                last_burst = now
                alarm("CHANGE BURST", f"{changed} files changed in the last {int(now - last_poll)}s")
            last_poll = now
    finally:
        print()
        wlog("INFO", "Stopping monitor...")
        remove_canaries()
        wlog("OK", f"Monitor stopped. Log saved: {log_path}")

# ---------------------------------------------------------------------------
# UPDATE
# ---------------------------------------------------------------------------
DENY_EXT = set(x.lower() for x in [
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".rtf", ".jpg", ".jpeg", ".png",
    ".gif", ".bmp", ".tiff", ".tif", ".svg", ".zip", ".rar", ".7z", ".gz", ".tar", ".exe", ".dll", ".sys",
    ".msi", ".iso", ".mp3", ".mp4", ".avi", ".mkv", ".mov", ".wav", ".csv", ".log", ".dat", ".bak", ".bkp",
    ".tmp", ".temp", ".cache", ".backup", ".backups", ".html", ".htm", ".xml", ".json", ".ini", ".cfg", ".conf",
    ".db", ".sqlite", ".swp", ".swo", ".swn", ".lock", ".key", ".save", ".old", ".part", ".partial", ".download",
    ".crdownload", ".data", ".dmp", ".pem", ".crt", ".cer", ".pub", ".pfx", ".p12", ".asc", ".gpg", ".pgp",
    ".kdbx", ".jks", ".keystore", ".vmdk", ".vdi", ".ova", ".torrent", ".cr2", ".nef", ".arw", ".dng", ".raw",
    ".psd", ".so", ".o", ".a", ".ko", ".py", ".c", ".h", ".sh", ".rb", ".go", ".rs", ".php",
    # too-common / legit extensions removed from the curated list - keep them out of
    # the community list too so they can't re-false-positive via the entropy path
    ".inc", ".java", ".arrow", ".abc", ".rdm", ".pb", ".glb"])

def clean_extension(line):
    l = line.strip()
    if not l or l[0] in "#;/":
        return None
    if "," in l:
        l = l.split(",")[0].strip()
    if l.startswith("*."):
        l = l[1:]
    elif l.startswith("*"):
        return None
    l = l.lower()
    if re.fullmatch(r"\.[a-z0-9][a-z0-9_\-]{0,15}", l) and re.search(r"[a-z]", l):
        return l
    return None

def run_update(cfg):
    print()
    print(_c("36", "=" * 64))
    print(_c("36", "  Update definitions  -  fetch the latest ransomware extensions"))
    print(_c("36", "=" * 64))
    warn("Run this on a CLEAN, online machine to refresh the USB - not on an isolated host.")
    src_file = os.path.join(cfg["data_dir"], "update-sources.txt")
    if not os.path.isfile(src_file):
        bad(f"No update-sources.txt in {cfg['data_dir']}")
        return

    community = set()
    trusted_ok = trusted_fail = comm_sources = 0
    for raw in _read_lines(src_file):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        typ, target, url = parts[0].lower(), parts[1], parts[2]
        info(f"Fetching [{typ}] {url}")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "RansomwareToolkit"})
            with urllib.request.urlopen(req, timeout=25) as resp:
                content = resp.read().decode("utf-8", errors="ignore")
        except Exception as e:
            warn(f"  failed: {e}")
            if typ == "trusted":
                trusted_fail += 1
            continue
        if not content or len(content) < 10:
            warn("  empty response, skipped")
            if typ == "trusted":
                trusted_fail += 1
            continue
        if typ == "trusted":
            dest = os.path.join(cfg["data_dir"], target)
            okv = True
            if target.endswith(".json"):
                try:
                    json.loads(content)
                except Exception:
                    okv = False
            elif len(content.splitlines()) < 5:
                okv = False
            if not okv:
                warn(f"  validation failed, keeping current {target}")
                trusted_fail += 1
                continue
            if os.path.isfile(dest):
                try:
                    os.replace(dest, dest + ".bak")
                except OSError:
                    pass
            with open(dest, "w", encoding="utf-8") as f:
                f.write(content)
            ok(f"  updated {target}")
            trusted_ok += 1
        elif typ == "community":
            comm_sources += 1
            added = 0
            for cl in content.splitlines():
                e = clean_extension(cl)
                if e and e not in DENY_EXT and e not in community:
                    community.add(e)
                    added += 1
            info(f"  accepted {added} clean extensions from this source")

    if community:
        curated = set()
        cf = os.path.join(cfg["data_dir"], "extensions.txt")
        if os.path.isfile(cf):
            for r in _read_lines(cf):
                t = r.strip().lower()
                if t and not t.startswith("#") and "*" not in t:
                    curated.add(t)
        auto = os.path.join(cfg["data_dir"], "extensions-auto.txt")
        if os.path.isfile(auto):
            for r in _read_lines(auto):
                t = r.strip().lower()
                if t and not t.startswith("#") and t not in DENY_EXT:
                    community.add(t)
            try:
                os.replace(auto, auto + ".bak")
            except OSError:
                pass
        final = sorted(e for e in community if e not in curated)
        with open(auto, "w", encoding="utf-8") as f:
            f.write("# AUTO-GENERATED by 'update' - DO NOT EDIT BY HAND.\n")
            f.write("# Clean '.ext' entries merged from community sources in update-sources.txt,\n")
            f.write("# minus anything already in extensions.txt. Loaded automatically by the scanner.\n")
            f.write(f"# Total: {len(final)}\n\n")
            f.write("\n".join(final) + "\n")
        ok(f"extensions-auto.txt now holds {len(final)} community extensions")
    elif comm_sources:
        warn("No community extensions parsed (sources unreachable?).")

    print()
    ok(f"Update finished. Trusted files updated: {trusted_ok}, failed/skipped: {trusted_fail}.")
    ioc = load_ioc(cfg["data_dir"])
    info("Definitions now: {} curated + {} community extensions, {} note patterns, {} keywords".format(
        len(ioc["exact"]) + len(ioc["wild"]), len(ioc["auto"]), len(ioc["notes"]), len(ioc["keywords"])))

# ---------------------------------------------------------------------------
# Online identification (manual upload)
# ---------------------------------------------------------------------------
def run_identify(cfg):
    fam_db = load_families(cfg["data_dir"])
    print()
    print(_c("36", "  Online identification"))
    warn("This opens third-party sites in your browser. You upload files MANUALLY.")
    warn("Do NOT upload sensitive/confidential data. Encrypted files (ciphertext)")
    warn("and the ransom note are generally safe to share for identification.")
    urls = fam_db.get("urls") or IDENTIFY_URLS_DEFAULT
    targets = [urls.get("idRansomware"), urls.get("cryptoSheriff")]
    for u in [t for t in targets if t]:
        try:
            if webbrowser.open(u):
                ok(f"Opened: {u}")
            else:
                info(f"Open manually: {u}")
        except Exception:
            info(f"Open manually: {u}")

# ---------------------------------------------------------------------------
# Menu + dispatch
# ---------------------------------------------------------------------------
def show_menu(cfg):
    while True:
        print()
        print(_c("36", "=" * 64))
        print(_c("36", "   Windows Ransomware Detection Toolkit  (Linux / Python)"))
        print(_c("90", "   Read-only scan - reports saved to the 'reports' folder"))
        print(_c("36", "=" * 64))
        print()
        print("   [1]  Quick scan     home folders (Desktop, Documents, ...)")
        print("   [2]  Full scan      whole filesystem (root advised)")
        print("   [3]  Live monitor   real-time early warning (canary + burst)")
        print("   [4]  Custom path    scan a folder you choose")
        print("   [5]  Open reports folder")
        print("   [6]  Update definitions   fetch latest extensions online")
        print("   [7]  Identify online       open ID Ransomware / No More Ransom")
        print("   [0]  Exit")
        print()
        try:
            choice = input("   Select an option: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if choice == "1":
            run_scan(cfg, resolve_targets("quick", None), "Quick"); _pause()
        elif choice == "2":
            run_scan(cfg, resolve_targets("full", None), "Full"); _pause()
        elif choice == "3":
            run_watch(cfg, None)
        elif choice == "4":
            t = input("   Enter full path (e.g. /srv/share): ").strip()
            if t:
                run_scan(cfg, resolve_targets("custom", [t]), "Custom")
            _pause()
        elif choice == "5":
            os.makedirs(cfg["output_dir"], exist_ok=True)
            _open_folder(cfg["output_dir"])
        elif choice == "6":
            run_update(cfg); _pause()
        elif choice == "7":
            run_identify(cfg); _pause()
        elif choice == "0":
            return

def _pause():
    try:
        input("\n   Press Enter to return to the menu ")
    except (EOFError, KeyboardInterrupt):
        pass

def _open_folder(path):
    try:
        if sys.platform == "darwin":
            os.system(f'open "{path}"')
        elif os.name == "nt":
            os.startfile(path)  # type: ignore
        else:
            os.system(f'xdg-open "{path}" >/dev/null 2>&1 &')
    except Exception:
        info(f"Reports are in: {path}")

def build_cfg(a):
    return {
        "data_dir": a.data_dir or os.path.join(SCRIPT_DIR, "data"),
        "output_dir": a.output_dir or os.path.join(SCRIPT_DIR, "reports"),
        "recent_hours": a.recent_hours,
        "mass_threshold": a.mass_threshold,
        "no_entropy": a.no_entropy,
        "max_mb": a.max_mb,
        "entropy_threshold": a.entropy_threshold,
        "burst_threshold": a.burst_threshold,
        "burst_window": a.burst_window,
        "open_report": a.open_report,
    }

def main():
    ap = argparse.ArgumentParser(description="Windows Ransomware Detection Toolkit - Linux/Python edition")
    ap.add_argument("--mode", choices=["menu", "quick", "full", "custom", "watch", "update"], default="menu")
    ap.add_argument("--path", nargs="+", help="paths to scan (custom) or watch")
    ap.add_argument("--recent-hours", type=int, default=24, dest="recent_hours")
    ap.add_argument("--mass-threshold", type=int, default=40, dest="mass_threshold")
    ap.add_argument("--no-entropy", action="store_true", dest="no_entropy")
    ap.add_argument("--max-mb", type=int, default=150, dest="max_mb")
    ap.add_argument("--entropy-threshold", type=float, default=7.8, dest="entropy_threshold")
    ap.add_argument("--burst-threshold", type=int, default=25, dest="burst_threshold")
    ap.add_argument("--burst-window", type=int, default=5, dest="burst_window")
    ap.add_argument("--open-report", action="store_true", dest="open_report")
    ap.add_argument("--data-dir", dest="data_dir")
    ap.add_argument("--output-dir", dest="output_dir")
    ap.add_argument("--config", dest="config", help="path to a JSON config file (default: toolkit.config.json next to the script, if present)")

    # OPTIONAL config file: if toolkit.config.json exists (or --config given), its
    # values become the defaults. Command-line flags still override it. Not required.
    known = {"recent_hours", "mass_threshold", "no_entropy", "max_mb", "entropy_threshold",
             "burst_threshold", "burst_window", "open_report", "data_dir", "output_dir"}
    cfg_path = None
    _pre, _ = ap.parse_known_args()
    if _pre.config and os.path.isfile(_pre.config):
        cfg_path = _pre.config
    elif os.path.isfile(os.path.join(SCRIPT_DIR, "toolkit.config.json")):
        cfg_path = os.path.join(SCRIPT_DIR, "toolkit.config.json")
    if cfg_path:
        try:
            with open(cfg_path, encoding="utf-8") as f:
                overrides = {k: v for k, v in json.load(f).items() if k in known}
            ap.set_defaults(**overrides)
        except Exception as e:
            warn(f"Could not read config {cfg_path}: {e}")

    a = ap.parse_args()
    try:
        sys.stdout.reconfigure(line_buffering=True)   # live output even when piped
    except Exception:
        pass
    cfg = build_cfg(a)

    mode = a.mode
    if a.path and mode == "menu":
        mode = "custom"

    if mode == "menu":
        show_menu(cfg)
    elif mode == "quick":
        sys.exit(run_scan(cfg, resolve_targets("quick", None), "Quick"))
    elif mode == "full":
        sys.exit(run_scan(cfg, resolve_targets("full", None), "Full"))
    elif mode == "custom":
        sys.exit(run_scan(cfg, resolve_targets("custom", a.path), "Custom"))
    elif mode == "watch":
        run_watch(cfg, a.path)
    elif mode == "update":
        run_update(cfg)

if __name__ == "__main__":
    main()
