# Changelog

## 3.4 — Fleet features (inventory, device-first reports, config, CI)

Aimed at running the same scan across many (50-60) machines.

- **Device inventory in every report** — hostname, FQDN, OS, model, serial,
  CPU/RAM, user, domain, IPs, MAC, disks (free/total), uptime, and (Windows)
  installed antivirus. Shown in the console header and embedded in the TXT, JSON
  and HTML reports so you can tell whose machine it is at a glance.
- **Report file name now starts with the computer name** —
  `<HOSTNAME>_RansomwareScan_<timestamp>.{txt,json,html}` — so reports from a
  fleet sort and identify by device.
- **Optional config file** (`toolkit.config.json`) — set thresholds once and drop
  the same file on every USB. Command-line flags still override it; if the file is
  absent the toolkit works out of the box. See `toolkit.config.example.json`.
- **GitHub Actions CI** — every push parse-checks both engines and runs a synthetic
  attack fixture (must be detected) + a clean fixture (must stay clean), protecting
  the precision work in 3.3.

## 3.3 — Precision hardening (real-world false-positive fixes)

A real Quick scan of a developer machine (361k files) produced ~5000 false
positives. Root-caused and fixed; the same machine now reports CLEAN, while a
synthetic attack fixture is still fully detected (28 findings, 5 layers). Applied
to BOTH the PowerShell and Python engines.

- **Entropy is now a confirmation-only signal.** It runs solely to corroborate a
  low-confidence *community* extension; the old "odd extension + high entropy"
  path is gone. This removed thousands of FPs on extensionless files (git
  objects, binaries) and digit-bearing formats (`.woff2`, `.3mf`, ...).
- **Mass-rename** only fires when a hand-vetted (curated) ransomware extension
  dominates a folder — source-code (`.ts`) and photo (`.heic`) folders no longer
  trip it.
- **Mass-change** now counts only recently-modified *suspicious* files, so busy
  but benign folders (downloads, builds) don't false-positive.
- **Note spread** counts only content-confirmed ransom notes, not name-only hits.
- **Content-only note match** now requires ≥2 definitive ransom phrases, so
  security docs mentioning "bitcoin"/"private key" are ignored.
- Removed over-common entries from the curated lists: extensions `.inc`, `.java`,
  `.arrow`, `.cache`, `.abc`, `.rdm` and the broad `*_encrypted.*` wildcard;
  ransom-note name `info.txt`.
- Greatly expanded the "naturally high-entropy" exclusion set (fonts, ML models,
  3D formats, compiled objects, `.pack`, `.wasm`, ...).
- The scanner no longer scans **its own folder** (README/IOC lists/reports
  legitimately contain ransomware wording).

## 3.2-py — Linux / macOS edition

- **`ransomware_toolkit.py`** — a single, self-contained Python 3 script (standard
  library only, no pip installs) that runs the whole toolkit on Linux and macOS:
  the same five detection layers, family/decryptor identification, TXT/JSON/HTML
  reports, definitions update, and a polling-based live monitor (canary decoys +
  change-burst + bad-drop, no external inotify dependency).
- It **shares the same `data/` folder** as the PowerShell version, so updating the
  IOC lists updates both platforms.
- **`run-scan.sh`** — tiny Linux/macOS launcher (menu via the Python script).
- Linux specifics: scans `/home`, `/Users`, `/root`; `full` mode walks the whole
  filesystem while skipping pseudo-filesystems (`/proc`, `/sys`, `/dev`, ...);
  root/`sudo` recommended for full coverage. Symlinked directories are not
  followed (loop-safe). Verified feature-parity with the PowerShell version.

## 3.2 — Auto-update + family identification

### Added
- **`[6] Update definitions`** (`-Mode Update`) — fetches the latest ransomware
  extensions online. Sources are configured in `data/update-sources.txt`:
  - `trusted` sources (your own repo) are validated and replace the file (a
    `.bak` is kept).
  - `community` sources (dannyroemhild, thephoton — updated ~weekly) are hard-
    filtered to clean `.ext` entries (wildcards, numeric-only extensions that
    collide with split archives, and common `.swp`/`.lock`/`.key`-type
    extensions are dropped) and union-merged into `data/extensions-auto.txt`.
- **Two-confidence detection model** — the hand-curated `extensions.txt` stays
  high-confidence (flags on the file name). The bulk community list
  (`extensions-auto.txt`, ~4700 entries) is low-confidence: a match is only
  reported when the file is **also high-entropy**, so it boosts detection
  without adding false positives.
- **`[7] Identify online`** + `data/families.json` — after a scan, the tool maps
  matched extensions/notes to a likely family and shows a free-decryptor link
  (offline). Option `[7]` opens ID Ransomware / No More Ransom in the browser for
  manual upload. No file is ever uploaded automatically (privacy).
- Family/decryptor hints added to the console output and the TXT/JSON/HTML reports.

### Changed
- Entropy layer only runs on genuinely suspicious candidates (known/community/odd
  extension), not on every high-entropy file — removes `.swp`/`.lock`/binary
  false positives and speeds up Quick scans.
- Expanded the "naturally high-entropy" exclusion list (camera RAW, crypto
  containers, VM images, more archive/media types).

## 3.1 — Single script

- Merged the two engines (`Scan-Ransomware.ps1` + `Watch-Ransomware.ps1`) into
  **one** file, `RansomwareToolkit.ps1`, that carries the interactive menu plus
  both the scanner and the live monitor, selectable with `-Mode`
  (`Menu`/`Quick`/`Full`/`Custom`/`Watch`).
- `RunScan.bat` is now a 2-line launcher (it exists only because Windows opens
  `.ps1` files in Notepad on double-click). Full-scan elevation is handled from
  inside the script.
- Detection logic and IOC data are unchanged; behaviour verified identical.

## 3.0 — Modernization

Complete rewrite into a portable, USB-friendly incident-response toolkit.

### Added
- **`RunScan.bat`** — one-click menu launcher (Quick / Full / Live monitor /
  Custom path / Open reports). Runs PowerShell with a process-scoped
  `-ExecutionPolicy Bypass`, so it never changes the machine's global policy.
- **`Scan-Ransomware.ps1`** — new multi-layer scanner with a **single** file
  system pass:
  - Layer 1: known ransomware extension match (exact + wildcard).
  - Layer 2: ransom-note file-name patterns.
  - Layer 3: ransom-note **content** confirmation (keywords).
  - Layer 4: **Shannon entropy** analysis to flag likely-encrypted files,
    excluding naturally high-entropy formats (`.zip/.jpg/.mp4/.docx`, ...) to
    avoid false positives.
  - Layer 5: **behavioural** heuristics — mass recent changes, folders
    dominated by one odd extension (mass rename), and the same note dropped
    across many folders.
  - Reports in **TXT + JSON + HTML** written next to the tool (onto the USB).
  - Severity-based verdict and process exit codes (0 clean / 1 suspicious / 2 found).
- **`Watch-Ransomware.ps1`** — real-time early-warning monitor using
  **canary decoy files** + `FileSystemWatcher`. Alarms on canary tampering,
  change bursts, and suspicious file drops. Canaries carry a unique marker and
  are swept idempotently, so a crash never leaves them behind.
- **`data/`** — externalised, updatable IOC lists (extensions, note names,
  keywords) refreshed with modern families: LockBit, Akira, Play, Royal,
  BlackBasta, Cl0p, Hive, Rhysida, Medusa, BianLian, Phobos/8base, Mallox,
  STOP/Djvu, and more.
- Bilingual (TR/EN) README, MIT license retained.

### Fixed / removed (from the legacy scripts, kept in `legacy/`)
- **Performance:** V2 re-scanned the entire `C:\` drive **once per extension**
  (~500 full-disk walks). Replaced with a single pass.
- **Bug:** V2 referenced an undefined `$driveToScan`, so it effectively scanned
  nothing.
- Removed the in-script `Set-ExecutionPolicy RemoteSigned` call, which changed
  the machine's global policy as a side effect.
- Reports now go to the toolkit/USB folder instead of the user's Desktop.
