#!/usr/bin/env bash
# Windows Ransomware Detection Toolkit - Linux launcher.
# Just starts the one Python script, which shows its own menu
# (Quick / Full / Live monitor / Custom / Update / Identify).
#
# Usage:
#   ./run-scan.sh                 # interactive menu
#   ./run-scan.sh --mode quick    # any argument is passed straight through
#
# Requires python3 (pre-installed on virtually all Linux distros). No pip installs.

set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PY="$(command -v python3 || true)"
if [ -z "$PY" ]; then
    echo "python3 not found. Install it, e.g.:  sudo apt install python3   (Debian/Ubuntu)"
    exit 1
fi

exec "$PY" "$DIR/ransomware_toolkit.py" "$@"
