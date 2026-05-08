#!/bin/bash
# Robust apt installer — tries each package individually, skips failures.
# Usage: apt-install-robust.sh pkg1 pkg2 pkg3 ...

set -o pipefail

apt-get update -qq 2>/dev/null

INSTALLED=()
SKIPPED=()

for pkg in "$@"; do
    if apt-get install -y --no-install-recommends "$pkg" 2>/dev/null; then
        INSTALLED+=("$pkg")
    else
        SKIPPED+=("$pkg")
        echo "WARN: skipped unavailable package: $pkg" >&2
    fi
done

rm -rf /var/lib/apt/lists/*

echo "--- apt-install-robust summary ---"
echo "Installed: ${#INSTALLED[@]} packages"
echo "Skipped:   ${#SKIPPED[@]} packages"
if [ ${#SKIPPED[@]} -gt 0 ]; then
    echo "Skipped list: ${SKIPPED[*]}"
fi
