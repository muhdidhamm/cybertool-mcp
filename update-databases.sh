#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Unified ThreatLens MCP — Tool Database & Pattern Updater
#
# Updates all tool databases/signatures/templates to latest versions.
# Data is stored in /opt/uts-mcp/data/ which should be a persistent volume.
#
# Usage:
#   update-databases.sh              # Update everything
#   update-databases.sh nmap         # Update a single tool
#   update-databases.sh --check      # Show last update timestamps
# ─────────────────────────────────────────────────────────────────────────────

set -o pipefail

DATA_DIR="/opt/uts-mcp/data"
LOG_FILE="/opt/uts-mcp/logs/db-update.log"
STAMP_DIR="$DATA_DIR/.update-stamps"

mkdir -p "$DATA_DIR" "$STAMP_DIR" "$(dirname "$LOG_FILE")"

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$msg"
    echo "$msg" >> "$LOG_FILE"
}

stamp() {
    date '+%Y-%m-%d %H:%M:%S' > "$STAMP_DIR/$1"
}

get_stamp() {
    if [ -f "$STAMP_DIR/$1" ]; then
        cat "$STAMP_DIR/$1"
    else
        echo "never"
    fi
}

# ── Individual update functions ──────────────────────────────────────────────

update_nmap() {
    log "Updating Nmap scripts and service probes..."
    mkdir -p "$DATA_DIR/nmap"
    nmap --script-updatedb 2>&1 | tail -5 >> "$LOG_FILE"
    if [ -d /usr/share/nmap/scripts ]; then
        cp -ru /usr/share/nmap/scripts "$DATA_DIR/nmap/" 2>/dev/null
        cp -u /usr/share/nmap/nmap-service-probes "$DATA_DIR/nmap/" 2>/dev/null
        cp -u /usr/share/nmap/nmap-os-db "$DATA_DIR/nmap/" 2>/dev/null
    fi
    stamp "nmap"
    log "  Nmap update complete."
}

update_metasploit() {
    log "Updating Metasploit framework..."
    mkdir -p "$DATA_DIR/metasploit"
    if command -v msfupdate &>/dev/null; then
        msfupdate 2>&1 | tail -10 >> "$LOG_FILE"
    elif command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y --only-upgrade metasploit-framework 2>&1 | tail -5 >> "$LOG_FILE"
    fi
    stamp "metasploit"
    log "  Metasploit update complete."
}

update_nuclei() {
    log "Updating Nuclei templates..."
    mkdir -p "$DATA_DIR/nuclei-templates"
    export HOME="$DATA_DIR"
    nuclei -update-templates -silent 2>&1 | tail -5 >> "$LOG_FILE"
    if [ -d "$DATA_DIR/.local/nuclei-templates" ]; then
        ln -sfn "$DATA_DIR/.local/nuclei-templates" "$DATA_DIR/nuclei-templates/latest"
    elif [ -d "$DATA_DIR/nuclei-templates" ]; then
        true
    fi
    stamp "nuclei"
    log "  Nuclei templates update complete."
}

update_wpscan() {
    log "Updating WPScan vulnerability database..."
    mkdir -p "$DATA_DIR/wpscan"
    export WPSCAN_DATA_DIR="$DATA_DIR/wpscan"
    wpscan --update 2>&1 | tail -5 >> "$LOG_FILE" || true
    stamp "wpscan"
    log "  WPScan update complete."
}

update_clamav() {
    log "Updating ClamAV virus signatures..."
    mkdir -p "$DATA_DIR/clamav"
    if [ ! -f "$DATA_DIR/clamav/freshclam.conf" ]; then
        cp /etc/clamav/freshclam.conf "$DATA_DIR/clamav/freshclam.conf" 2>/dev/null || \
        echo -e "DatabaseMirror database.clamav.net\nDatabaseDirectory $DATA_DIR/clamav" > "$DATA_DIR/clamav/freshclam.conf"
    fi
    freshclam --datadir="$DATA_DIR/clamav" --config-file="$DATA_DIR/clamav/freshclam.conf" 2>&1 | tail -10 >> "$LOG_FILE" || true
    stamp "clamav"
    log "  ClamAV update complete."
}

update_exploitdb() {
    log "Updating ExploitDB / SearchSploit database..."
    mkdir -p "$DATA_DIR/exploitdb"
    searchsploit -u 2>&1 | tail -5 >> "$LOG_FILE" || true
    if [ -d /usr/share/exploitdb ]; then
        cp -ru /usr/share/exploitdb/files_exploits.csv "$DATA_DIR/exploitdb/" 2>/dev/null
        cp -ru /usr/share/exploitdb/files_shellcodes.csv "$DATA_DIR/exploitdb/" 2>/dev/null
    fi
    stamp "exploitdb"
    log "  ExploitDB update complete."
}

update_nikto() {
    log "Updating Nikto plugins and databases..."
    mkdir -p "$DATA_DIR/nikto"
    nikto -update 2>&1 | tail -5 >> "$LOG_FILE" || true
    if [ -d /var/lib/nikto ]; then
        cp -ru /var/lib/nikto/* "$DATA_DIR/nikto/" 2>/dev/null
    fi
    stamp "nikto"
    log "  Nikto update complete."
}

update_rkhunter() {
    log "Updating rkhunter definitions..."
    rkhunter --update 2>&1 | tail -5 >> "$LOG_FILE" || true
    rkhunter --propupd 2>&1 | tail -5 >> "$LOG_FILE" || true
    stamp "rkhunter"
    log "  rkhunter update complete."
}

update_lynis() {
    log "Updating Lynis..."
    if command -v lynis &>/dev/null; then
        lynis update info 2>&1 | tail -5 >> "$LOG_FILE" || true
        cd /usr/share/lynis && git pull 2>&1 | tail -3 >> "$LOG_FILE" || true
    fi
    stamp "lynis"
    log "  Lynis update complete."
}

update_subfinder() {
    log "Updating Subfinder provider config..."
    mkdir -p "$DATA_DIR/subfinder"
    export HOME="$DATA_DIR"
    subfinder -silent -update 2>&1 | tail -3 >> "$LOG_FILE" || true
    stamp "subfinder"
    log "  Subfinder update complete."
}

update_amass() {
    log "Updating Amass data sources..."
    mkdir -p "$DATA_DIR/amass"
    export HOME="$DATA_DIR"
    stamp "amass"
    log "  Amass config directory initialized."
}

update_wapiti() {
    log "Updating Wapiti vulnerability modules..."
    wapiti --update 2>&1 | tail -5 >> "$LOG_FILE" || true
    stamp "wapiti"
    log "  Wapiti update complete."
}

update_hashcat() {
    log "Verifying hashcat rule files..."
    mkdir -p "$DATA_DIR/hashcat"
    if [ -d /usr/share/hashcat/rules ]; then
        cp -ru /usr/share/hashcat/rules "$DATA_DIR/hashcat/" 2>/dev/null
    fi
    stamp "hashcat"
    log "  Hashcat rules synced."
}

# ── Dispatcher ───────────────────────────────────────────────────────────────

update_all() {
    log "═══════════════════════════════════════════════════════════════"
    log "  Starting full database update..."
    log "═══════════════════════════════════════════════════════════════"

    update_nmap
    update_exploitdb
    update_nikto
    update_nuclei
    update_wpscan
    update_clamav
    update_rkhunter
    update_metasploit
    update_lynis
    update_subfinder
    update_amass
    update_wapiti
    update_hashcat

    stamp "all"
    log "═══════════════════════════════════════════════════════════════"
    log "  All database updates complete."
    log "═══════════════════════════════════════════════════════════════"
}

show_status() {
    echo "═══════════════════════════════════════════════════"
    echo "  Unified ThreatLens — Database Update Status"
    echo "═══════════════════════════════════════════════════"
    printf "  %-20s %s\n" "TOOL" "LAST UPDATED"
    echo "  ──────────────────────────────────────────────"
    for tool in nmap metasploit nuclei wpscan clamav exploitdb nikto rkhunter lynis subfinder amass wapiti hashcat all; do
        printf "  %-20s %s\n" "$tool" "$(get_stamp $tool)"
    done
    echo "═══════════════════════════════════════════════════"
    echo "  Data directory: $DATA_DIR"
    if [ -d "$DATA_DIR" ]; then
        echo "  Data size: $(du -sh "$DATA_DIR" 2>/dev/null | cut -f1)"
    fi
    echo "═══════════════════════════════════════════════════"
}

# ── Main ─────────────────────────────────────────────────────────────────────

case "${1:-all}" in
    --check|--status|-s)
        show_status
        ;;
    all)
        update_all
        ;;
    nmap)           update_nmap ;;
    metasploit|msf) update_metasploit ;;
    nuclei)         update_nuclei ;;
    wpscan)         update_wpscan ;;
    clamav)         update_clamav ;;
    exploitdb|searchsploit) update_exploitdb ;;
    nikto)          update_nikto ;;
    rkhunter)       update_rkhunter ;;
    lynis)          update_lynis ;;
    subfinder)      update_subfinder ;;
    amass)          update_amass ;;
    wapiti)         update_wapiti ;;
    hashcat)        update_hashcat ;;
    *)
        echo "Usage: $0 [tool|all|--check]"
        echo "Tools: nmap, metasploit, nuclei, wpscan, clamav, exploitdb, nikto,"
        echo "       rkhunter, lynis, subfinder, amass, wapiti, hashcat"
        exit 1
        ;;
esac
