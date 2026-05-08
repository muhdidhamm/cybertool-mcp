#!/bin/bash
set -e

export PATH="/opt/uts-mcp/venv/bin:$PATH"

# All log output MUST go to stderr — stdout is reserved for MCP JSON-RPC
log() { echo "$@" >&2; }

mkdir -p /opt/uts-mcp/output /opt/uts-mcp/logs /opt/uts-mcp/reports

# ── Persistent data directory setup ──────────────────────────────────────────
DATA_DIR="/opt/uts-mcp/data"
STAMP_DIR="$DATA_DIR/.update-stamps"
mkdir -p "$DATA_DIR" "$STAMP_DIR"

init_persistent_data() {
    log "[entrypoint] Initializing persistent data directories..."

    mkdir -p "$DATA_DIR"/{nmap,metasploit,nuclei-templates,wpscan,clamav,exploitdb,nikto,hashcat,subfinder,amass}

    # Nmap — symlink scripts and probes from persistent store
    if [ -d "$DATA_DIR/nmap/scripts" ] && [ "$(ls -A "$DATA_DIR/nmap/scripts" 2>/dev/null)" ]; then
        ln -sfn "$DATA_DIR/nmap/scripts" /usr/share/nmap/scripts 2>/dev/null || true
    fi
    if [ -f "$DATA_DIR/nmap/nmap-service-probes" ]; then
        ln -sf "$DATA_DIR/nmap/nmap-service-probes" /usr/share/nmap/nmap-service-probes 2>/dev/null || true
    fi
    if [ -f "$DATA_DIR/nmap/nmap-os-db" ]; then
        ln -sf "$DATA_DIR/nmap/nmap-os-db" /usr/share/nmap/nmap-os-db 2>/dev/null || true
    fi

    # ClamAV — point to persistent virus database
    if [ -d "$DATA_DIR/clamav" ] && [ "$(ls -A "$DATA_DIR/clamav"/*.cvd 2>/dev/null)" ]; then
        ln -sfn "$DATA_DIR/clamav" /var/lib/clamav 2>/dev/null || true
    fi

    # Nikto — persistent plugins
    if [ -d "$DATA_DIR/nikto" ] && [ "$(ls -A "$DATA_DIR/nikto" 2>/dev/null)" ]; then
        ln -sfn "$DATA_DIR/nikto" /var/lib/nikto 2>/dev/null || true
    fi

    # ExploitDB — persistent CSV indices
    if [ -f "$DATA_DIR/exploitdb/files_exploits.csv" ]; then
        cp -u "$DATA_DIR/exploitdb/files_exploits.csv" /usr/share/exploitdb/ 2>/dev/null || true
        cp -u "$DATA_DIR/exploitdb/files_shellcodes.csv" /usr/share/exploitdb/ 2>/dev/null || true
    fi

    # Nuclei — point HOME so templates persist
    if [ -d "$DATA_DIR/nuclei-templates" ]; then
        mkdir -p /root/.local
        ln -sfn "$DATA_DIR/nuclei-templates" /root/.local/nuclei-templates 2>/dev/null || true
    fi

    # WPScan — persistent database
    if [ -d "$DATA_DIR/wpscan" ]; then
        export WPSCAN_DATA_DIR="$DATA_DIR/wpscan"
    fi

    # Hashcat — persistent rules
    if [ -d "$DATA_DIR/hashcat/rules" ] && [ "$(ls -A "$DATA_DIR/hashcat/rules" 2>/dev/null)" ]; then
        ln -sfn "$DATA_DIR/hashcat/rules" /usr/share/hashcat/rules 2>/dev/null || true
    fi

    # Subfinder / Amass — persistent configs
    mkdir -p /root/.config
    ln -sfn "$DATA_DIR/subfinder" /root/.config/subfinder 2>/dev/null || true
    ln -sfn "$DATA_DIR/amass" /root/.config/amass 2>/dev/null || true
}

# ── First-boot auto-update ───────────────────────────────────────────────────
check_first_boot_update() {
    if [ ! -f "$STAMP_DIR/all" ]; then
        log "[entrypoint] First boot detected — running initial database update..."
        log "[entrypoint] This may take several minutes. Subsequent starts will skip this."
        /opt/uts-mcp/update-databases.sh all >&2
    else
        log "[entrypoint] Databases already initialized (last full update: $(cat "$STAMP_DIR/all"))."
        log "[entrypoint] Run 'update_all_databases' tool or '/opt/uts-mcp/update-databases.sh' to refresh."
    fi
}

# AUTO_UPDATE env var controls behavior:
#   "first" (default) — only update on first boot (stamp file missing)
#   "always"          — update every time the container starts
#   "never"           — skip updates entirely
AUTO_UPDATE="${AUTO_UPDATE:-first}"

init_persistent_data

case "$AUTO_UPDATE" in
    always)
        log "[entrypoint] AUTO_UPDATE=always — running full database update..."
        /opt/uts-mcp/update-databases.sh all >&2
        ;;
    first)
        check_first_boot_update
        ;;
    never)
        log "[entrypoint] AUTO_UPDATE=never — skipping database updates."
        ;;
esac

# ── Start MCP server ────────────────────────────────────────────────────────
TRANSPORT="${MCP_TRANSPORT:-stdio}"

case "$TRANSPORT" in
    stdio)
        exec python3 /opt/uts-mcp/server.py --transport stdio
        ;;
    sse)
        exec python3 /opt/uts-mcp/server.py --transport sse --host 0.0.0.0 --port "${MCP_PORT:-8080}"
        ;;
    streamable-http)
        exec python3 /opt/uts-mcp/server.py --transport streamable-http --host 0.0.0.0 --port "${MCP_PORT:-8080}"
        ;;
    *)
        log "Unknown transport: $TRANSPORT"
        exit 1
        ;;
esac
