# =============================================================================
# Stage 1: tools-base — heavy tool installation (cached across code changes)
# =============================================================================
FROM kalilinux/kali-rolling:latest AS tools-base

ENV DEBIAN_FRONTEND=noninteractive
ENV TERM=xterm-256color

# Robust installer — copied first and alone so edits to it bust only this layer
COPY apt-install-robust.sh /usr/local/bin/apt-install-robust.sh
RUN sed -i 's/\r$//' /usr/local/bin/apt-install-robust.sh && \
    chmod +x /usr/local/bin/apt-install-robust.sh

# Exclude non-runtime package artifacts to keep image smaller.
RUN printf '%s\n' \
    'path-exclude=/usr/share/doc/*' \
    'path-exclude=/usr/share/man/*' \
    'path-exclude=/usr/share/info/*' \
    'path-exclude=/usr/share/lintian/*' \
    'path-exclude=/usr/share/locale/*' \
    'path-include=/usr/share/locale/en*' \
    > /etc/dpkg/dpkg.cfg.d/01_nodoc

# Avoid pulling suggested/recommended packages to reduce footprint.
RUN printf '%s\n' \
    'APT::Install-Recommends "0";' \
    'APT::Install-Suggests "0";' \
    > /etc/apt/apt.conf.d/01norecommend

# ── Base system & build dependencies ────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv python3-dev build-essential \
    curl wget git jq dnsutils whois pv tree htop tmux vim nano \
    ruby golang openssl ca-certificates libssl-dev default-jre-headless \
    openssh-client lsof parted fdisk util-linux lvm2 ntfs-3g xfsprogs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/* /var/log/*

# ── ALL packages in ONE layer (biggest cache win) ──────────────────
# Consolidating into a single RUN avoids 16× apt-get update and makes
# the entire tool layer a single cache entry that only rebuilds when
# you add or remove a package from this list.
RUN /usr/local/bin/apt-install-robust.sh \
    # ── Metapackages ──
    kali-tools-top10 \
    kali-tools-information-gathering \
    kali-tools-vulnerability \
    kali-tools-web \
    kali-tools-database \
    kali-tools-passwords

RUN /usr/local/bin/apt-install-robust.sh \
    kali-tools-wireless \
    kali-tools-reverse-engineering \
    kali-tools-exploitation \
    kali-tools-social-engineering \
    kali-tools-sniffing-spoofing \
    kali-tools-post-exploitation

RUN /usr/local/bin/apt-install-robust.sh \
    kali-tools-forensics \
    kali-tools-crypto-stego \
    kali-tools-reporting \
    kali-tools-rfid \
    kali-tools-sdr \
    kali-tools-voip

RUN /usr/local/bin/apt-install-robust.sh \
    # ── Network Scanning & Reconnaissance ──
    nmap masscan zmap unicornscan hping3 arping fping netdiscover \
    arp-scan p0f traceroute mtr tcpdump tshark nbtscan iperf3 netsniff-ng \
    # ── Web Application Security ──
    nikto dirb dirbuster gobuster wfuzz ffuf feroxbuster whatweb wafw00f \
    wpscan joomscan droopescan sqlmap commix xsser skipfish wapiti \
    sslyze sslscan ssldump testssl.sh burpsuite zaproxy \
    # ── SSL/TLS & Certificate Tools ──
    openssl gnutls-bin nss-tools certbot tlsx \
    # ── Password & Brute-Force ──
    hydra john john-data hashcat hashcat-utils medusa ncrack patator \
    crowbar brutespray thc-pptp-bruter ophcrack samdump2 cewl crunch \
    cupp maskprocessor hashid hash-identifier \
    # ── Active Directory & Windows ──
    responder impacket-scripts crackmapexec netexec kerbrute \
    ldapdomaindump bloodhound.py powershell smbclient smbmap rpcclient \
    enum4linux enum4linux-ng evil-winrm certipy-ad \
    # ── OSINT & Information Gathering ──
    theharvester recon-ng dmitry fierce dnsenum dnsrecon dnsmap dnstwist \
    sublist3r amass subfinder assetfinder httpx-toolkit nuclei naabu \
    sherlock spiderfoot onesixtyone snmp \
    # ── Vulnerability Scanning ──
    legion lynis chkrootkit rkhunter clamav clamav-daemon \
    # ── Exploitation & Post-Exploitation ──
    metasploit-framework exploitdb social-engineer-toolkit beef-xss \
    bettercap evilginx2 gophish weevely routersploit shellnoob \
    backdoor-factory sshuttle chisel \
    # ── Sniffing & Spoofing ──
    ettercap-text-only dsniff macchanger mitm6 mitmproxy sslstrip dnschef \
    # ── Wireless Security ──
    aircrack-ng wifite reaver pixiewps bully cowpatty pyrit kismet \
    hostapd dnsmasq hcxdumptool hcxtools airgeddon wavemon spooftooph \
    wifiphisher fluxion fern-wifi-cracker mdk4 asleap hostapd-wpe \
    # ── Forensics & Steganography ──
    binwalk foremost scalpel sleuthkit autopsy volatility3 yara steghide \
    stegosuite outguess stegcracker exiftool pdfcrack fcrackzip rarcrack \
    unrar p7zip bulk-extractor ddrescue dc3dd afflib-tools \
    # ── Reverse Engineering ──
    radare2 rizin cutter gdb gdb-peda pwndbg gef binutils upx-ucl \
    apktool dex2jar smali baksmali ltrace strace ghidra jadx \
    # ── Database Assessment ──
    sqlninja bbqsql jsql-injection hexorbase oscanner sidguesser \
    tnscmd10g odat dbpwaudit postgresql postgresql-contrib \
    # ── VoIP ──
    sipvicious sipp enumiax iaxflood inviteflood rtpbreak \
    rtpinsertsound rtpmixsound sctpscan \
    # ── SDR ──
    gnuradio hackrf rtl-sdr multimon-ng kalibrate-rtl inspectrum dump1090-fa \
    # ── Stress Testing / DoS ──
    slowhttptest t50 goldeneye dhcpig siege thc-ssl-dos \
    # ── Bluetooth ──
    bluelog bluesnarfer blueranger bluez bluez-tools btscanner \
    # ── Reporting & Documentation ──
    dradis cutycapt cherrytree pipal recordmydesktop \
    # ── Networking Utilities ──
    dos2unix ipcalc netcat-openbsd socat ncat proxychains4 tor i2p \
    pandoc wkhtmltopdf texlive-latex-base texlive-fonts-recommended \
    texlive-latex-extra \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/* /var/log/*

# ── Python security packages (separate layer — changes less often) ──────
RUN pip3 install --no-cache-dir --break-system-packages \
    scapy requests beautifulsoup4 lxml paramiko pycryptodome \
    cryptography pyopenssl impacket ldap3 python-nmap shodan \
    pwntools ropper capstone keystone-engine yara-python \
    jinja2 markdown weasyprint python-docx \
    || true

# ── Post-Quantum Cryptography tools ─────────────────────────────────────
RUN pip3 install --no-cache-dir --break-system-packages \
    pqcrypto oqs || true

# Remove non-runtime Python artifacts from system site-packages.
RUN rm -rf /root/.cache/pip /root/.cache && \
    for d in /usr/lib/python3* /usr/local/lib/python3*; do \
      if [ -d "$d" ]; then \
        find "$d" -type d \( -name '__pycache__' -o -name 'test' -o -name 'tests' -o -name 'testing' -o -name 'examples' \) -prune -exec rm -rf '{}' + 2>/dev/null || true; \
        find "$d" -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete 2>/dev/null || true; \
      fi; \
    done

# ── Wordlists ───────────────────────────────────────────────────────────
RUN /usr/local/bin/apt-install-robust.sh wordlists seclists && \
    mkdir -p /usr/share/wordlists && \
    cd /usr/share/wordlists && \
    (gunzip -f rockyou.txt.gz 2>/dev/null || \
     wget -q -O rockyou.txt.gz https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt 2>/dev/null && \
     gunzip -f rockyou.txt.gz) || true && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* /var/log/*

# Strip non-essential leftovers; keep binary stripping opt-in for safety.
ARG ENABLE_BINARY_STRIP=0
RUN rm -rf /usr/share/examples/* /usr/share/doc-base/* && \
    find /usr/lib -type f -name '*.a' -delete 2>/dev/null || true && \
    if [ "$ENABLE_BINARY_STRIP" = "1" ] && command -v strip >/dev/null 2>&1; then \
      find /usr/bin /usr/sbin -type f -perm /111 -exec strip --strip-unneeded '{}' + 2>/dev/null || true; \
    fi

# Extra non-runtime pruning (safe defaults): keep binaries, remove debug/help/UI assets.
RUN rm -rf \
    /usr/lib/debug/* \
    /usr/share/help/* \
    /usr/share/gtk-doc/* \
    /usr/share/icons/* \
    /usr/share/themes/* \
    /usr/share/backgrounds/* \
    /usr/share/pixmaps/* \
    /usr/share/bug/* \
    /var/cache/fontconfig/* \
    /var/cache/debconf/*-old

# Seed initial Nmap script DB
RUN nmap --script-updatedb 2>/dev/null || true


# =============================================================================
# Stage 2: runtime — MCP server code (rebuilds fast on code changes)
# =============================================================================
FROM tools-base AS runtime

WORKDIR /opt/uts-mcp

# ── Python venv + MCP dependencies (only rebuilds if requirements.txt changes)
RUN python3 -m venv /opt/uts-mcp/venv
ENV PATH="/opt/uts-mcp/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    (pip cache purge >/dev/null 2>&1 || true) && \
    (find /opt/uts-mcp/venv -type d \( -name '__pycache__' -o -name 'test' -o -name 'tests' -o -name 'testing' -o -name 'examples' \) -prune -exec rm -rf '{}' + 2>/dev/null || true) && \
    find /opt/uts-mcp/venv -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete 2>/dev/null || true

# ── Shell scripts (only rebuilds if scripts change) ──────────────────────
COPY entrypoint.sh update-databases.sh ./
RUN sed -i 's/\r$//' entrypoint.sh update-databases.sh && \
    chmod +x entrypoint.sh update-databases.sh

# ── Report templates (only rebuilds if templates change) ─────────────────
COPY templates/ ./templates/

# ── PQC scanner script ───────────────────────────────────────────────────
COPY scripts/ ./scripts/

# ── Example playbooks and docs used by runtime seeding ───────────────────
COPY examples/ ./examples/

# ── Pinned subscription trust keys (immutable image layer) ───────────────
COPY config/subscription-keys/ /opt/uts-mcp/config/subscription-keys/

# ── MCP server code (most frequent changes — LAST for fastest rebuild) ───
COPY server.py .
COPY tools/ ./tools/

# ── Directory structure ──────────────────────────────────────────────────
RUN mkdir -p /opt/uts-mcp/output /opt/uts-mcp/logs /opt/uts-mcp/wordlists \
    /opt/uts-mcp/reports /opt/uts-mcp/data && \
    ln -sf /usr/share/wordlists /opt/uts-mcp/wordlists/system && \
    ln -sf /usr/share/seclists /opt/uts-mcp/wordlists/seclists

VOLUME ["/opt/uts-mcp/data", "/opt/uts-mcp/output", "/opt/uts-mcp/reports", "/opt/uts-mcp/logs"]

EXPOSE 8080

ENTRYPOINT ["/opt/uts-mcp/entrypoint.sh"]
      