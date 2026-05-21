#!/bin/bash
# =============================================================================
#  VenomRecon v1.0 — One-Shot Dependency Installer
#  Target: WSL Kali Linux (or any Debian/Ubuntu system with Go ≥ 1.21)
#  Run via:  bash install.sh
# =============================================================================

set -e

PROJECT_ROOT="$(pwd)"

print_banner() {
cat << 'EOF'
 ___      ___  _______  ________   ________  _____ ______   ________  _______   ________  ________  ________
|\  \    /  /||\  ___ \|\   ___  \|\   __  \|\   _ \  _   \|\   __  \|\  ___ \ |\   ____\|\   __  \|\   ___  \
\ \  \  /  / /\ \   __/\ \  \\ \  \ \  \|\  \ \  \\\__\ \  \ \  \|\  \ \   __/|\ \  \___|\ \  \|\  \ \  \\ \  \
 \ \  \/  / /  \ \  \_|/_\ \  \\ \  \ \  \\\  \ \  \\|__| \  \ \   _  _\ \  \_|/_\ \  \    \ \  \\\  \ \  \\ \  \
  \ \    / /    \ \  \_|\ \ \  \\ \  \ \  \\\  \ \  \    \ \  \ \  \\  \\ \  \_|\ \ \  \____\ \  \\\  \ \  \\ \  \
   \ \__/ /      \ \_______\ \__\\ \__\ \_______\ \__\    \ \__\ \__\\ _\\ \_______\ \_______\ \_______\ \__\\ \__\
    \|__|/        \|_______|\|__| \|__|\|_______|\|__|     \|__|\|__|\|__|\|_______|\|_______|\|_______|\|__| \|__|

              VenomRecon v1.0 — Power Upgrade Installer
EOF
}

print_banner

echo ""
echo "============================================="
echo "  VenomRecon v1.0 — One-Shot Installer"
echo "  Target: WSL Kali Linux / Debian / Ubuntu"
echo "============================================="
echo ""

# ── Sanity checks ──────────────────────────────────────────────────────────

echo "[*] Checking system requirements..."

if ! command -v go &>/dev/null; then
    echo "[!] Go not found. Installing Go 1.22..."
    cd /tmp
    wget -q https://go.dev/dl/go1.22.3.linux-amd64.tar.gz -O go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go.tar.gz
    rm go.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin:$(go env GOPATH)/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin
    echo "[+] Go installed: $(go version)"
else
    echo "[+] Go found: $(go version)"
fi

export PATH=$PATH:$(go env GOPATH)/bin:$HOME/go/bin

if ! command -v python3 &>/dev/null; then
    echo "[!] Python3 not found. Please install python3."
    exit 1
fi

if ! command -v pip3 &>/dev/null; then
    echo "[!] pip3 not found. Installing..."
    sudo apt-get install -y python3-pip
fi

echo "[+] Python: $(python3 --version)"

# ── System packages ────────────────────────────────────────────────────────

echo ""
echo "[+] Installing system packages (apt)..."
sudo apt-get update -qq
sudo apt-get install -y -qq \
    git curl wget dnsutils whois nmap masscan wpscan whatweb cloud-enum \
    ruby ruby-dev build-essential cargo \
    libpcap-dev libssl-dev \
    2>/dev/null || true

# ── ProjectDiscovery toolkit ───────────────────────────────────────────────

echo ""
echo "[+] Installing ProjectDiscovery tools..."

go_install() {
    echo "    -> $1"
    go install -v "$1" 2>/dev/null || echo "    [!] Failed: $1 (non-fatal)"
}

go_install "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
go_install "github.com/projectdiscovery/httpx/cmd/httpx@latest"
go_install "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
go_install "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
go_install "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
go_install "github.com/projectdiscovery/katana/cmd/katana@latest"
go_install "github.com/projectdiscovery/alterx/cmd/alterx@latest"
go_install "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
go_install "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
go_install "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"

# chaos-client
go_install "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"

# ── Tomnomnom tools ────────────────────────────────────────────────────────

echo ""
echo "[+] Installing Tomnomnom tools..."
go_install "github.com/tomnomnom/assetfinder@latest"
go_install "github.com/tomnomnom/waybackurls@latest"
go_install "github.com/tomnomnom/qsreplace@latest"
go_install "github.com/tomnomnom/gf@latest"
go_install "github.com/tomnomnom/hacks/kxss@latest"

# ── Discovery & crawling ───────────────────────────────────────────────────

echo ""
echo "[+] Installing discovery tools..."
go_install "github.com/lc/gau/v2/cmd/gau@latest"
go_install "github.com/lc/subjs@latest"
go_install "github.com/hakluke/hakrawler@latest"
go_install "github.com/hakluke/haktrails@latest"
go_install "github.com/jaeles-project/gospider@latest"
go_install "github.com/d3mondev/puredns/v2@latest"
go_install "github.com/gwen001/github-subdomains@latest"

# ── Takeover tools ─────────────────────────────────────────────────────────

echo ""
echo "[+] Installing subdomain takeover tools..."
go_install "github.com/PentestPadawan/subzy@latest"
go_install "github.com/haccer/subjack@latest"
go_install "github.com/anshumanbh/tko-subs@latest"
go_install "github.com/ffuf/ffuf/v2@latest"
go_install "github.com/OJ/gobuster/v3@latest"

# ── XSS & fuzzing ──────────────────────────────────────────────────────────

echo ""
echo "[+] Installing XSS & fuzzing tools..."
go_install "github.com/hahwul/dalfox/v2@latest"
go_install "github.com/KathanP19/Gxss@latest"
go_install "github.com/takshal/freq@latest"
go_install "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
go_install "github.com/lobuhi/byp4xx@latest"
go_install "github.com/kleiton0x00/ppmap@latest"

# ── JS recon ───────────────────────────────────────────────────────────────

echo ""
echo "[+] Installing JS recon tools..."
go_install "github.com/BishopFox/jsluice/cmd/jsluice@latest"
go_install "github.com/Josue87/gotator@latest"

# ── GitHub tools ───────────────────────────────────────────────────────────

echo ""
echo "[+] Installing GitHub recon tools..."
go_install "github.com/gitleaks/gitleaks/v8@latest"

# ── massdns ────────────────────────────────────────────────────────────────

echo ""
echo "[+] Building massdns from source..."
if ! command -v massdns &>/dev/null; then
    cd /tmp
    git clone --depth 1 https://github.com/blechschmidt/massdns.git massdns_build 2>/dev/null || true
    if [ -d massdns_build ]; then
        cd massdns_build && make -j$(nproc) && sudo cp bin/massdns /usr/local/bin/ && cd /tmp && rm -rf massdns_build
        echo "[+] massdns installed."
    fi
else
    echo "[+] massdns already installed."
fi

# ── Python packages ────────────────────────────────────────────────────────

if [ -f "$PROJECT_ROOT/installers/install_pip.sh" ]; then
    bash "$PROJECT_ROOT/installers/install_pip.sh"
else
    echo "[!] install_pip.sh not found in installers/ directory"
fi

# ── External scripts ───────────────────────────────────────────────────────

if [ -f "$PROJECT_ROOT/installers/install_external.sh" ]; then
    bash "$PROJECT_ROOT/installers/install_external.sh"
else
    echo "[!] install_external.sh not found in installers/ directory"
fi

# ── Wordlists ──────────────────────────────────────────────────────────────

echo ""
echo "[+] Setting up wordlists..."
sudo mkdir -p /usr/share/wordlists

WORDLIST_DIR="$PROJECT_ROOT"
# Figure out the project wordlists dir
if [ -d "$PROJECT_ROOT/wordlists" ]; then
    WORDLIST_DIR="$PROJECT_ROOT/wordlists"
elif [ -d "$PROJECT_ROOT/src/venomrecon/wordlists" ]; then
    WORDLIST_DIR="$PROJECT_ROOT/src/venomrecon/wordlists"
fi

if [ ! -d "/usr/share/wordlists/seclists" ]; then
    echo "    -> Cloning SecLists (~1.5 GB)..."
    sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/seclists 2>/dev/null || true
else
    echo "    -> SecLists already present."
fi

# Symlink/copy key SecLists files into the project wordlists dir if missing
if [ -d "/usr/share/wordlists/seclists" ]; then
    # DNS wordlists (tiered)
    [ ! -f "$WORDLIST_DIR/dns.txt" ] && \
        ln -sf /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
               "$WORDLIST_DIR/dns.txt" 2>/dev/null || true

    [ ! -f "$WORDLIST_DIR/dns_medium.txt" ] && \
        ln -sf /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
               "$WORDLIST_DIR/dns_medium.txt" 2>/dev/null || true

    [ ! -f "$WORDLIST_DIR/dns_large.txt" ] && \
        ln -sf /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
               "$WORDLIST_DIR/dns_large.txt" 2>/dev/null || true

    # VHosts wordlist
    [ ! -f "$WORDLIST_DIR/vhosts.txt" ] && \
        ln -sf /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
               "$WORDLIST_DIR/vhosts.txt" 2>/dev/null || true

    # Params wordlist
    [ ! -f "$WORDLIST_DIR/params.txt" ] && \
        ln -sf /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt \
               "$WORDLIST_DIR/params.txt" 2>/dev/null || true
fi

# Download a public resolvers list if missing
if [ ! -f "$WORDLIST_DIR/resolvers.txt" ]; then
    echo "    -> Downloading resolvers.txt..."
    curl -sL "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" \
         -o "$WORDLIST_DIR/resolvers.txt" 2>/dev/null || true
fi

# ── nuclei templates update ────────────────────────────────────────────────

echo ""
echo "[+] Updating nuclei templates..."
nuclei -update-templates -silent 2>/dev/null || true

# ── GF patterns ────────────────────────────────────────────────────────────

echo ""
echo "[+] Installing gf patterns..."
GF_PATTERNS_DIR="$HOME/.gf"
mkdir -p "$GF_PATTERNS_DIR"
if [ ! -d "/tmp/Gf-Patterns" ]; then
    git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns /tmp/Gf-Patterns 2>/dev/null || true
fi
[ -d /tmp/Gf-Patterns ] && cp /tmp/Gf-Patterns/*.json "$GF_PATTERNS_DIR/" 2>/dev/null || true

# ── PATH reminder ──────────────────────────────────────────────────────────

GOBIN="$(go env GOPATH)/bin"
if ! echo "$PATH" | grep -q "$GOBIN"; then
    echo ""
    echo "[!] Add Go binaries to PATH permanently:"
    echo "    echo 'export PATH=\$PATH:$GOBIN' >> ~/.bashrc && source ~/.bashrc"
fi

# ── Done ───────────────────────────────────────────────────────────────────

echo ""
echo "============================================="
echo "[SUCCESS] VenomRecon v1.0 install complete!"
echo ""
echo "Next steps:"
echo "  1. source ~/.bashrc   (to load Go PATH)"
echo "  2. export GITHUB_TOKEN=ghp_xxxx"
echo "  3. export SHODAN_API_KEY=xxxx  (optional)"
echo "  4. export CHAOS_API_KEY=xxxx   (optional)"
echo "  5. export BEVIGIL_API_KEY=xxxx (optional)"
echo "  6. python3 src/venomrecon/main.py --doctor"
echo "  7. python3 src/venomrecon/main.py -d target.com --agree-tos"
echo "============================================="
