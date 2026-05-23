#!/bin/bash
# =============================================================================
#  VenomRecon v1.0 — One-Shot Dependency Installer
#  Target: WSL Kali Linux (or any Debian/Ubuntu system with Go ≥ 1.21)
#  Run via:  bash installers/install.sh   (from repo root)
#         OR cd installers && bash install.sh  (works from anywhere now)
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

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
echo "  Project root: $PROJECT_ROOT"
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

# Check npm for getJS
if ! command -v npm &>/dev/null; then
    echo "[*] npm not found — will install nodejs..."
    sudo apt-get install -y -qq nodejs npm 2>/dev/null || true
fi

# ── System packages ────────────────────────────────────────────────────────

echo ""
echo "[+] Installing system packages (apt)..."
sudo apt-get update -qq

apt_install() {
    echo "    -> apt: $1"
    sudo apt-get install -y -qq "$1" 2>/dev/null || echo "    [!] Failed: apt $1 (non-fatal)"
}

apt_install git
apt_install curl
apt_install wget
apt_install dnsutils
apt_install whois
apt_install nmap
apt_install masscan
apt_install whatweb
apt_install ruby
apt_install ruby-dev
apt_install build-essential
apt_install cargo
apt_install libpcap-dev
apt_install libssl-dev
apt_install nodejs
apt_install npm

# wpscan via gem (apt version is often stale)
if ! command -v wpscan &>/dev/null; then
    echo "    -> gem: wpscan"
    sudo gem install wpscan --quiet 2>/dev/null || echo "    [!] Failed: wpscan (non-fatal)"
fi

if ! command -v gh &>/dev/null; then
    echo ""
    echo "[+] Installing GitHub CLI (gh)..."
    curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
        | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg 2>/dev/null
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
        | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
    sudo apt-get update -qq 2>/dev/null
    apt_install gh
fi

# ── Go tools ───────────────────────────────────────────────────────────────

go_install() {
    echo "    -> $1"
    go install "$1" 2>/dev/null || echo "    [!] Failed: $1 (non-fatal)"
}

echo ""
echo "[+] Installing ProjectDiscovery tools..."
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
go_install "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"

echo ""
echo "[+] Installing Tomnomnom tools..."
go_install "github.com/tomnomnom/assetfinder@latest"
go_install "github.com/tomnomnom/waybackurls@latest"
go_install "github.com/tomnomnom/qsreplace@latest"
go_install "github.com/tomnomnom/gf@latest"
go_install "github.com/tomnomnom/hacks/kxss@latest"

echo ""
echo "[+] Installing discovery tools..."
go_install "github.com/lc/gau/v2/cmd/gau@latest"
go_install "github.com/lc/subjs@latest"
go_install "github.com/hakluke/hakrawler@latest"
go_install "github.com/hakluke/haktrails@latest"
go_install "github.com/jaeles-project/gospider@latest"
go_install "github.com/d3mondev/puredns/v2@latest"
go_install "github.com/gwen001/github-subdomains@latest"

echo ""
echo "[+] Installing subdomain takeover tools..."
go_install "github.com/LukaSikic/subzy@latest"
go_install "github.com/haccer/subjack@latest"
go_install "github.com/anshumanbh/tko-subs@latest"
go_install "github.com/ffuf/ffuf/v2@latest"
go_install "github.com/OJ/gobuster/v3@latest"

echo ""
echo "[+] Installing XSS & fuzzing tools..."
go_install "github.com/hahwul/dalfox/v2@latest"
go_install "github.com/KathanP19/Gxss@latest"
go_install "github.com/takshal/freq@latest"
go_install "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
go_install "github.com/lobuhi/byp4xx@latest"
go_install "github.com/kleiton0x00/ppmap@latest"

echo ""
echo "[+] Installing JS recon tools..."
go_install "github.com/BishopFox/jsluice/cmd/jsluice@latest"
go_install "github.com/Josue87/gotator@latest"

echo ""
echo "[+] Installing GitHub recon tools..."
go_install "github.com/gitleaks/gitleaks/v8@latest"
go_install "github.com/trufflesecurity/trufflehog/v3@latest"

# ── massdns (from source) ──────────────────────────────────────────────────

echo ""
echo "[+] Building massdns from source..."
if ! command -v massdns &>/dev/null; then
    # save and restore the working directory explicitly.
    _SAVED_DIR="$(pwd)"
    cd /tmp
    git clone --depth 1 https://github.com/blechschmidt/massdns.git massdns_build 2>/dev/null || true
    if [ -d massdns_build ]; then
        cd massdns_build
        make -j"$(nproc)" 2>/dev/null
        sudo cp bin/massdns /usr/local/bin/ 2>/dev/null || true
        cd /tmp
        rm -rf massdns_build
        echo "[+] massdns installed."
    fi
    cd "$_SAVED_DIR"
else
    echo "[+] massdns already installed."
fi

# ── findomain (binary release) ─────────────────────────────────────────────
# BUG-FIX-NEW: findomain was completely absent from install.sh

echo ""
echo "[+] Installing findomain..."
if ! command -v findomain &>/dev/null; then
    _arch="$(uname -m)"
    if [ "$_arch" = "x86_64" ]; then
        curl -sL "https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip" \
             -o /tmp/findomain.zip 2>/dev/null \
        && sudo unzip -oq /tmp/findomain.zip -d /usr/local/bin/ \
        && sudo chmod +x /usr/local/bin/findomain \
        && rm -f /tmp/findomain.zip \
        && echo "[+] findomain installed." \
        || echo "[!] Failed: findomain (non-fatal)"
    else
        echo "[!] findomain: unsupported arch $arch — install manually"
    fi
else
    echo "[+] findomain already installed."
fi

# ── feroxbuster (binary release — faster than cargo) ──────────────────────

echo ""
echo "[+] Installing feroxbuster..."
if ! command -v feroxbuster &>/dev/null; then
    curl -sL "https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster_linux-amd64.deb" \
         -o /tmp/feroxbuster.deb 2>/dev/null \
    && sudo dpkg -i /tmp/feroxbuster.deb 2>/dev/null \
    && rm -f /tmp/feroxbuster.deb \
    && echo "[+] feroxbuster installed." \
    || echo "[!] Failed: feroxbuster deb — trying cargo..." \
    && cargo install feroxbuster 2>/dev/null \
    || echo "[!] Failed: feroxbuster (non-fatal)"
else
    echo "[+] feroxbuster already installed."
fi

# ── x8 (binary release) ───────────────────────────────────────────────────

echo ""
echo "[+] Installing x8..."
if ! command -v x8 &>/dev/null; then
    curl -sL "https://github.com/Sh1Yo/x8/releases/latest/download/x86_64-linux-x8" \
         -o /tmp/x8 2>/dev/null \
    && sudo mv /tmp/x8 /usr/local/bin/x8 \
    && sudo chmod +x /usr/local/bin/x8 \
    && echo "[+] x8 installed." \
    || echo "[!] Failed: x8 binary — trying cargo..." \
    && cargo install x8 2>/dev/null \
    || echo "[!] Failed: x8 (non-fatal)"
else
    echo "[+] x8 already installed."
fi

# ── getJS (npm) ───────────────────────────────────────────────────────────

echo ""
echo "[+] Installing getJS (npm)..."
if ! command -v getJS &>/dev/null; then
    npm install -g getjs 2>/dev/null && echo "[+] getJS installed." || echo "[!] Failed: getjs (non-fatal)"
fi

# ── Python packages ────────────────────────────────────────────────────────

export PROJECT_ROOT

if [ -f "$PROJECT_ROOT/installers/install_pip.sh" ]; then
    bash "$PROJECT_ROOT/installers/install_pip.sh"
else
    echo "[!] install_pip.sh not found — skipping Python tools"
fi

# ── External scripts ───────────────────────────────────────────────────────

if [ -f "$PROJECT_ROOT/installers/install_external.sh" ]; then
    bash "$PROJECT_ROOT/installers/install_external.sh"
else
    echo "[!] install_external.sh not found — skipping external scripts"
fi

# ── Wordlists ──────────────────────────────────────────────────────────────

echo ""
echo "[+] Setting up wordlists..."
sudo mkdir -p /usr/share/wordlists

WORDLIST_DIR="$PROJECT_ROOT"
if [ -d "$PROJECT_ROOT/wordlists" ]; then
    WORDLIST_DIR="$PROJECT_ROOT/wordlists"
elif [ -d "$PROJECT_ROOT/src/venomrecon/wordlists" ]; then
    WORDLIST_DIR="$PROJECT_ROOT/src/venomrecon/wordlists"
fi

if [ ! -d "/usr/share/wordlists/seclists" ]; then
    echo "    -> Cloning SecLists (~1.5 GB)..."
    sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git \
         /usr/share/wordlists/seclists 2>/dev/null || true
else
    echo "    -> SecLists already present."
fi

if [ -d "/usr/share/wordlists/seclists" ]; then
    _symlink() {
        [ ! -f "$2" ] && ln -sf "$1" "$2" 2>/dev/null || true
    }
    _symlink /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt     "$WORDLIST_DIR/dns.txt"
    _symlink /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt    "$WORDLIST_DIR/dns_medium.txt"
    _symlink /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt   "$WORDLIST_DIR/dns_large.txt"
    _symlink /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt     "$WORDLIST_DIR/vhosts.txt"
    _symlink /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt   "$WORDLIST_DIR/params.txt"
fi

if [ ! -f "$WORDLIST_DIR/resolvers.txt" ]; then
    echo "    -> Downloading resolvers.txt..."
    curl -sL "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" \
         -o "$WORDLIST_DIR/resolvers.txt" 2>/dev/null || true
fi

# ── nuclei templates & gf patterns ────────────────────────────────────────

echo ""
echo "[+] Updating nuclei templates..."
nuclei -update-templates -silent 2>/dev/null || true

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
echo "  1. source ~/.bashrc   (to reload PATH)"
echo "  2. cd $PROJECT_ROOT"
echo "  3. python3 src/venomrecon/main.py --doctor"
echo "  4. python3 src/venomrecon/main.py -d target.com --agree-tos"
echo "============================================="
