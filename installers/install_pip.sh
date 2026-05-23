#!/bin/bash
# VenomRecon — Python package installer

if [ -z "${PROJECT_ROOT:-}" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
fi

echo ""
echo "[+] Installing Python tools..."

pip_install() {
    echo "    -> pip: $1"
    pip3 install "$1" --break-system-packages -q 2>/dev/null \
        || pip3 install "$1" -q 2>/dev/null \
        || echo "    [!] Failed: $1 (non-fatal)"
}

pip_install "dnsgen"
pip_install "dirsearch"
pip_install "arjun"
pip_install "paramspider"
pip_install "uro"
pip_install "sqlmap"
pip_install "git+https://github.com/r0oth3x49/ghauri.git"
pip_install "dnsrecon"
pip_install "wafw00f"
pip_install "bevigil-cli"      
pip_install "shodan"
pip_install "requests"

pip_install "mmh3"

REQUIREMENTS="$PROJECT_ROOT/requirements.txt"
if [ -f "$REQUIREMENTS" ]; then
    echo "    -> requirements.txt"
    pip3 install -r "$REQUIREMENTS" --break-system-packages -q 2>/dev/null \
        || pip3 install -r "$REQUIREMENTS" -q 2>/dev/null \
        || echo "    [!] Failed: requirements.txt (non-fatal)"
else
    echo "    [*] No requirements.txt found at $REQUIREMENTS — skipping"
fi
