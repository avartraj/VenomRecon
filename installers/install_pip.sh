#!/bin/bash
# pip packages installation

echo ""
echo "[+] Installing Python tools..."

pip_install() {
    echo "    -> pip: $1"
    pip3 install "$1" --break-system-packages -q 2>/dev/null || pip3 install "$1" -q 2>/dev/null || echo "    [!] Failed: $1 (non-fatal)"
}

# Core requirements
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

# Project requirements
if [ -f "requirements.txt" ]; then
    echo "    -> requirements.txt"
    pip3 install -r requirements.txt --break-system-packages -q 2>/dev/null || pip3 install -r requirements.txt -q
fi
