#!/bin/bash
# External scripts installation

echo ""
echo "[+] Cloning external scripts..."
SCRIPTS_DIR="$HOME/venomrecon-scripts"
mkdir -p "$SCRIPTS_DIR"
cd "$SCRIPTS_DIR"

clone_script() {
    local name="$1"
    local url="$2"
    if [ ! -d "$name" ]; then
        echo "    -> Cloning $name..."
        git clone --depth 1 "$url" "$name" 2>/dev/null || echo "    [!] Failed to clone $name (non-fatal)"
    else
        echo "    -> $name already cloned."
    fi
}

clone_script "SecretFinder"  "https://github.com/m4ll0k/SecretFinder"
clone_script "LinkFinder"    "https://github.com/GerbenJavado/LinkFinder"
clone_script "GitDorker"     "https://github.com/obheda12/GitDorker"
clone_script "cloudhunter"   "https://github.com/belane/CloudHunter.git"
clone_script "CORStest"      "https://github.com/RUB-NDS/CORStest"
clone_script "Corsy"         "https://github.com/s0md3v/Corsy"
clone_script "tplmap"        "https://github.com/epinna/tplmap"
curl -sL https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json -o ~/venomrecon-scripts/fingerprints.json
