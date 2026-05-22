# ☠️ VenomRecon v1.0 — Terminator Edition

VenomRecon Autonomous Agent is an advanced Bug Bounty Reconnaissance Automation Framework built in Python. Designed for scale, speed, and deep vulnerability discovery, it orchestrates over 60+ external OSINT and security testing tools to map out attack surfaces, discover exposed secrets, and automate vulnerability scanning.

## WARNING

**AUTHORIZED USE ONLY**
Use VenomRecon strictly on assets you own, or where you have explicit written permission to test. Unauthorized use of this tool against targets is illegal and unethical.
<img width="1672" height="941" alt="image" src="https://github.com/user-attachments/assets/a5ec7dd5-0035-4feb-96a8-a6498bae06c9" />


## ⚡ Features
VenomRecon executes a massive 13-phase reconnaissance pipeline:
- Subdomain Discovery (Passive & Active)
- Takeover Checks
- Tech Fingerprinting & Port Scanning
- Content Discovery & Dirbusting
- Parameter Discovery
- Archive & Wayback Machine Scraping
- JavaScript Static Analysis & Secret Extraction
- GitHub Dorking & Secrets Scanning
- Cloud Asset Enumeration (AWS, Azure, GCP)
- DNS, ASN, and Open Ports Intelligence
- Vulnerability Scanning (XSS, SQLi, LFI, SSRF, CORS)
- Nuclei Mass Scanning
- Markdown & JSON Report Generation
## 📦 Dependencies & Installation

VenomRecon relies heavily on external Golang tools, Python scripts, and SecLists. It is strictly designed to run on Linux (specifically Kali Linux / WSL).

## 1. Clone the Repository
```bash
git clone https://github.com/avartraj/venomrecon.git
cd venomrecon
```

## 2. Install Python Requirements
```bash
pip install -r requirements.txt
```

## 3. Run the Automated Installer
VenomRecon ships with a fully automated installer that handles apt, go install, pip, and external GitHub script cloning.
```bash
cd installers/
chmod +x install.sh
./install.sh
```
**IMPORTANT**
- SecLists is strictly required. The installer will attempt to install it, but ensure `/usr/share/wordlists/seclists` exists on your machine.
- VenomRecon will refuse to run without it.

## 4. Verify Your Environment
Run the VenomRecon Doctor to ensure all 60+ tools, wordlists, and scripts are correctly installed and mapped:
```bash
python src/venomrecon/main.py --doctor
```
If tools are missing, you can let the doctor auto-install them via WSL:
```bash
python src/venomrecon/main.py --doctor --install-missing
```

## 🔑 Configuration (API Keys)
To maximize your reconnaissance results, you should configure your API keys.
- Copy the example environment file:
```bash
cp .env.example .env
```
- Open `.env` and fill in your keys (Shodan, GitHub, SecurityTrails, etc.).
- Never commit `.env` to GitHub. It is ignored by `.gitignore` by default.

## 🚀 Usage
VenomRecon is designed to be highly autonomous. You select a target and a "Scan Profile," and the framework handles the rest.

## Scan Profiles
types:
- **passive:** Safe, read-only OSINT. Subdomain gathering, archive scraping, and DNS checks ONLY. No packets are sent directly to the target infrastructure.
- **standard:** (Default) Active probing, dirbusting, and port scanning. Vulnerability scans and cloud checks are skipped to save time and reduce noise.
- **aggressive:** Full assault. Enables all 13 phases, including 105+ active vulnerability checks (Nuclei, XSS, SQLi, LFI, SSRF, CORS, etc.).

## Wildcard vs Single-Host Mode

### Wildcard Mode (-w)
Use this when your target is a root domain (e.g., `example.com`). It will run aggressive subdomain enumeration, DNS brute-forcing, and map out the entire attack surface before moving to the next phases.

### Single-Host Mode (Default)
If you do not use `-w`, the tool assumes your target is a single endpoint (e.g., `api.example.com` or `https://sub.example.com`). It will bypass full subdomain enumeration and jump straight into content discovery and vulnerability scanning for that specific host.

## Examples

### Single-Host Scan (Default)
(Jumps straight to content discovery and vulnerabilities on a single host)

```bash
python src/venomrecon/main.py -d api.target.com --agree-tos
```

### Wildcard Subdomain Scan
(Runs full subdomain enumeration & brute force on the root domain first)

```bash
python src/venomrecon/main.py -d target.com -w --agree-tos
```

### Aggressive Wildcard Vulnerability Scan:
```bash
python src/venomrecon/main.py -d target.com -w --profile aggressive --agree-tos
```

### Passive OSINT Only:
```bash
python src/venomrecon/main.py -d target.com --profile passive --agree-tos
```

### Skip Specific Phases (e.g., skip GitHub and Cloud recon):
```bash
python src/venomrecon/main.py -d target.com --skip 8,9 --agree-tos
```

## Output
Results are automatically organized into `results_<domain>/`. You will find:
- `report.md`: The final human-readable executive summary.
- `report.json`: Machine-readable results.
- `live_subdomains.txt`: Filtered, live endpoints.
- `all_confirmed_vulns.txt`: Verified vulnerabilities.
- Extracted JavaScript secrets, parameters, and more.
