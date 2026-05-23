# ☠️ VenomRecon v1.0 — Terminator Edition

VenomRecon is an autonomous Bug Bounty Reconnaissance Automation Framework built in Python. It orchestrates 60+ external OSINT and security tools across a 13-phase pipeline, mapping the full attack surface, extracting secrets, and running 105+ active vulnerability checks without you touching a single command between phases.

### Authorized Use Only

Use VenomRecon strictly on assets you own or where you have explicit written permission to test. Unauthorized use is illegal and unethical.


<img width="1280" height="702" alt="image" src="https://github.com/user-attachments/assets/dee67cc2-5db6-4a96-8e54-879bc85ba7c8" />


---

## Features

VenomRecon runs a 13-phase autonomous reconnaissance pipeline:

| Phase | Name | What it does |
|-------|------|-------------|
| 1 | Subdomain Enumeration | Passive + active subdomain discovery via 15+ sources, DNS brute-force, permutation |
| 2 | Subdomain Takeover | Checks all discovered subdomains for takeover via subzy, subjack, tko-subs |
| 3 | Tech Fingerprinting | whatweb, httpx tech-detect, Shodan, screenshots, WAF detection |
| 4 | Content Discovery | Crawling, dirbusting (ffuf, feroxbuster, gobuster), vhost fuzzing |
| 5 | Parameter Discovery | arjun, paramspider, x8, gf pattern matching |
| 6 | Archive & DNS History | Wayback Machine, gau, SecurityTrails passive DNS |
| 7 | JavaScript Recon | jsluice, SecretFinder, LinkFinder — endpoints and secrets from JS files |
| 8 | GitHub Recon | github-subdomains, gitleaks, GitDorker, trufflehog |
| 9 | Cloud Recon | AWS/Azure/GCP asset enumeration via cloud_enum, CloudHunter |
| 10 | DNS / ASN / Ports | dnsx, asnmap, nmap, masscan, zone transfer, DNSSEC, SPF/DMARC/DKIM |
| 11 | Vulnerability Scanning | 105+ checks: XSS, SQLi, LFI, SSRF, CORS, SSTI, open redirect, host header, and more |
| 12 | Nuclei Mass Scan | Full nuclei template run across all live targets |
| 13 | Report Generation | Markdown executive summary + machine-readable JSON |

---

## Requirements

- **OS:** Kali Linux, Ubuntu, or Debian (WSL supported)
- **Python:** ≥ 3.10
- **Go:** ≥ 1.21
- **Disk:** ~10 GB free (SecLists is ~1.5 GB, Go tools add ~2 GB)
- **RAM:** 4 GB minimum, 8 GB recommended for aggressive scans

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/avartraj/venomrecon.git
cd venomrecon
```

### 2. Run the Automated Installer

The installer handles everything: apt packages, Go tools, pip packages, external Python scripts, wordlists, nuclei templates, and gf patterns. Run it from the **repo root**:

```bash
chmod +x installers/install.sh
bash installers/install.sh
```

> **Note:** Do not `cd` into `installers/` before running. The installer resolves its own paths, running it from inside the directory will break internal path lookups.

> **Note:** SecLists (~1.5 GB) is cloned during install. VenomRecon will refuse to run without it at `/usr/share/wordlists/seclists`.

### 3. Configure API Keys

Copy the example env file and fill in your keys:

```bash
cp .env.example .env
```

Open `.env` and add your keys. The more you fill in, the better your results:

```bash
# Required for GitHub dorking and subdomain discovery
GITHUB_TOKEN=

# Intelligence and passive recon
SHODAN_API_KEY=
SECURITYTRAILS_API_KEY=
CHAOS_API_KEY=
BEVIGIL_API_KEY=
LEAKIX_API_KEY=
CENSYS_API_KEY=
VIRUSTOTAL_API_KEY=
ALIENVAULT_API_KEY=
INTELX_API_KEY=
NETLAS_API_KEY=
ZOOMEYE_API_KEY=
THREATBOOK_API_KEY=

# Vulnerability scanning
WPSCAN_API_KEY=
DNSDUMPSTER_API_KEY=
CERTSPOTTER_API_KEY=
DIGITALYAMA_API_KEY=
PUGRECON_API_KEY=
```

> **Never commit `.env` to GitHub.** It is gitignored by default.

### 4. Verify Your Environment

Run the doctor to check that all 60+ tools, wordlists, API keys, and external scripts are correctly installed:

```bash
python src/venomrecon/main.py --doctor
```

If tools are missing at the end of a scan, pass `--install-missing` and VenomRecon will attempt to auto-install them via WSL:

```bash
python src/venomrecon/main.py -d target.com --agree-tos --install-missing
```

---

## Usage

```
python src/venomrecon/main.py [-d DOMAIN] [-w] [-o OUTDIR] [-t THREADS]
                              [--resume] [--skip PHASES] [--profile PROFILE]
                              [--agree-tos] [--dry-run] [-v] [--doctor]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-d, --domain` | — | Target domain or URL |
| `-w, --wildcard` | off | Force full subdomain enumeration on root domain |
| `-o, --outdir` | `results_<domain>` | Custom output directory |
| `-t, --threads` | 8 | Worker thread count |
| `--resume` | off | Skip phases that already produced output files |
| `--skip` | — | Comma-separated phase numbers to skip, e.g. `--skip 8,9` |
| `--profile` | `standard` | Scan depth: `passive`, `standard`, or `aggressive` |
| `--agree-tos` | off | Skip the authorization prompt |
| `--dry-run` | off | Print planned commands without executing anything |
| `-v, --verbose` | off | Show debug output |
| `--doctor` | off | Check tool/wordlist/API key status |
| `--install-missing` | off | Auto-install missing tools via WSL after scan |

### Scan Profiles

| Profile | Description |
|---------|-------------|
| `passive` | Safe, read-only OSINT only. Subdomain gathering, archive scraping, DNS checks. No packets sent directly to target infrastructure. |
| `standard` | (Default) Active probing, dirbusting, and port scanning. Vulnerability scanning and cloud checks are skipped. |
| `aggressive` | Full 13-phase run. All 105+ active vulnerability checks enabled — XSS, SQLi, LFI, SSRF, CORS, Nuclei mass scan, etc. |

---

## Scan Modes

### Wildcard Mode (`-w`)

Use when your target is a root domain. Runs full subdomain enumeration, DNS brute-forcing, and permutation before moving to the next phases.

```bash
python src/venomrecon/main.py -d target.com -w --agree-tos
```

### Single-Host Mode (default)

Use when your target is a specific endpoint. Bypasses subdomain enumeration and goes straight to content discovery and vulnerability scanning on that host.

```bash
python src/venomrecon/main.py -d api.target.com --agree-tos
```

### URL Mode

Pass a full URL and VenomRecon will skip phases 1 and 2, seeding the pipeline directly with that endpoint.

```bash
python src/venomrecon/main.py -d https://api.target.com/v2 --agree-tos
```

---

## Examples

```bash
# Full aggressive wildcard scan
python src/venomrecon/main.py -d target.com -w --profile aggressive --agree-tos

# Passive OSINT only, no active probing
python src/venomrecon/main.py -d target.com --profile passive --agree-tos

# Skip GitHub and Cloud phases
python src/venomrecon/main.py -d target.com -w --skip 8,9 --agree-tos

# Resume an interrupted scan
python src/venomrecon/main.py -d target.com -w --profile aggressive --resume --agree-tos

# Custom output directory with 16 threads
python src/venomrecon/main.py -d target.com -w -o /tmp/target_recon -t 16 --agree-tos

# Dry run — see what commands would execute without firing anything
python src/venomrecon/main.py -d target.com -w --profile aggressive --dry-run --agree-tos
```

---

## Output

All results are written to `results_<domain>/` (or your custom `-o` path):

| File | Contents |
|------|----------|
| `report.md` | Human-readable executive summary of all findings |
| `report.json` | Machine-readable results for pipeline integration |
| `live_subdomains.txt` | Confirmed live endpoints |
| `all_subdomains.txt` | Full deduplicated subdomain list |
| `all_crawled_urls.txt` | All URLs discovered across crawlers |
| `all_confirmed_vulns.txt` | Verified vulnerability findings |
| `param_urls.txt` | URLs with parameters (arjun, gf output) |
| `js_secrets.txt` | Secrets extracted from JavaScript files |
| `nuclei_*.txt` | Nuclei findings by tag |
| `venomrecon.log` | Full execution log |
| `errors.txt` | Tools that failed or timed out |

---

## Contributing
  
Pull requests are welcome. If you're adding a new probe, module, or tool integration, keep it consistent with the existing phase structure and make sure it degrades gracefully when the underlying tool is missing. Open an issue first if you're proposing something that touches the core pipeline.
 
For bug reports, include your `--doctor` output and the relevant section of `venomrecon.log`.
 
---

## Legal
 
VenomRecon is built for security professionals conducting authorized assessments. You are solely responsible for how you use this tool.
 
- Only run against targets you own or have explicit written permission to test
- Bug bounty use: stay within the defined scope of the program
- Do not use against critical infrastructure, government systems, or any target where you lack authorization
 
The authors accept no liability for misuse.
 
---
