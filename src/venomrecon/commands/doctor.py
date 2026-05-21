"""Dependency validation for VenomRecon."""

import os
import shutil

from core.config import config
from core.logger import Colors


TOOL_REGISTRY = {
    # Phase 1 – Subdomain Discovery
    "subfinder":          ([1], "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    "assetfinder":        ([1], "go install github.com/tomnomnom/assetfinder@latest"),
    "findomain":          ([1], "https://github.com/findomain/findomain"),
    "thexrecon":          ([1], "optional - manual install"),
    "haktrails":          ([1], "go install github.com/hakluke/haktrails@latest"),
    "github-subdomains":  ([1], "go install github.com/gwen001/github-subdomains@latest"),
    "chaos":              ([1], "go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest"),
    "alterx":             ([1], "go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest"),
    "gotator":            ([1], "go install github.com/Josue87/gotator@latest"),
    "bevigil-cli":        ([1], "pip install bevigil-osint"),
    "dnsgen":             ([1], "pip install dnsgen"),
    "massdns":            ([1], "https://github.com/blechschmidt/massdns"),
    "puredns":            ([1], "go install github.com/d3mondev/puredns/v2@latest"),
    "shuffledns":         ([1], "go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"),
    "dnsx":               ([1, 3, 10], "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
    "ffuf":               ([1, 4], "go install github.com/ffuf/ffuf/v2@latest"),
    "gobuster":           ([1, 4], "go install github.com/OJ/gobuster/v3@latest"),
    "httpx":              ([1, 3, 4, 11], "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    "wafw00f":            ([1, 3], "pip install wafw00f"),
    "cdncheck":           ([1], "go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"),
    "asnmap":             ([1, 10], "go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest"),
    # Phase 2 – Takeover
    "subzy":              ([2], "go install -v github.com/PentestPadawan/subzy@latest"),
    "subjack":            ([2], "go install github.com/haccer/subjack@latest"),
    "tko-subs":           ([2], "go install github.com/anshumanbh/tko-subs@latest"),
    "dig":                ([2, 10], "apt install dnsutils"),
    "nuclei":             ([2, 11, 12], "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    # Phase 3 – Tech Fingerprinting
    "shodan":             ([3], "pip install shodan"),
    "whatweb":            ([3], "gem install whatweb"),
    "wpscan":             ([3, 11], "gem install wpscan"),
    # Phase 4 – Content Discovery
    "gau":                ([4, 6], "go install github.com/lc/gau/v2/cmd/gau@latest"),
    "waybackurls":        ([4, 6], "go install github.com/tomnomnom/waybackurls@latest"),
    "hakrawler":          ([4], "go install github.com/hakluke/hakrawler@latest"),
    "katana":             ([4], "go install github.com/projectdiscovery/katana/cmd/katana@latest"),
    "gospider":           ([4], "go install github.com/jaeles-project/gospider@latest"),
    "dirsearch":          ([4], "pip install dirsearch"),
    "feroxbuster":        ([4], "cargo install feroxbuster"),
    "byp4xx":             ([4, 11], "go install github.com/lobuhi/byp4xx@latest"),
    # Phase 5 – Parameter Discovery
    "uro":                ([5], "pip install uro"),
    "arjun":              ([5], "pip install arjun"),
    "paramspider":        ([5], "pip install paramspider"),
    "x8":                 ([5], "cargo install x8"),
    "gf":                 ([5, 9], "go install github.com/tomnomnom/gf@latest"),
    # Phase 7 – JS Recon
    "getJS":              ([7], "npm install -g getjs"),
    "subjs":              ([7], "go install github.com/lc/subjs@latest"),
    "jsluice":            ([7], "go install github.com/BishopFox/jsluice/cmd/jsluice@latest"),
    # Phase 8 – GitHub Recon
    "trufflehog":         ([8], "brew install trufflehog"),
    "gitleaks":           ([8], "go install github.com/gitleaks/gitleaks/v8@latest"),
    "gh":                 ([8], "https://cli.github.com/"),
    # Phase 9 – Cloud Recon
    "cloud_enum":         ([9], "pip install cloud-enum"),
    # Phase 10 – DNS/ASN/Ports
    "whois":              ([10], "apt install whois"),
    "dnsrecon":           ([10], "pip install dnsrecon"),
    "nmap":               ([10], "apt install nmap"),
    "masscan":            ([10], "apt install masscan"),
    "corsy":              ([10], "pip install corsy - or clone https://github.com/s0md3v/Corsy"),
    # Phase 11 – Vulnerability Scanning
    "sqlmap":             ([11], "pip install sqlmap"),
    "ghauri":             ([11], "pip install ghauri"),
    "dalfox":             ([11], "go install github.com/hahwul/dalfox/v2@latest"),
    "Gxss":              ([11], "go install github.com/KathanP19/Gxss@latest"),
    "kxss":              ([11], "go install github.com/tomnomnom/hacks/kxss@latest"),
    "freq":              ([11], "go install github.com/takshal/freq@latest"),
    "qsreplace":         ([11], "go install github.com/tomnomnom/qsreplace@latest"),
    "interactsh-client": ([11], "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"),
    "crlfuzz":           ([11], "go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"),
    "ppmap":             ([11], "go install github.com/kleiton0x00/ppmap@latest"),
}

EXTERNAL_SCRIPTS = {
    "SecretFinder.py": "https://github.com/m4ll0k/SecretFinder",
    "linkfinder.py":   "https://github.com/GerbenJavado/LinkFinder",
    "GitDorker.py":    "https://github.com/obheda12/GitDorker",
    "cloudhunter.py":  "https://github.com/belane/CloudHunter",
    "CORStest.py":     "https://github.com/RUB-NDS/CORStest",
    "corsy.py":        "https://github.com/s0md3v/Corsy",
    "tplmap.py":       "https://github.com/epinna/tplmap",
}

CORE_TOOLS = {"subfinder", "httpx", "nuclei"}


def _phases_skipped(phases: list[int], skip_phases: set[int]) -> bool:
    return all(phase in skip_phases for phase in phases)


def check_external_scripts(script_dir: str) -> list[dict]:
    results = []
    scripts_map = {
        "SecretFinder.py": "SecretFinder/SecretFinder.py",
        "linkfinder.py":   "LinkFinder/linkfinder.py",
        "GitDorker.py":    "GitDorker/GitDorker.py",
        "cloudhunter.py":  "cloudhunter/cloudhunter.py",
        "CORStest.py":     "CORStest/CORStest.py",
        "corsy.py":        "Corsy/corsy.py",
        "tplmap.py":       "tplmap/tplmap.py",
    }
    for name, url in EXTERNAL_SCRIPTS.items():
        rel_path = scripts_map.get(name, name)
        full_path = os.path.join(script_dir, rel_path)
        found = bool(shutil.which(name)) or os.path.isfile(full_path)
        results.append({"name": name, "found": found, "url": url})
    return results


def run_doctor(skip_phases: list = None, verbose: bool = False) -> dict:
    """Print dependency status and return structured status."""
    skip = set(skip_phases or [])
    tools = []
    missing_required = []

    print(f"{Colors.BOLD}{Colors.GREEN}VenomRecon Doctor{Colors.NC}")
    print(f"{Colors.GREEN}================={Colors.NC}")
    print("")
    print(f"{Colors.BOLD}{'Tool':<22} {'Status':<10} {'Phases':<14} Install hint{Colors.NC}")
    print("-" * 100)

    for tool, (phases, hint) in sorted(TOOL_REGISTRY.items()):
        path = shutil.which(tool)
        skipped = _phases_skipped(phases, skip)
        if path:
            status = f"{Colors.GREEN}FOUND{Colors.NC}"
            status_raw = "FOUND"
            hint_txt = path if verbose else ""
        elif skipped:
            status = f"{Colors.YELLOW}SKIPPED{Colors.NC}"
            status_raw = "SKIPPED"
            hint_txt = hint
        else:
            status = f"{Colors.RED}MISSING{Colors.NC}"
            status_raw = "MISSING"
            hint_txt = hint
            if tool in CORE_TOOLS:
                missing_required.append(tool)
        tools.append({"name": tool, "status": status_raw, "phases": phases, "path": path, "hint": hint})
        # The ANSI escape codes mess up column formatting slightly, so we pad it differently
        # Let's just use f-strings directly with color injected at the right spots.
        status_pad = 10 + len(Colors.GREEN) + len(Colors.NC) if status_raw == "FOUND" else 10 + len(Colors.RED) + len(Colors.NC) if status_raw == "MISSING" else 10 + len(Colors.YELLOW) + len(Colors.NC)
        print(f"{Colors.CYAN}{tool:<22}{Colors.NC} {status:<{status_pad}} {','.join(str(p) for p in phases):<14} {hint_txt}")

    api_keys = {
        name: bool(os.environ.get(name))
        for name in (
            "GITHUB_TOKEN", "SHODAN_API_KEY", "SECURITYTRAILS_API_KEY",
            "CHAOS_API_KEY", "BEVIGIL_API_KEY", "LEAKIX_API_KEY",
            "WPSCAN_API_KEY", "CENSYS_API_KEY", "VIRUSTOTAL_API_KEY",
            "ALIENVAULT_API_KEY", "DIGITALYAMA_API_KEY", "DNSDUMPSTER_API_KEY",
            "CERTSPOTTER_API_KEY", "INTELX_API_KEY", "NETLAS_API_KEY",
            "PUGRECON_API_KEY", "THREATBOOK_API_KEY", "ZOOMEYE_API_KEY",
        )
    }
    print(f"\n{Colors.BOLD}{Colors.GREEN}Environment{Colors.NC}\n-----------")
    for name, is_set in api_keys.items():
        status_color = Colors.GREEN if is_set else Colors.RED
        print(f"{name:<28} {status_color}{'set' if is_set else 'not set'}{Colors.NC}")

    wordlists = {
        "SECLISTS_DNS":     config.seclists_dns,
        "DNS_MEDIUM":       config.dns_wordlist_medium,
        "DNS_LARGE":        config.dns_wordlist_large,
        "DIRB_COMMON":      config.dirb_common,
        "VHOSTS_WORDLIST":  config.vhosts_wordlist,
        "PARAMS_WORDLIST":  config.params_wordlist,
        "RESOLVERS_FILE":   config.resolvers_file,
    }
    print(f"\n{Colors.BOLD}{Colors.GREEN}Wordlists{Colors.NC}\n---------")
    for label, path in wordlists.items():
        found = os.path.isfile(path)
        status_color = Colors.GREEN if found else Colors.RED
        print(f"{label:<18} {status_color}{'found' if found else 'missing'}{Colors.NC} {path}")

    from pathlib import Path
    scripts_dir = os.path.join(str(Path.home()), "venomrecon-scripts")
    scripts = check_external_scripts(scripts_dir)
    print(f"\n{Colors.BOLD}{Colors.GREEN}External Scripts{Colors.NC}\n----------------")
    for item in scripts:
        status_color = Colors.GREEN if item['found'] else Colors.RED
        print(f"{Colors.CYAN}{item['name']:<20}{Colors.NC} {status_color}{'FOUND' if item['found'] else 'MISSING'}{Colors.NC:<10} {item['url']}")

    found_count = len([item for item in tools if item["status"] == "FOUND"])
    missing_count = len([item for item in tools if item["status"] == "MISSING"])
    print(f"\n{Colors.BOLD}Summary: {Colors.GREEN}{found_count}/{len(TOOL_REGISTRY)}{Colors.NC} tools found, {Colors.RED}{missing_count}{Colors.NC} missing")
    if missing_required:
        print(f"{Colors.BOLD}{Colors.RED}Required core tools missing: {', '.join(missing_required)}{Colors.NC}")

    return {
        "tools": tools,
        "api_keys": api_keys,
        "wordlists": wordlists,
        "external_scripts": scripts,
        "missing_required": missing_required,
    }
