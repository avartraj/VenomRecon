"""
core/config.py – Centralised configuration for VenomRecon.

All settings default to safe values and can be overridden via
environment variables so you never need to edit this file directly.

  export SECLISTS_DNS=/path/to/wordlist.txt
  export GITHUB_TOKEN=ghp_xxxx
  …etc.
"""
import os
from pathlib import Path
from core import logger

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_WORDLISTS = os.path.join(_HERE, "wordlists")

PROFILE_CONFIG = {
    "passive": {
        "skip_phases": [2, 3, 4, 5, 8, 9, 11, 12],
        "notes": [
            "Phase 1: passive subdomain sources only",
            "Phase 6: archive/wayback only",
            "Phase 7: static JS URL collection only",
            "Phase 10: DNS records only",
        ],
        "phase_overrides": {
            1: {"active": False},
            7: {"fetch_js": False},
            10: {"port_scan": False, "shodan": False, "cors": False},
        },
    },
    "standard": {
        "skip_phases": [8, 9, 11],
        "notes": [
            "GitHub recon skipped by default to avoid API rate limits",
            "Cloud recon skipped by default",
            "Vulnerability scanning skipped; use aggressive for full vuln scan",
        ],
        "phase_overrides": {},
    },
    "aggressive": {
        "skip_phases": [],
        "notes": ["All phases enabled including full 105-check vulnerability scan."],
        "phase_overrides": {},
    },
}


class Config:
    def __init__(self):
        # Load local .env file natively if it exists in the workspace root
        env_path = os.path.join(os.path.dirname(os.path.dirname(_HERE)), ".env")
        if os.path.isfile(env_path):
            try:
                with open(env_path, "r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "=" in line:
                            k, v = line.split("=", 1)
                            os.environ[k.strip()] = v.strip().strip("'\"")
            except Exception:
                pass

        home = str(Path.home())

        # ── Wordlists ──────────────────────────────────────────────
        seclists_base = "/usr/share/wordlists/seclists"

        self.seclists_dns = os.environ.get(
            "SECLISTS_DNS",
            f"{seclists_base}/Discovery/DNS/subdomains-top1million-110000.txt",
        )
        self.dns_wordlist_small = os.environ.get(
            "DNS_WORDLIST_SMALL",
            f"{seclists_base}/Discovery/DNS/subdomains-top1million-20000.txt",
        )
        self.dns_wordlist_medium = os.environ.get(
            "DNS_WORDLIST_MEDIUM",
            f"{seclists_base}/Discovery/DNS/subdomains-top1million-110000.txt",
        )
        self.dns_wordlist_large = os.environ.get(
            "DNS_WORDLIST_LARGE",
            f"{seclists_base}/Discovery/DNS/dns-Jhaddix.txt",
        )
        self.dirb_common = os.environ.get(
            "DIRB_COMMON",
            f"{seclists_base}/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt",
        )
        self.vhosts_wordlist = os.environ.get(
            "VHOSTS_WORDLIST",
            f"{seclists_base}/Discovery/DNS/namelist.txt",
        )
        self.params_wordlist = os.environ.get(
            "PARAMS_WORDLIST",
            f"{seclists_base}/Discovery/Web-Content/burp-parameter-names.txt",
        )
        self.sqli_wordlist = os.environ.get(
            "SQLI_WORDLIST",
            f"{seclists_base}/Fuzzing/SQLi/Generic-SQLi.txt",
        )
        self.rce_wordlist = os.environ.get(
            "RCE_WORDLIST",
            f"{seclists_base}/Fuzzing/command-injection-commix.txt",
        )
        self.resolvers_file = os.environ.get(
            "RESOLVERS_FILE",
            f"{seclists_base}/Miscellaneous/dns-resolvers.txt",
        )
        self.medium_dorks = os.environ.get(
            "MEDIUM_DORKS",
            "Dorks/medium_dorks.txt",
        )
        self.github_tokens_file = os.environ.get(
            "GITHUB_TOKENS_FILE",
            os.path.join(home, "tokens.txt"),
        )
        self.subjack_fingerprints = os.environ.get(
            "SUBJACK_FINGERPRINTS",
            os.path.join(home, "venomrecon-scripts", "fingerprints.json"),
        )

        # ── API keys ──────────────────────────────────────────────────
        self.securitytrails_api_key = os.environ.get("SECURITYTRAILS_API_KEY", "")
        self.shodan_api_key         = os.environ.get("SHODAN_API_KEY", "")
        self.github_token           = os.environ.get("GITHUB_TOKEN", "")
        self.chaos_api_key          = os.environ.get("CHAOS_API_KEY", "")
        self.bevigil_api_key        = os.environ.get("BEVIGIL_API_KEY", "")
        self.leakix_api_key         = os.environ.get("LEAKIX_API_KEY", "")
        self.wpscan_api_key         = os.environ.get("WPSCAN_API_KEY", "")
        self.censys_api_key         = os.environ.get("CENSYS_API_KEY", "")
        self.virustotal_api_key     = os.environ.get("VIRUSTOTAL_API_KEY", "")
        self.alienvault_api_key     = os.environ.get("ALIENVAULT_API_KEY", "")
        self.digitalyama_api_key    = os.environ.get("DIGITALYAMA_API_KEY", "")
        self.dnsdumpster_api_key    = os.environ.get("DNSDUMPSTER_API_KEY", "")
        self.certspotter_api_key    = os.environ.get("CERTSPOTTER_API_KEY", "")
        self.intelx_api_key         = os.environ.get("INTELX_API_KEY", "")
        self.netlas_api_key         = os.environ.get("NETLAS_API_KEY", "")
        self.pugrecon_api_key       = os.environ.get("PUGRECON_API_KEY", "")
        self.threatbook_api_key     = os.environ.get("THREATBOOK_API_KEY", "")
        self.zoomeye_api_key        = os.environ.get("ZOOMEYE_API_KEY", "")

        # Sync active keys to subfinder config dynamically
        self.sync_subfinder_config()

        # ── Performance ───────────────────────────────────────────────
        self.threads: int = int(os.environ.get("RECON_THREADS", "8"))
        if self.threads < 1:
            self.threads = 1

        self.dry_run: bool        = os.environ.get("VENOMRECON_DRY_RUN", "0") in ("1", "true", "yes")
        self.verify_secrets: bool = os.environ.get("VENOMRECON_VERIFY_SECRETS", "0") in ("1", "true", "yes")
        self.verify_active: bool  = os.environ.get("VENOMRECON_VERIFY_ACTIVE", "0") in ("1", "true", "yes")
        self.profile: str         = os.environ.get("VENOMRECON_PROFILE", "standard")
        self.phase_overrides: dict = {}
        self.inter_tool_delay: float = float(os.environ.get("INTER_TOOL_DELAY", "0.5"))

        self.tool_timeouts = {
            "default": 300,
            "nuclei": 3600,
            "sqlmap": 1800,
            "dalfox": 1800,
            "httpx": 900,
            "katana": 900,
            "gau": 600,
            "waybackurls": 600,
            "wafw00f": 300,
            "asnmap": 120,
            "wpscan": 600,
        }

        self.dir_fuzz_limit: int = int(os.environ.get("DIR_FUZZ_LIMIT", "10"))
        # Expand ASN to CIDR ranges via asnmap
        self.asnmap_expand: bool = os.environ.get("ASNMAP_EXPAND", "0") in ("1", "true", "yes")

        _skip_raw = os.environ.get("SKIP_PHASES", "")
        self.skip_phases: set = {
            int(x.strip()) for x in _skip_raw.split(",") if x.strip().isdigit()
        }
        self.resume: bool = os.environ.get("RECON_RESUME", "0") in ("1", "true", "yes")

    def dns_wordlist_for_profile(self) -> str:
        """Return the appropriate DNS wordlist based on current profile."""
        if self.profile == "aggressive":
            wl = self.dns_wordlist_large
        elif self.profile == "standard":
            wl = self.dns_wordlist_medium
        else:
            wl = self.dns_wordlist_small
        # Fallback to small if tiered file doesn't exist
        import os as _os
        return wl if _os.path.isfile(wl) else self.seclists_dns

    def apply_profile(self, profile: str):
        """Apply scan-profile defaults without clearing explicit skips."""
        if profile not in PROFILE_CONFIG:
            profile = "standard"
        self.profile = profile
        profile_cfg = PROFILE_CONFIG[profile]
        self.skip_phases |= set(profile_cfg.get("skip_phases", []))
        self.phase_overrides = profile_cfg.get("phase_overrides", {})

    def check_wordlists(self):
        """Halt execution if SecLists directory is missing."""
        seclists_base = "/usr/share/wordlists/seclists"
        if not os.path.isdir(seclists_base):
            logger.error(f"\n[!] CRITICAL: SecLists directory is not available at {seclists_base}!")
            logger.error("    VenomRecon strictly requires SecLists for wordlists.")
            logger.error("    Please install it system-wide using: sudo apt install seclists\n")
            import sys
            sys.exit(1)

    def should_skip(self, phase_num: int, sentinel_file: str = "") -> bool:
        if phase_num in self.skip_phases:
            logger.warning(f"Phase {phase_num} explicitly skipped via SKIP_PHASES.")
            return True
        if self.resume and sentinel_file and os.path.isfile(sentinel_file):
            if os.path.getsize(sentinel_file) > 0:
                logger.info(f"Phase {phase_num} already done (resume mode). Skipping.")
                return True
        return False

    def sync_subfinder_config(self):
        """Sync active API keys to subfinder's provider-config.yaml dynamically."""
        providers = {}
        if self.chaos_api_key:
            providers["chaos"] = [self.chaos_api_key]
        if self.shodan_api_key:
            providers["shodan"] = [self.shodan_api_key]
        if self.censys_api_key:
            providers["censys"] = [self.censys_api_key]
        if self.virustotal_api_key:
            providers["virustotal"] = [self.virustotal_api_key]
        if self.securitytrails_api_key:
            providers["securitytrails"] = [self.securitytrails_api_key]
        if self.bevigil_api_key:
            providers["bevigil"] = [self.bevigil_api_key]
        if self.dnsdumpster_api_key:
            providers["dnsdumpster"] = [self.dnsdumpster_api_key]
        if self.intelx_api_key:
            providers["intelx"] = [self.intelx_api_key]
        if self.leakix_api_key:
            providers["leakix"] = [self.leakix_api_key]
        if self.netlas_api_key:
            providers["netlas"] = [self.netlas_api_key]
        if self.threatbook_api_key:
            providers["threatbook"] = [self.threatbook_api_key]
        if self.zoomeye_api_key:
            providers["zoomeye"] = [self.zoomeye_api_key]
        if self.certspotter_api_key:
            providers["certspotter"] = [self.certspotter_api_key]

        if not providers:
            return

        subfinder_dir = Path(Path.home()) / ".config" / "subfinder"
        try:
            subfinder_dir.mkdir(parents=True, exist_ok=True)
            config_file = subfinder_dir / "provider-config.yaml"
            
            lines = ["# Subfinder provider configuration auto-generated by VenomRecon", ""]
            for provider, keys in sorted(providers.items()):
                lines.append(f"{provider}:")
                for k in keys:
                    lines.append(f"  - {k}")
            
            with open(config_file, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
        except Exception:
            pass


config = Config()
