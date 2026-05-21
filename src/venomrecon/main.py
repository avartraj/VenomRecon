#!/usr/bin/env python3
"""VenomRecon CLI and phase orchestration."""

import argparse
import os
import shutil
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
for path in (_HERE, _PARENT):
    if path not in sys.path:
        sys.path.insert(0, path)

from commands.doctor import run_doctor
from core import logger
from core.config import config
from core.runner import sanitize_domain
from modules import discovery, intelligence, parameters, subdomain, takeover, vulnerability
from modules.report import generate_json_report, generate_report
from utils.helpers import PhaseTimer, banner


PHASE_NAMES = {
    1: "Subdomain Enumeration",
    2: "Subdomain Takeover",
    3: "Technology / IP / Screenshots",
    4: "Content Discovery",
    5: "Parameter Discovery",
    6: "Archive and DNS History",
    7: "JavaScript Recon",
    8: "GitHub Recon",
    9: "Cloud Recon",
    10: "DNS / ASN / Port Scanning",
    11: "Vulnerability Scanning",
    12: "Nuclei Mass Scan",
    13: "Report Generation",
}


def pre_flight_check() -> None:
    """Verify core tool installations before proceeding."""
    required = ["subfinder", "httpx", "nuclei"]
    missing = [tool for tool in required if not shutil.which(tool)]
    if missing:
        logger.error(f"CRITICAL: Missing core tools -> {', '.join(missing)}")
        logger.error("Run dependency checks with: python src/venomrecon/main.py --doctor")
        sys.exit(1)


def _run_parallel(funcs_and_args: list, max_workers: int = 4) -> None:
    """Run a list of (callable, args_tuple) items concurrently."""
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(fn, *args): fn.__name__ for fn, args in funcs_and_args}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                fut.result()
            except Exception as exc:
                logger.error(f"Parallel phase [{name}] failed: {exc}")


def print_help_menu():
    from core.logger import Colors
    c_flag = f"{Colors.YELLOW}{Colors.BOLD}"
    c_desc = f"{Colors.CYAN}"
    c_head = f"{Colors.GREEN}{Colors.BOLD}"
    nc = f"{Colors.NC}"
    
    help_text = f"""
{c_head}Usage:{nc} {Colors.GREEN}venomrecon{nc} [-h] [-d DOMAIN] [-w] [-o OUTDIR] [-t THREADS] [--resume]
                  [--skip SKIP] [-v] [--doctor] [--agree-tos] [--dry-run]
                  [--profile {{passive,standard,aggressive}}] [--install-missing]

  {c_head}[ VENOMRECON v1.0 - Advanced recon and vulnerability scanner ]{nc}
  {Colors.RED}{Colors.BOLD}AUTHORIZED USE ONLY.{nc}

{c_head}Options:{nc}
  {c_flag}-h, --help{nc}            {c_desc}Show this help message and exit.{nc}
  {c_flag}-d, --domain{nc}          {c_desc}Target domain or URL.{nc}
  {c_flag}-w, --wildcard{nc}        {c_desc}Force wildcard/subdomain enumeration mode.{nc}
  {c_flag}-o, --outdir{nc}          {c_desc}Output directory (default: results_<domain>).{nc}
  {c_flag}-t, --threads{nc}         {c_desc}Worker thread count (default: 8).{nc}
  {c_flag}--resume{nc}              {c_desc}Skip phases that already produced output.{nc}
  {c_flag}--skip{nc}                {c_desc}Comma-separated phase numbers to skip, e.g. --skip 8,9.{nc}
  {c_flag}-v, --verbose{nc}         {c_desc}Show debug output.{nc}
  {c_flag}--doctor{nc}              {c_desc}Check installed tools, scripts, wordlists, and API keys.{nc}
  {c_flag}--agree-tos{nc}           {c_desc}Confirm you are authorized to test the target.{nc}
  {c_flag}--dry-run{nc}             {c_desc}Print planned commands without running subprocesses.{nc}
  {c_flag}--install-missing{nc}     {c_desc}Automatically install missing tools via WSL after scan.{nc}

{c_head}Scan Profiles:{nc}
  {c_flag}--profile passive{nc}     {c_desc}Safe, read-only OSINT. Subdomain gathering, archive scraping,{nc}
                        {c_desc}and DNS checks ONLY. No packets sent directly to target.{nc}
  {c_flag}--profile standard{nc}    {c_desc}(Default) Active probing, dirbusting, and port scanning.{nc}
                        {c_desc}Vulnerability scans and cloud checks skipped to reduce noise.{nc}
  {c_flag}--profile aggressive{nc}  {c_desc}Full assault. Enables all 13 phases including 105+ vuln{nc}
                        {c_desc}checks (Nuclei, XSS, SQLi, LFI, SSRF, CORS, etc.).{nc}
"""
    print(help_text)
    import sys
    sys.exit(0)

def parse_args():
    import sys
    if "-h" in sys.argv or "--help" in sys.argv or len(sys.argv) == 1:
        print_help_menu()

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("-d", "--domain")
    parser.add_argument("-w", "--wildcard", action="store_true")
    parser.add_argument("-o", "--outdir")
    parser.add_argument("-t", "--threads", type=int, default=None)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--skip", default="")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--doctor", action="store_true")
    parser.add_argument("--agree-tos", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--profile", choices=["passive", "standard", "aggressive"], default="standard")
    parser.add_argument("--install-missing", action="store_true")
    
    return parser.parse_args()


def _authorized_use_gate(args) -> None:
    warning = """
+------------------------------------------------------------------+
|  VenomRecon - Authorized Use Only                                |
|  Use only on assets you own or have written permission to test.  |
|  Unauthorized use is illegal and unethical.                      |
+------------------------------------------------------------------+
"""
    print(warning)
    if args.agree_tos or args.dry_run or os.environ.get("VENOMRECON_AGREE_TOS") == "1":
        return
    answer = input("Do you confirm you are authorized to test this target? [y/N] ").strip().lower()
    if answer not in ("y", "yes"):
        logger.error("Authorization confirmation not provided. Aborting.")
        sys.exit(1)


def _apply_profile(profile: str, wildcard: bool) -> bool:
    config.apply_profile(profile)
    overrides = config.phase_overrides.get(1, {})
    if overrides.get("active") is False:
        return False
    return wildcard


def _parse_target(raw_target: str, wildcard: bool):
    is_url = raw_target.startswith(("http://", "https://"))
    if is_url:
        host = urlparse(raw_target).netloc.split(":", 1)[0]
        outname = sanitize_domain(host)
        return raw_target, outname, False, True
    if raw_target.startswith("*."):
        outname = sanitize_domain(raw_target[2:])
        return outname, outname, True, False
    outname = sanitize_domain(raw_target)
    return outname, outname, wildcard, False


def main():
    banner()
    args = parse_args()
    logger.set_verbose(args.verbose)

    if args.doctor:
        skip = {int(x.strip()) for x in args.skip.split(",") if x.strip().isdigit()} if args.skip else set()
        result = run_doctor(sorted(skip), args.verbose)
        sys.exit(0 if not result.get("missing_required") else 1)

    if not args.domain:
        logger.error("Target domain is required unless --doctor is used.")
        sys.exit(2)

    config.dry_run = args.dry_run
    config.verify_secrets = getattr(args, 'verify_secrets', False)
    config.verify_active = getattr(args, 'verify_active', False)
    _authorized_use_gate(args)

    target, outname, wildcard, is_url = _parse_target(args.domain, args.wildcard)

    if args.threads:
        config.threads = max(1, args.threads)
    if args.resume:
        config.resume = True
    if args.skip:
        config.skip_phases |= {int(x.strip()) for x in args.skip.split(",") if x.strip().isdigit()}
    wildcard = _apply_profile(args.profile, wildcard)

    outdir = args.outdir or f"results_{outname}"
    if not config.dry_run:
        os.makedirs(outdir, exist_ok=True)
        logger.setup_file_log(os.path.join(outdir, "venomrecon.log"))

    logger.info(f"Target    : {target}")
    logger.info(f"Mode      : {'URL Target' if is_url else 'Wildcard (*.' + outname + ')' if wildcard else 'Single domain'}")
    logger.info(f"Profile   : {config.profile}")
    logger.info(f"Output    : {os.path.abspath(outdir)}")
    logger.info(f"Threads   : {config.threads}")
    logger.info(f"Resume    : {config.resume}")
    logger.info(f"Skip      : {sorted(config.skip_phases) or 'none'}")

    if not config.dry_run:
        pre_flight_check()
    config.check_wordlists()

    if is_url:
        if config.dry_run:
            logger.info(f"[DRY-RUN] seed URL target files in {outdir}")
        else:
            with open(os.path.join(outdir, "live_subdomains.txt"), "w", encoding="utf-8") as f:
                f.write(target + "\n")
            with open(os.path.join(outdir, "all_crawled_urls.txt"), "w", encoding="utf-8") as f:
                f.write(target + "\n")
        config.skip_phases.update([1, 2])
        logger.warning("Bypassed Phases 1 & 2 due to explicit URL target.")

    wall_start = time.time()
    try:
        logger.phase(1, PHASE_NAMES[1])
        with PhaseTimer("Phase 1"):
            subdomain.run_phase(target, outdir, wildcard)

        logger.phase(2, PHASE_NAMES[2])
        with PhaseTimer("Phase 2"):
            if config.should_skip(2):
                logger.warning("Phase 2 skipped.")
            else:
                takeover.run_phase(target, outdir)

        logger.phase(3, "Technology / IP / Screenshots + Content Discovery")
        with PhaseTimer("Phases 3+4"):
            _run_parallel(
                [(discovery.run_phase4, (target, outdir)), (discovery.run_phase5, (target, outdir))],
                max_workers=2,
            )

        logger.phase(5, PHASE_NAMES[5])
        with PhaseTimer("Phase 5"):
            if config.should_skip(5):
                logger.warning("Phase 5 skipped.")
            else:
                parameters.run_phase(target, outdir)

        logger.phase(6, "Intelligence: Archive, JS, GitHub, Cloud, DNS/Ports")
        with PhaseTimer("Phases 6-10"):
            _run_parallel(
                [
                    (intelligence.run_phase7, (target, outdir)),
                    (intelligence.run_phase8, (target, outdir)),
                    (intelligence.run_phase9, (target, outdir)),
                    (intelligence.run_phase10, (target, outdir)),
                    (intelligence.run_phase11, (target, outdir)),
                ],
                max_workers=5,
            )

        logger.phase(11, "Vulnerability Scanning + Nuclei Mass Scan")
        with PhaseTimer("Phases 11+12"):
            _run_parallel(
                [(vulnerability.run_phase12, (target, outdir)), (vulnerability.run_phase13, (target, outdir))],
                max_workers=2,
            )

        with PhaseTimer("Phase 13"):
            generate_report(target, outdir)
            if not config.dry_run:
                generate_json_report(target, outdir)

    except KeyboardInterrupt:
        logger.warning("\nRecon interrupted by user (Ctrl+C).")
        sys.exit(130)
    except Exception as exc:
        logger.error(f"Fatal error: {exc}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    elapsed = time.time() - wall_start
    h, rem = divmod(int(elapsed), 3600)
    m, s = divmod(rem, 60)
    error_path = os.path.join(outdir, "errors.txt")
    if config.dry_run:
        logger.info(f"[DRY-RUN] write {error_path}")
    else:
        logger.dump_errors(error_path)
    logger.success(f"Total wall-clock time: {h}h {m}m {s}s")
    logger.success(f"All results in:  {os.path.abspath(outdir)}/")
    logger.success(f"Full report:     {os.path.abspath(outdir)}/report.md")
    logger.success(f"Error log:       {os.path.abspath(error_path)}")
    
    from core.runner import missing_tools_run
    if missing_tools_run:
        logger.warning(f"\n[!] Scan finished, but {len(missing_tools_run)} tools were MISSING!")
        for t in sorted(missing_tools_run):
            logger.warning(f"  - {t}")
        if getattr(args, "install_missing", False):
            logger.info("Auto-installing missing tools via install.sh in WSL kali-linux...")
            # Use wslpath or cd to parent directory
            wsl_parent = f"$(wslpath '{_PARENT}')"
            install_cmd = f"wsl -d kali-linux bash -c \"cd {wsl_parent} && sudo bash installers/install.sh\""
            logger.info(f"Running: {install_cmd}")
            os.system(install_cmd)
        else:
            logger.warning("You can install dependencies by passing --install-missing or running --doctor")



if __name__ == "__main__":
    main()
