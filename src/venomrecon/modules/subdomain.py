"""
Phase 1 - Subdomain Discovery
Tools: subfinder, assetfinder, findomain, chaos, haktrails,
       crt.sh (native), wayback (native), rapiddns (native), leakix (native),
       bevigil-cli, shuffledns, dnsx, ffuf, gobuster dns,
       puredns, alterx, gotator, dnsgen+massdns,
       github-subdomains, wafw00f, cdncheck, asnmap
"""
import os
import json
import re
import urllib.request
import threading
from concurrent.futures import ThreadPoolExecutor
from core import logger
from core.runner import run, run_pipe, run_many, append_unique, read_lines
from core.config import config
from utils.fileops import merge_deduplicate_and_cleanup, safe_delete
from utils.fileops import atomic_write
from utils.shell_replacements import awk_column, filter_by_status_code
from utils.probes import fetch_rapiddns, fetch_leakix


def fetch_crtsh(target: str, outfile: str) -> None:
    """Python-native crt.sh scraper."""
    if config.dry_run:
        logger.info(f"[DRY-RUN] fetch crt.sh subdomains for {target}")
        return
    logger.info("Fetching subdomains from crt.sh...")
    try:
        url = f"https://crt.sh/?q=%25.{target}&output=json"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
            subs = set()
            for item in data:
                name_value = item.get("name_value", "")
                for val in name_value.split("\n"):
                    val = val.strip().lower()
                    if val.startswith("*."):
                        val = val[2:]
                    if val:
                        subs.add(val)
            atomic_write(outfile, sorted(subs))
    except Exception as e:
        logger.error(f"Error fetching crt.sh subdomains: {e}", context="crtsh")
        atomic_write(outfile, [])


def fetch_wayback_subs(target: str, outfile: str) -> None:
    """Python-native Wayback subdomains scraper."""
    if config.dry_run:
        logger.info(f"[DRY-RUN] fetch Wayback subdomains for {target}")
        return
    logger.info("Fetching subdomains from Wayback CDX API...")
    try:
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=text&fl=original&collapse=urlkey"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
            subs = set()
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                if "://" in line:
                    line = line.split("://", 1)[-1]
                host = line.split("/", 1)[0]
                host = host.split(":", 1)[0]
                host = host.strip().lower()
                if host.startswith("*."):
                    host = host[2:]
                if host:
                    subs.add(host)
            atomic_write(outfile, sorted(subs))
    except Exception as e:
        logger.error(f"Error fetching Wayback subdomains: {e}", context="wayback_subs")
        atomic_write(outfile, [])


# ─────────────────────────────────────────
# Phase 1.1 - Passive (all tools in parallel)
# ─────────────────────────────────────────

def run_passive(target: str, outdir: str):
    """Run all passive subdomain scrapers concurrently."""
    logger.info("Phase 1.1: Passive Subdomain Scraping (concurrent)")

    tasks = {
        "subfinder": dict(
            cmd=["subfinder", "-d", target, "-all", "-silent", "-o", f"{outdir}/subfinder.txt"],
            timeout=None,
        ),
        "assetfinder": dict(
            cmd=["assetfinder", "--subs-only", target],
            output_file=f"{outdir}/assetfinder.txt",
            timeout=None,
        ),
        "findomain": dict(
            cmd=["findomain", "-t", target, "-u", f"{outdir}/findomain.txt"],
            timeout=None,
        ),
        "thexrecon": dict(
            cmd=["thexrecon", "-u", target],
            output_file=f"{outdir}/thexrecon_raw.txt",
            timeout=None,
        ),
        "haktrails": dict(
            cmd=["haktrails", "subdomains"],
            stdin_data=target + "\n",
            output_file=f"{outdir}/haktrails.txt",
            timeout=None,
        ),
    }

    if config.github_token:
        tasks["github_subs"] = dict(
            cmd=["github-subdomains", "-d", target, "-t", config.github_token, "-o", f"{outdir}/github_subs.txt"],
            timeout=None,
        )

    # chaos (requires CHAOS_API_KEY)
    if config.chaos_api_key:
        tasks["chaos"] = dict(
            cmd=["chaos", "-d", target, "-key", config.chaos_api_key, "-o", f"{outdir}/chaos.txt", "-silent"],
            timeout=120,
        )

    # bevigil-cli (requires BEVIGIL_API_KEY)
    if config.bevigil_api_key:
        tasks["bevigil"] = dict(
            cmd=["bevigil-cli", "--api-key", config.bevigil_api_key, "osint", "--domain", target, "--subdomains"],
            output_file=f"{outdir}/bevigil.txt",
            timeout=120,
        )

    # Python-native scrapers (crtsh, wayback, rapiddns, leakix) run in threads
    native_scrapers = [
        (fetch_crtsh, (target, f"{outdir}/crtsh.txt")),
        (fetch_wayback_subs, (target, f"{outdir}/wayback_subs.txt")),
        (fetch_rapiddns, (target, f"{outdir}/rapiddns.txt")),
        (fetch_leakix, (target, f"{outdir}/leakix.txt")),
    ]

    native_threads = []
    for fn, args in native_scrapers:
        t = threading.Thread(target=fn, args=args)
        t.start()
        native_threads.append(t)

    # Run command-based tasks in parallel
    run_many(tasks, max_workers=config.threads)

    # Join Python-native scraper threads
    for t in native_threads:
        t.join()

    # Post-process thexrecon results natively
    thexrecon_raw = f"{outdir}/thexrecon_raw.txt"
    if os.path.isfile(thexrecon_raw):
        regex = re.compile(r'([a-zA-Z0-9][-a-zA-Z0-9]*\.)+' + re.escape(target), re.IGNORECASE)
        lines = read_lines(thexrecon_raw)
        filtered = sorted({m.group(0).lower() for l in lines for m in [regex.search(l)] if m})
        atomic_write(f"{outdir}/thexrecon.txt", filtered)
        safe_delete(thexrecon_raw)

    logger.success("Phase 1.1 complete - all passive scrapers done.")


# ─────────────────────────────────────────
# Phase 1.1b - Permutation Generation
# ─────────────────────────────────────────

def run_permutations(target: str, outdir: str, passive_merged: str):
    """Generate permuted subdomain candidates from passive results, then resolve."""
    logger.info("Phase 1.1b: Permutation Generation (alterx, gotator, dnsgen - concurrent)")

    if not os.path.isfile(passive_merged) or os.path.getsize(passive_merged) == 0:
        logger.warning("No passive subdomains found for permutation. Skipping.")
        return

    perm_tasks = {}

    # alterx: smart permutation via ProjectDiscovery
    perm_tasks["alterx"] = dict(
        cmd=["alterx", "-l", passive_merged, "-silent", "-o", f"{outdir}/alterx_perms.txt"],
        timeout=180,
    )

    # gotator: wordlist-based permutation
    perm_tasks["gotator"] = dict(
        cmd=["gotator", "-sub", passive_merged, "-perm",
             "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
             "-silent", "-dp", "2"],
        output_file=f"{outdir}/gotator_perms.txt",
        timeout=180,
    )

    # dnsgen: mutation-based generation
    try:
        subfinder_content = "\n".join(read_lines(passive_merged)) + "\n"
        perm_tasks["dnsgen"] = dict(
            cmd=["dnsgen", "-"],
            stdin_data=subfinder_content,
            output_file=f"{outdir}/dnsgen_perms.txt",
            timeout=180,
        )
    except Exception:
        pass

    run_many(perm_tasks, max_workers=3)

    # Merge permutation outputs
    all_perm_file = f"{outdir}/all_perms.txt"
    merge_deduplicate_and_cleanup(
        source_files=[
            f"{outdir}/alterx_perms.txt",
            f"{outdir}/gotator_perms.txt",
            f"{outdir}/dnsgen_perms.txt",
        ],
        output_file=all_perm_file,
        delete_sources=False,
    )

    # Resolve via puredns
    if os.path.isfile(config.resolvers_file) and os.path.isfile(all_perm_file):
        run(
            ["puredns", "resolve", all_perm_file, "-r", config.resolvers_file,
             "-w", f"{outdir}/puredns_perms.txt"],
            timeout=600,
        )

    logger.success("Phase 1.1b complete - permutation generation done.")


# ─────────────────────────────────────────
# Phase 1.2 - Brute-force
# ─────────────────────────────────────────

def run_brute(target: str, outdir: str):
    """Phase 1.2 - Brute-force subdomain enumeration (some tools in parallel)."""
    logger.info("Phase 1.2: Brute-force Subdomain Enumeration")

    wl = config.dns_wordlist_for_profile()
    if not os.path.isfile(wl):
        logger.warning(f"DNS wordlist not found: {wl}. Skipping brute-force entirely.")
        return

    tasks = {}

    if os.path.isfile(config.resolvers_file):
        tasks["shuffledns"] = dict(
            cmd=["shuffledns", "-d", target, "-w", wl, "-r", config.resolvers_file, "-o", f"{outdir}/shuffledns_output.txt"],
            timeout=None,
        )
        tasks["dnsx_brute"] = dict(
            cmd=["dnsx", "-d", target, "-w", wl, "-r", config.resolvers_file, "-o", f"{outdir}/dnsx_brute.txt"],
            timeout=None,
        )
        tasks["puredns"] = dict(
            cmd=["puredns", "bruteforce", wl, target, "-r", config.resolvers_file, "-w", f"{outdir}/puredns_brute.txt"],
            timeout=None,
        )
    else:
        logger.warning(f"Resolvers file not found: {config.resolvers_file}. "
                       "Skipping shuffledns/dnsx/puredns.")

    tasks["ffuf_dns"] = dict(
        cmd=["ffuf", "-u", f"http://FUZZ.{target}", "-c", "-w", wl, "-t", "100", "-fc", "403", "-o", f"{outdir}/ffuf_subs_output.json"],
        timeout=None,
    )
    tasks["gobuster_dns"] = dict(
        cmd=["gobuster", "dns", "-d", target, "-w", wl, "-o", f"{outdir}/gobuster_dns.txt"],
        timeout=None,
    )

    run_many(tasks, max_workers=config.threads)

    # massdns on permutation results (if available)
    if os.path.isfile(config.resolvers_file) and os.path.isfile(f"{outdir}/all_perms.txt"):
        logger.info("Running massdns on permutation candidates...")
        try:
            massdns_cmd = [
                "massdns",
                "-r", config.resolvers_file,
                "-t", "A",
                "-o", "S",
                "--flush",
                "-w", f"{outdir}/massdns_perms.txt",
                f"{outdir}/all_perms.txt",
            ]
            run(massdns_cmd, timeout=600)
        except Exception as e:
            logger.error(f"Error in massdns permutations: {e}", context="massdns_perms")

    logger.success("Phase 1.2 complete - brute-force done.")


# ─────────────────────────────────────────
# Phase 1.3 & 1.4 - Combine + Probe
# ─────────────────────────────────────────

def combine_and_probe(target: str, outdir: str) -> str:
    """Deduplicate all subdomain files then probe live ones via httpx, wafw00f, cdncheck."""
    logger.info("Phase 1.3: Combining all discovered subdomains")

    src_files = [
        f"{outdir}/subfinder.txt",
        f"{outdir}/assetfinder.txt",
        f"{outdir}/findomain.txt",
        f"{outdir}/chaos.txt",
        f"{outdir}/crtsh.txt",
        f"{outdir}/wayback_subs.txt",
        f"{outdir}/rapiddns.txt",
        f"{outdir}/leakix.txt",
        f"{outdir}/bevigil.txt",
        f"{outdir}/haktrails.txt",
        f"{outdir}/shuffledns_output.txt",
        f"{outdir}/dnsx_brute.txt",
        f"{outdir}/gobuster_dns.txt",
        f"{outdir}/puredns_brute.txt",
        f"{outdir}/puredns_perms.txt",
        f"{outdir}/dnsgen_massdns.txt",
        f"{outdir}/github_subs.txt",
        f"{outdir}/thexrecon.txt",
    ]

    all_subs = f"{outdir}/all_subdomains.txt"
    total = merge_deduplicate_and_cleanup(src_files, all_subs, delete_sources=False)
    logger.success(f"Total unique subdomains: {total}")

    logger.info("Phase 1.4: Probing live subdomains (httpx + wafw00f + cdncheck - concurrent)")
    live_tmp = f"{outdir}/live_subdomains_tmp.txt"

    # Run httpx, wafw00f, cdncheck, and dnsx concurrently
    probe_tasks = {
        "httpx_probe": dict(
            cmd=["httpx", "-l", all_subs, "-silent", "-status-code", "-threads", "50", "-o", live_tmp],
            timeout=900,
        ),
        "wafw00f": dict(
            cmd=["wafw00f", "-i", all_subs, "-o", f"{outdir}/waf_detection.txt", "-a"],
            timeout=300,
        ),
        "cdncheck": dict(
            cmd=["cdncheck", "-l", all_subs, "-resp", "-o", f"{outdir}/cdn_detection.txt"],
            timeout=120,
        ),
        "dnsx_full": dict(
            cmd=["dnsx", "-l", all_subs, "-a", "-cname", "-resp", "-o", f"{outdir}/dnsx_full.txt"],
            timeout=300,
        ),
    }
    run_many(probe_tasks, max_workers=4)

    # 200-only alive
    atomic_write(f"{outdir}/alive_200.txt", filter_by_status_code(live_tmp, [200]))

    # auth-protected (401/403)
    run(
        ["httpx", "-l", all_subs, "-mc", "401,403", "-silent", "-title", "-status-code", "-ip", "-threads", "50", "-o", f"{outdir}/auth_protected.txt"],
        timeout=600,
    )

    # Extract just the URL column
    atomic_write(f"{outdir}/live_subdomains.txt", awk_column(live_tmp, 1))

    live_count = len(read_lines(f"{outdir}/live_subdomains.txt"))
    logger.success(f"Live subdomains: {live_count}")

    # ASN expansion via asnmap (on live IPs)
    if config.asnmap_expand:
        live_ips = f"{outdir}/live_ips.txt"
        if os.path.isfile(live_ips):
            run(
                ["asnmap", "-l", live_ips, "-silent", "-o", f"{outdir}/asn_cidrs.txt"],
                timeout=120,
            )
            logger.info("asnmap CIDR expansion complete.")

    return f"{outdir}/live_subdomains.txt"


# ─────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────

def run_phase(target: str, outdir: str, wildcard_mode: bool):
    """Called by main.py to run the full subdomain phase."""
    if config.should_skip(1, f"{outdir}/all_subdomains.txt"):
        return

    # Always run passive sources
    run_passive(target, outdir)

    # Merge passive results early for permutation input
    passive_src = [
        f"{outdir}/subfinder.txt", f"{outdir}/assetfinder.txt",
        f"{outdir}/findomain.txt", f"{outdir}/crtsh.txt",
        f"{outdir}/wayback_subs.txt", f"{outdir}/rapiddns.txt",
        f"{outdir}/leakix.txt", f"{outdir}/chaos.txt",
        f"{outdir}/bevigil.txt", f"{outdir}/haktrails.txt",
    ]
    passive_merged = f"{outdir}/all_passive_subs.txt"
    merge_deduplicate_and_cleanup(passive_src, passive_merged, delete_sources=False)

    if wildcard_mode:
        # Permutation generation
        run_permutations(target, outdir, passive_merged)
        # Active brute-force
        run_brute(target, outdir)
    else:
        logger.info("Single-domain mode – passive enumeration only.")
        subs_file = f"{outdir}/all_subdomains.txt"
        if not os.path.isfile(subs_file) or os.path.getsize(subs_file) == 0:
            if config.dry_run:
                logger.info(f"[DRY-RUN] seed {subs_file} with {target}")
            else:
                os.makedirs(outdir, exist_ok=True)
                with open(subs_file, "w") as fh:
                    fh.write(target + "\n")

    combine_and_probe(target, outdir)
