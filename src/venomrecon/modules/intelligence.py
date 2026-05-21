"""
Phase 7  – Archive & DNS History
Phase 8  – JavaScript Recon
Phase 9  – GitHub Recon
Phase 10 – Cloud Recon
Phase 11 – DNS, ASN, Ports (+ email security, zone transfer, DNSSEC, asnmap)
All independent tools within each phase are run concurrently.
Phases 7-11 are called concurrently from main.py.
"""
import os
import json
import re
import ssl
import urllib.request
import threading
from urllib.parse import urlparse
from core import logger
from core.runner import run, run_pipe, run_many, read_lines, write_file
from core.config import config
from utils.fileops import merge_deduplicate_and_cleanup, atomic_write
from concurrent.futures import ThreadPoolExecutor
from utils.probes import (
    check_spf_record,
    check_dmarc_record,
    check_dkim_record,
    attempt_zone_transfer,
    check_dnssec,
)
from utils.js_secrets import (
    collect_js_urls_from_file,
    discover_and_fetch_sourcemaps,
    is_js_url,
    scan_js_sources,
    write_js_findings,
)


# ─────────────────────────────────────────────────────────────────
# Phase 7 – Archive & DNS History
# ─────────────────────────────────────────────────────────────────

def run_phase7(target: str, outdir: str):
    if config.should_skip(6, f"{outdir}/juicy_archive.txt"):
        return
    logger.info("Phase 6: Archive & DNS History")
    wayback = f"{outdir}/wayback_urls.txt"

    # Filter wayback URLs for juicy keywords natively in Python
    if os.path.isfile(wayback):
        try:
            pat = re.compile(
                r'admin|login|upload|api|config|\.env|\.git|backup|password|secret|token|key',
                re.IGNORECASE
            )
            lines = read_lines(wayback)
            matched = [line for line in lines if pat.search(line)]
            if matched:
                atomic_write(f"{outdir}/juicy_archive.txt", matched)
            else:
                atomic_write(f"{outdir}/juicy_archive.txt", [])
        except Exception as e:
            logger.error(f"Error filtering wayback URLs: {e}")
            atomic_write(f"{outdir}/juicy_archive.txt", [])

    # Fetch SecurityTrails passive subdomains and DNS history natively
    if config.securitytrails_api_key:
        # 1. Subdomains
        try:
            url = f"https://api.securitytrails.com/v1/domain/{target}/subdomains"
            req = urllib.request.Request(
                url,
                headers={
                    "APIKEY": config.securitytrails_api_key,
                    "Accept": "application/json",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
                }
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                subs = data.get("subdomains", [])
                lines = [f"{sub}.{target}" for sub in subs]
                atomic_write(f"{outdir}/securitytrails_subs.txt", lines)
        except Exception as e:
            logger.error(f"Error fetching SecurityTrails subdomains: {e}", context="securitytrails")
            atomic_write(f"{outdir}/securitytrails_subs.txt", [])

        # 2. DNS History
        try:
            url = f"https://api.securitytrails.com/v1/domain/{target}/dns_history/a"
            req = urllib.request.Request(
                url,
                headers={
                    "APIKEY": config.securitytrails_api_key,
                    "Accept": "application/json",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
                }
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                content = resp.read().decode("utf-8", errors="ignore")
                atomic_write(f"{outdir}/securitytrails_dns_history.txt", [content])
        except Exception as e:
            logger.error(f"Error fetching SecurityTrails DNS history: {e}", context="securitytrails")
            atomic_write(f"{outdir}/securitytrails_dns_history.txt", [])

    logger.success("Phase 6 complete.")


def _in_scope_url(url: str, target: str) -> bool:
    try:
        host = urlparse(url).netloc.lower()
        if not host:
            return True
        target = target.lower().lstrip("*.")
        return host == target or host.endswith("." + target)
    except Exception:
        return False


def run_phase8(target: str, outdir: str):
    if config.should_skip(7, f"{outdir}/js_secrets.txt"):
        return
    logger.info("Phase 7: JavaScript Recon (Direct URL Parsing)")

    all_crawled = f"{outdir}/all_crawled_urls.txt"
    js_urls_file = f"{outdir}/all_js_urls.txt"
    live = f"{outdir}/live_subdomains.txt"

    # Extract JS URLs from crawled URLs natively in Python
    crawled_js_file = f"{outdir}/crawled_js_urls.txt"
    if os.path.isfile(all_crawled):
        try:
            pat = re.compile(r'\.js($|\?)', re.IGNORECASE)
            lines = read_lines(all_crawled)
            js_lines = sorted({line for line in lines if pat.search(line)})
            atomic_write(crawled_js_file, js_lines)
        except Exception as e:
            logger.error(f"Error extracting JS URLs: {e}")
            atomic_write(crawled_js_file, [])

    # Extract JS URLs using getJS/subjs (concurrent)
    js_tasks = {}
    if os.path.isfile(live):
        live_data = ""
        try:
            with open(live, "r", encoding="utf-8", errors="ignore") as f:
                live_data = f.read()
        except OSError:
            pass

        js_tasks["getjs"] = dict(
            cmd=["getJS", "--complete"],
            stdin_data=live_data,
            output_file=f"{outdir}/getjs_urls.txt",
            timeout=300,
        )
        js_tasks["subjs"] = dict(
            cmd=["subjs", "-i", live, "-o", f"{outdir}/subjs_urls.txt"],
            timeout=300,
        )
    if js_tasks:
        run_many(js_tasks, max_workers=len(js_tasks))

    merge_deduplicate_and_cleanup(
        source_files=[
            f"{outdir}/crawled_js_urls.txt",
            f"{outdir}/getjs_urls.txt",
            f"{outdir}/subjs_urls.txt",
            f"{outdir}/linkfinder_results.txt",
        ],
        output_file=js_urls_file,
        delete_sources=False,
        filter_fn=lambda line: is_js_url(line) and _in_scope_url(line, target),
    )
    
    # URL Direct Interaction Scanning (No Downloading Bloat)
    if os.path.isfile(js_urls_file) and os.path.getsize(js_urls_file) > 0:
        js_urls_data = ""
        try:
            with open(js_urls_file, "r", encoding="utf-8", errors="ignore") as f:
                js_urls_data = f.read()
        except OSError:
            pass

        scan_tasks = {
            "nuclei_js_secrets": dict(
                cmd=["nuclei", "-l", js_urls_file, "-t", "http/javascript,exposure,token,config", "-silent", "-o", f"{outdir}/js_secrets.txt"],
                timeout=1800,
            ),
            "jsluice_remote": dict(
                cmd=["jsluice", "urls"],
                stdin_data=js_urls_data,
                output_file=f"{outdir}/jsluice_urls.txt",
                timeout=1800,
            ),
            "jsluice_sec_remote": dict(
                cmd=["jsluice", "secrets"],
                stdin_data=js_urls_data,
                output_file=f"{outdir}/jsluice_secrets.txt",
                timeout=1800,
            )
        }
        run_many(scan_tasks, max_workers=3)

        # Python-based logic (sequential fallback checks)
        import os
        from pathlib import Path
        scripts_dir = os.path.join(str(Path.home()), "venomrecon-scripts")
        
        for script_rel, out in [
            ("SecretFinder/SecretFinder.py", f"{outdir}/secretfinder_results.txt"),
            ("LinkFinder/linkfinder.py",   f"{outdir}/linkfinder_results.txt"),
        ]:
            script_abs = os.path.join(scripts_dir, script_rel)
            run(
                ["python3", script_abs, "-i", js_urls_file, "-o", "cli"],
                output_file=out,
                append=True,
                timeout=1800
            )

    js_urls = collect_js_urls_from_file(js_urls_file)
    if config.profile == "passive":
        logger.info("Passive profile active: scanning collected JS URL text only.")
        passive_rows = [line for line in read_lines(js_urls_file)]
        atomic_write(f"{outdir}/sourcemap_sources.txt", [])
        findings = scan_js_sources(
            [],
            outdir,
            extra_files=[
                js_urls_file,
                f"{outdir}/jsluice_urls.txt",
                f"{outdir}/jsluice_secrets.txt",
                f"{outdir}/secretfinder_results.txt",
                f"{outdir}/linkfinder_results.txt",
            ],
        )
        if passive_rows:
            logger.info(f"Collected {len(passive_rows)} JS URL references for passive analysis.")
    else:
        discover_and_fetch_sourcemaps(js_urls, outdir)
        findings = scan_js_sources(
            js_urls,
            outdir,
            extra_files=[
                f"{outdir}/jsluice_urls.txt",
                f"{outdir}/jsluice_secrets.txt",
                f"{outdir}/secretfinder_results.txt",
                f"{outdir}/linkfinder_results.txt",
            ],
        )
    write_js_findings(findings, outdir)
    logger.success(f"Phase 7 Python secret engine complete: {len(findings)} unique findings.")
    logger.success("Phase 7 complete.")


# ─────────────────────────────────────────────────────────────────
# Phase 9 – GitHub Recon
# ─────────────────────────────────────────────────────────────────

def run_phase9(target: str, outdir: str):
    if config.should_skip(8, f"{outdir}/gitdorker_results.txt"):
        return
    logger.info("Phase 8: GitHub Recon")
    org = target.split(".")[0]

    tasks = {}

    if os.path.isfile(config.medium_dorks) and os.path.isfile(config.github_tokens_file):
        tasks["gitdorker"] = dict(
            cmd=[
                "python3", "GitDorker.py", "-d", config.medium_dorks,
                "-tf", config.github_tokens_file, "-q", target, "-lb",
                "-o", f"{outdir}/gitdorker_results.txt"
            ],
            timeout=300,
        )

    if config.github_token:
        tasks["trufflehog"] = dict(
            cmd=["trufflehog", "github", "--org", org, "--only-verified", "--token", config.github_token],
            output_file=f"{outdir}/trufflehog_results.txt",
            timeout=300,
        )
        tasks["gitleaks"] = dict(
            cmd=[
                "gitleaks", "detect", "--source", f"https://github.com/{org}",
                "--report-path", f"{outdir}/gitleaks.json"
            ],
            timeout=300,
        )

    if tasks:
        run_many(tasks, max_workers=len(tasks))

    # gh CLI manual dorks (sequential – rate-limited API)
    if config.github_token:
        dork_results = f"{outdir}/github_manual_dorks.txt"
        for q in [f"'{target}' password", f"'{target}' secret",
                  f"'{target}' api_key", f"'{target}' token"]:
            run(
                ["gh", "search", "code", q, "--limit", "20", "--json", "path,repository"],
                output_file=dork_results,
                append=True,
                timeout=60,
            )

    logger.success("Phase 8 complete.")


# ─────────────────────────────────────────────────────────────────
# Phase 10 – Cloud Recon
# ─────────────────────────────────────────────────────────────────

def run_phase10(target: str, outdir: str):
    if config.should_skip(9, f"{outdir}/cloud_enum_results.txt"):
        return
    logger.info("Phase 9: Cloud Recon")
    company = target.split(".")[0]
    all_crawled = f"{outdir}/all_crawled_urls.txt"

    # Cloud enumeration tools (parallel)
    cloud_tasks = {
        "cloud_enum": dict(
            cmd=[
                "cloud_enum", "-k", target,
                "-b", "/usr/share/wordlists/seclists/Discovery/Infrastructure/cloud-metadata.txt",
                "-o", f"{outdir}/cloud_enum_results.txt"
            ],
            timeout=300,
        ),
        "cloudhunter": dict(
            cmd=["python3", os.path.join(str(Path.home()), "venomrecon-scripts", "cloudhunter/cloudhunter.py"), "-t", "s3", "-d", target],
            output_file=f"{outdir}/cloudhunter_results.txt",
            append=True,
            timeout=180,
        ),
    }

    # Extract S3 hits natively in Python
    s3_hits_file = f"{outdir}/s3_hits.txt"
    if os.path.isfile(all_crawled):
        try:
            patterns = [
                r'[a-zA-Z0-9.-]+\.s3\.amazonaws\.com',
                r'[a-zA-Z0-9.-]+\.s3-[a-zA-Z0-9-]+\.amazonaws\.com',
                r'[a-zA-Z0-9.-]+\.s3\.dualstack\.[a-zA-Z0-9-]+\.amazonaws\.com',
                r'[a-zA-Z0-9.-]+\.s3\.[a-zA-Z0-9-]+\.amazonaws\.com',
                r's3://[a-zA-Z0-9.-]+'
            ]
            combined_pattern = re.compile('|'.join(f'(?:{p})' for p in patterns), re.IGNORECASE)
            hits = set()
            for line in read_lines(all_crawled):
                for match in combined_pattern.finditer(line):
                    hits.add(match.group(0))
            if hits:
                atomic_write(s3_hits_file, sorted(hits))
            else:
                atomic_write(s3_hits_file, [])
        except Exception as e:
            logger.error(f"Error parsing S3 buckets: {e}")
            atomic_write(s3_hits_file, [])

    run_many(cloud_tasks, max_workers=len(cloud_tasks))

    # Verify S3 hits natively in Python
    s3_hits = read_lines(s3_hits_file) if os.path.isfile(s3_hits_file) else []
    s3_file = f"{outdir}/s3_confirmed.txt"
    for url in s3_hits:
        req_url = url
        if req_url.startswith("s3://"):
            req_url = f"https://{req_url[5:]}.s3.amazonaws.com"
        elif not req_url.startswith("http://") and not req_url.startswith("https://"):
            req_url = f"https://{req_url}"

        try:
            req = urllib.request.Request(
                req_url,
                method="HEAD",
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            )
            ctx = ssl._create_unverified_context()
            try:
                with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                    headers = resp.info()
            except urllib.error.HTTPError as he:
                headers = he.headers
            
            matched_headers = []
            for hname, hval in headers.items():
                if hname.lower() in ("x-amz-bucket-region", "x-amz-request-id"):
                    matched_headers.append(f"{hname}: {hval}")
            
            if matched_headers:
                with open(s3_file, "a", encoding="utf-8") as fh:
                    fh.write(f"S3 confirmed: {url}\n" + "\n".join(matched_headers) + "\n\n")
        except Exception:
            pass

    # Azure / GCP blob quick-check natively in Python (concurrently)
    def check_cloud_storage(label: str, url: str, results_dict: dict):
        try:
            req = urllib.request.Request(
                url,
                method="GET",
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            )
            ctx = ssl._create_unverified_context()
            try:
                with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                    code = resp.status
            except urllib.error.HTTPError as he:
                code = he.code
            results_dict[label] = str(code)
        except Exception:
            results_dict[label] = "000"

    cloud_results = {}
    threads = []
    checks = {
        f"azure_{company}": f"https://{company}.blob.core.windows.net",
        f"azure_{company}_backup": f"https://{company}backup.blob.core.windows.net",
        f"gcp_{company}": f"https://storage.googleapis.com/{company}",
    }
    for label, url in checks.items():
        t = threading.Thread(target=check_cloud_storage, args=(label, url, cloud_results))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    cloud_exposed = f"{outdir}/cloud_storage_exposed.txt"
    for label, code in cloud_results.items():
        if code.startswith("200") or code.startswith("403"):
            with open(cloud_exposed, "a", encoding="utf-8") as fh:
                fh.write(f"{label}: HTTP {code}\n")

    logger.success("Phase 9 complete.")


# ─────────────────────────────────────────────────────────────────
# Phase 11 – DNS, ASN, Ports
# ─────────────────────────────────────────────────────────────────

def run_phase11(target: str, outdir: str):
    if config.should_skip(10, f"{outdir}/whois.txt"):
        return
    logger.info("Phase 10: DNS, ASN & Port Scanning")
    phase_cfg = config.phase_overrides.get(10, {})

    # WHOIS, dnsrecon, dnsx (parallel)
    info_tasks = {
        "whois": dict(
            cmd=["whois", target],
            output_file=f"{outdir}/whois.txt",
            timeout=60,
        ),
        "dnsrecon": dict(
            cmd=["dnsrecon", "-d", target, "-t", "axfr", "-c", f"{outdir}/dnsrecon.csv"],
            timeout=120,
        ),
        "dnsx_records": dict(
            cmd=["dnsx", "-d", target, "-a", "-mx", "-ns", "-txt", "-resp", "-o", f"{outdir}/dnsx_records.txt"],
            timeout=120,
        ),
    }
    run_many(info_tasks, max_workers=len(info_tasks))

    # ASN lookup natively in Python by parsing WHOIS results
    asn = ""
    whois_file = f"{outdir}/whois.txt"
    if os.path.isfile(whois_file):
        for line in read_lines(whois_file):
            if "origin" in line.lower():
                parts = line.strip().split()
                if parts:
                    asn = parts[-1]
                break
    
    if not asn:
        # Fallback to run whois again if file is empty
        whois_out = run(["whois", target], timeout=30)
        for line in whois_out.splitlines():
            if "origin" in line.lower():
                parts = line.strip().split()
                if parts:
                    asn = parts[-1]
                break

    if asn:
        with open(f"{outdir}/asn.txt", "w", encoding="utf-8") as fh:
            fh.write(f"ASN: {asn}\n")
        logger.info(f"ASN: {asn}")
        if config.shodan_api_key and phase_cfg.get("shodan", True):
            try:
                url = f"https://api.shodan.io/shodan/host/search?key={config.shodan_api_key}&query=asn:{asn}"
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
                )
                with urllib.request.urlopen(req, timeout=60) as resp:
                    data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                    ips = [match.get("ip_str") for match in data.get("matches", []) if match.get("ip_str")]
                    if ips:
                        atomic_write(f"{outdir}/asn_ips.txt", ips)
            except Exception as e:
                logger.error(f"Error fetching Shodan ASN IPs: {e}", context="shodan_asn")

    # Port scans – nmap + masscan (parallel)
    live_ips = f"{outdir}/live_ips.txt"
    if os.path.isfile(live_ips) and phase_cfg.get("port_scan", True):
        run_many(
            {
                "nmap": dict(
                    cmd=["nmap", "-iL", live_ips, "--top-ports", "1000", "-T4", "-oN", f"{outdir}/nmap_quick.txt"],
                    timeout=900,
                ),
                "masscan": dict(
                    cmd=["masscan", "-iL", live_ips, "-p0-65535", "--rate=5000", "-oG", f"{outdir}/masscan_results.txt"],
                    timeout=900,
                ),
            },
            max_workers=2,
        )

    # CORS checks (parallel)
    live = f"{outdir}/live_subdomains.txt"
    if os.path.isfile(live) and phase_cfg.get("cors", True):
        run_many(
            {
                "corstest": dict(
                    cmd=["python3", os.path.join(str(Path.home()), "venomrecon-scripts", "CORStest/CORStest.py"), "-p", "50", "-i", live, "-o", f"{outdir}/cors_results.txt"],
                    timeout=300,
                ),
                "corsy": dict(
                    cmd=["python3", os.path.join(str(Path.home()), "venomrecon-scripts", "Corsy/corsy.py"), "-i", live, "-t", "10", "--headers", "User-Agent: GoogleBot"],
                    output_file=f"{outdir}/cors_results.txt",
                    append=True,
                    timeout=300,
                ),
            },
            max_workers=2,
        )

    # ── Email security + DNS security checks (concurrent) ─────────
    all_subs = f"{outdir}/all_subdomains.txt"
    email_outfile = f"{outdir}/email_security_findings.txt"
    zt_outfile = f"{outdir}/zone_transfer_findings.txt"
    dnssec_outfile = f"{outdir}/dnssec_findings.txt"

    def _run_email_dns_security():
        with ThreadPoolExecutor(max_workers=5) as pool:
            pool.submit(check_spf_record, target, email_outfile)
            pool.submit(check_dmarc_record, target, email_outfile)
            pool.submit(check_dkim_record, target, email_outfile)
            if os.path.isfile(all_subs):
                pool.submit(attempt_zone_transfer, all_subs, zt_outfile)
            pool.submit(check_dnssec, target, dnssec_outfile)

    _run_email_dns_security()
    logger.info("Email/DNS security checks complete (SPF, DMARC, DKIM, zone transfer, DNSSEC).")

    # ── asnmap CIDR expansion ──────────────────────────────────────
    live_ips = f"{outdir}/live_ips.txt"
    if os.path.isfile(live_ips) and config.asnmap_expand:
        run(
            ["asnmap", "-l", live_ips, "-silent", "-o", f"{outdir}/asn_cidrs.txt"],
            timeout=120,
        )
        logger.info("asnmap CIDR expansion complete.")

    logger.success("Phase 10 complete.")
