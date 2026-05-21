"""
Phase 4 – Technology, IPs & Screenshots
Phase 5 – Content Discovery
Tools: dnsx, shodan, httpx, whatweb, wpscan (WordPress targets),
       gau, waybackurls, hakrawler, katana, gospider,
       dirsearch, feroxbuster, ffuf, byp4xx,
       probe_graphql_native, probe_api_versions_native, probe_websocket_native,
       run_vhost_fuzz, collect_favicon_hashes, favicon_hash_shodan_lookup
"""
import os
from urllib.parse import urlparse
from core import logger
from core.runner import run, run_pipe, run_many, read_lines, write_file
from core.config import config
from utils.fileops import merge_deduplicate_and_cleanup
from utils.probes import (
    probe_graphql_native,
    probe_api_versions_native,
    probe_websocket_native,
    run_vhost_fuzz,
    collect_favicon_hashes,
    favicon_hash_shodan_lookup,
    detect_wordpress_targets,
)


def _in_scope_url(line: str, target: str) -> bool:
    host = urlparse(line).hostname
    if not host:
        return True
    target = target.lower().lstrip("*.")
    host = host.lower()
    return host == target or host.endswith("." + target)


# ─────────────────────────────────────────────────────────────────
# Phase 4
# ─────────────────────────────────────────────────────────────────

def run_phase4(target: str, outdir: str):
    if config.should_skip(3, f"{outdir}/httpx_tech.txt"):
        return

    logger.info("Phase 3: Technology Fingerprinting, IPs & Screenshots")
    live = f"{outdir}/live_subdomains.txt"
    if not os.path.isfile(live):
        logger.warning("live_subdomains.txt missing. Skipping Phase 3.")
        return

    # All tech fingerprinting tools run concurrently
    tech_tasks = {
        "dnsx_ips": dict(
            cmd=["dnsx", "-l", live, "-a", "-resp-only", "-o", f"{outdir}/live_ips.txt"],
            timeout=300,
        ),
        "httpx_tech": dict(
            cmd=[
                "httpx", "-list", live, "-silent", "-status-code", "-tech-detect", "-title",
                "-location", "-cl", "-probe", "-threads", "50",
                "-json", "-o", f"{outdir}/httpx_tech.json"
            ],
            timeout=600,
        ),
        "httpx_tech_txt": dict(
            cmd=[
                "httpx", "-list", live, "-silent", "-status-code", "-tech-detect", "-title",
                "-location", "-cl", "-probe", "-threads", "50",
                "-o", f"{outdir}/httpx_tech.txt"
            ],
            timeout=600,
        ),
        "shodan": dict(
            cmd=["shodan", "domain", target],
            output_file=f"{outdir}/shodan_info.txt",
            timeout=120,
        ),
        "whatweb": dict(
            cmd=["whatweb", "--quiet", "--input-file", live],
            output_file=f"{outdir}/whatweb_results.txt",
            timeout=300,
        ),
    }
    run_many(tech_tasks, max_workers=5)

    # Parse tech JSON to identify WordPress targets
    detect_wordpress_targets(f"{outdir}/httpx_tech.json", f"{outdir}/wordpress_targets.txt")

    # Run wpscan on WordPress targets (if any found)
    wp_targets = f"{outdir}/wordpress_targets.txt"
    if os.path.isfile(wp_targets) and os.path.getsize(wp_targets) > 0:
        logger.info("WordPress targets found — running wpscan")
        wp_hosts = read_lines(wp_targets)[:5]  # cap at 5
        wp_tasks = {}
        for host in wp_hosts:
            hn = host.replace("https://", "").replace("http://", "").replace("/", "_")
            cmd = [
                "wpscan", "--url", host, "--enumerate", "vp,vt,u",
                "--no-banner", "--format", "cli"
            ]
            if config.wpscan_api_key:
                cmd.extend(["--api-token", config.wpscan_api_key])
            cmd.extend(["-o", f"{outdir}/wpscan_{hn}.txt"])

            wp_tasks[f"wpscan_{hn}"] = dict(
                cmd=cmd,
                timeout=600,
            )
        if wp_tasks:
            run_many(wp_tasks, max_workers=min(3, len(wp_tasks)))

    # Favicon hash collection + Shodan lookup (concurrent)
    favicon_file = f"{outdir}/favicon_hashes.txt"
    collect_favicon_hashes(live, favicon_file)
    favicon_hash_shodan_lookup(favicon_file, outdir)


    logger.success("Phase 3 complete.")


# ─────────────────────────────────────────────────────────────────
# Phase 5
# ─────────────────────────────────────────────────────────────────

def run_phase5(target: str, outdir: str):
    if config.should_skip(4, f"{outdir}/all_crawled_urls.txt"):
        return

    logger.info("Phase 4: Content Discovery")
    live = f"{outdir}/live_subdomains.txt"

    # ── URL collection – all crawlers in parallel ──────────────────
    url_tasks = {
        "gau": dict(
            cmd=["gau", "--subs"],
            stdin_data=target + "\n",
            output_file=f"{outdir}/gau_urls.txt",
            timeout=600,
        ),
        "waybackurls": dict(
            cmd=["waybackurls"],
            stdin_data=target + "\n",
            output_file=f"{outdir}/wayback_urls.txt",
            timeout=300,
        ),
    }
    if os.path.isfile(live):
        live_data = ""
        try:
            with open(live, "r", encoding="utf-8", errors="ignore") as f:
                live_data = f.read()
        except OSError:
            pass

        url_tasks["hakrawler"] = dict(
            cmd=["hakrawler", "-d", "3", "-subs", "-u"],
            stdin_data=live_data,
            output_file=f"{outdir}/hakrawler_urls.txt",
            timeout=600,
        )
        url_tasks["katana"] = dict(
            cmd=["katana", "-list", live, "-d", "3", "-silent", "-o", f"{outdir}/katana_urls.txt"],
            timeout=600,
        )
        url_tasks["gospider"] = dict(
            cmd=["gospider", "-S", live, "-d", "3", "-t", "20", "--json"],
            output_file=f"{outdir}/gospider_raw.json",
            timeout=600,
        )

    run_many(url_tasks, max_workers=config.threads)

    # Post-process gospider JSON lines output
    raw_gospider = f"{outdir}/gospider_raw.json"
    gospider_urls = f"{outdir}/gospider_urls.txt"
    if os.path.isfile(raw_gospider):
        import json
        urls = []
        for line in read_lines(raw_gospider):
            try:
                data = json.loads(line)
                out = data.get("output")
                if out:
                    urls.append(out)
            except Exception:
                pass
        if urls:
            write_file(gospider_urls, "\n".join(urls) + "\n")
        try:
            os.remove(raw_gospider)
        except OSError:
            pass

    # ── Combine all crawled URLs ──────────────────────────────────
    all_crawled = f"{outdir}/all_crawled_urls.txt"
    merge_deduplicate_and_cleanup(
        source_files=[
            f"{outdir}/gau_urls.txt",
            f"{outdir}/wayback_urls.txt",
            f"{outdir}/hakrawler_urls.txt",
            f"{outdir}/katana_urls.txt",
            f"{outdir}/gospider_urls.txt",
        ],
        output_file=all_crawled,
        delete_sources=True,
        filter_fn=lambda line: _in_scope_url(line, target),
    )

    # Apply uro deduplication
    if os.path.isfile(all_crawled):
        uro_out = f"{outdir}/all_crawled_uro.txt"
        try:
            with open(all_crawled, "r", encoding="utf-8", errors="ignore") as fh:
                raw_urls = fh.read()
            uro_result = run(["uro"], stdin_data=raw_urls, timeout=120)
            if uro_result:
                with open(uro_out, "w", encoding="utf-8") as fh:
                    fh.write(uro_result)
                os.replace(uro_out, all_crawled)
        except Exception as e:
            logger.warning(f"uro dedup failed (non-fatal): {e}")

    logger.success(f"Crawled URLs merged -> {all_crawled}")

    # ── Additional endpoint discovery (concurrent) ─────────────────
    logger.info("Probing GraphQL, API versions, WebSockets, and VHosts")
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=4) as pool:
        pool.submit(probe_graphql_native, live, outdir)
        pool.submit(probe_api_versions_native, live, outdir)
        pool.submit(probe_websocket_native, all_crawled, outdir)
        pool.submit(run_vhost_fuzz, live, target, outdir, config.vhosts_wordlist)

    # ── Directory Fuzzing – top N live hosts in parallel ───────────
    hosts = read_lines(live) if os.path.isfile(live) else []
    limit = config.dir_fuzz_limit
    logger.info(f"Directory fuzzing top {min(limit, len(hosts))} hosts")

    fuzz_tasks = {}
    for host in hosts[:limit]:
        hn = host.replace("https://", "").replace("http://", "").replace("/", "_")
        fuzz_tasks[f"dirsearch_{hn}"] = dict(
            cmd=[
                "dirsearch", "-u", host,
                "-e", "conf,config,bak,backup,old,php,asp,aspx,js,json,env,xml,yaml,yml,txt,log",
                "-q", "-w", config.dirb_common, "-o", f"{outdir}/dirsearch_{hn}.txt"
            ],
            timeout=300,
        )
        fuzz_tasks[f"ffuf_{hn}"] = dict(
            cmd=[
                "ffuf", "-u", f"{host}/FUZZ", "-w", config.dirb_common,
                "-t", "50", "-fc", "404,403", "-o", f"{outdir}/ffuf_dir_{hn}.json"
            ],
            timeout=300,
        )

    if fuzz_tasks:
        run_many(fuzz_tasks, max_workers=config.threads)

    # Feroxbuster on all top hosts at once
    if os.path.isfile(live):
        top_hosts = read_lines(live)[:limit]
        if top_hosts:
            stdin_data = "\n".join(top_hosts) + "\n"
            run(
                [
                    "feroxbuster", "--stdin", "--quiet",
                    "-w", config.dirb_common, "-o", f"{outdir}/ferox_results.txt"
                ],
                stdin_data=stdin_data,
                timeout=600,
            )

    # ── byp4xx on 403 pages ────────────────────────────────────────
    auth_protected = f"{outdir}/auth_protected.txt"
    if os.path.isfile(auth_protected):
        logger.info("Running byp4xx on 403/401 responses")
        pages_403 = [
            line.split()[0] for line in read_lines(auth_protected)
            if "403" in line or "401" in line
        ][:20]  # cap
        byp_tasks = {}
        for i, url in enumerate(pages_403):
            byp_tasks[f"byp4xx_{i}"] = dict(
                cmd=["byp4xx", url],
                output_file=f"{outdir}/byp4xx_results.txt",
                append=True,
                timeout=60,
            )
        if byp_tasks:
            run_many(byp_tasks, max_workers=min(5, len(byp_tasks)))

    # ── Sensitive path probes – all in parallel ────────────────────
    logger.info("Probing sensitive paths")
    sensitive = {
        "/robots.txt":       "robots_txt_exposed.txt",
        "/.git/HEAD":        "git_exposed.txt",
        "/.env":             "env_exposed.txt",
        "/config.php":       "config_php_exposed.txt",
        "/admin":            "admin_exposed.txt",
        "/wp-login.php":     "wordpress_exposed.txt",
        "/phpinfo.php":      "phpinfo_exposed.txt",
        "/server-status":    "server_status_exposed.txt",
        "/.svn/entries":     "svn_exposed.txt",
        "/crossdomain.xml":  "crossdomain_exposed.txt",
        "/sitemap.xml":      "sitemap_exposed.txt",
        "/.DS_Store":        "dsstore_exposed.txt",
        "/backup.zip":       "backup_zip_exposed.txt",
        "/api/v1":           "api_v1_exposed.txt",
        "/api/v2":           "api_v2_exposed.txt",
        "/swagger.json":     "swagger_exposed.txt",
        "/openapi.json":     "openapi_exposed.txt",
        "/.htaccess":        "htaccess_exposed.txt",
        "/web.config":       "webconfig_exposed.txt",
        "/.bash_history":    "bash_history_exposed.txt",
        "/graphql":          "graphql_exposed.txt",
        "/actuator/health":  "actuator_health_exposed.txt",
        "/actuator/env":     "actuator_env_exposed.txt",
        "/.well-known/security.txt": "security_txt_exposed.txt",
    }
    if os.path.isfile(live):
        probe_tasks = {
            f"probe_{path.strip('/')}": dict(
                cmd=[
                    "httpx", "-l", live, "-path", path, "-status-code", "-mc", "200",
                    "-threads", "50", "-o", f"{outdir}/{outfile}"
                ],
                timeout=120,
            )
            for path, outfile in sensitive.items()
        }
        run_many(probe_tasks, max_workers=config.threads)

    logger.success("Phase 4 complete.")
