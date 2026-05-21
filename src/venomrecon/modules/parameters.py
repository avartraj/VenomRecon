"""
Phase 6 – Parameter Discovery
Tools: uro, arjun, paramspider, x8, gf (sqli, xss, lfi, redirect, ssrf, rce, ssti)
"""
import os
from core import logger
from core.runner import run, run_pipe
from core.config import config


def run_phase(target: str, outdir: str):
    logger.info("Phase 5: Parameter Discovery")
    all_crawled = f"{outdir}/all_crawled_urls.txt"

    if not os.path.isfile(all_crawled):
        logger.warning("all_crawled_urls.txt not found. Skipping Phase 5.")
        return

    # Deduplicate and clean URLs with uro
    param_urls = f"{outdir}/param_urls.txt"
    run_pipe(
        f"cat {all_crawled} | grep '?' | uro | sort -u",
        output_file=param_urls
    )

    # arjun – discover hidden parameters
    if os.path.isfile(param_urls):
        run(
            f"arjun -i {param_urls} -oT {outdir}/arjun_params.txt 2>/dev/null",
            timeout=600
        )

    # paramspider
    run(
        f"paramspider --domain {target} --exclude woff,css,png,jpg,svg,ttf "
        f"--output {outdir}/paramspider.txt 2>/dev/null",
        timeout=300
    )

    # x8 – secret parameter discovery
    if os.path.isfile(param_urls):
        run(
            f"x8 -u {param_urls} -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt "
            f"--output {outdir}/x8_params.txt 2>/dev/null",
            timeout=300
        )

    # gf pattern matching
    gf_patterns = {
        "sqli": "sqli_params.txt",
        "xss": "xss_params.txt",
        "lfi": "lfi_params.txt",
        "redirect": "redirect_params.txt",
        "ssrf": "ssrf_params.txt",
        "rce": "rce_params.txt",
        "ssti": "ssti_params.txt",
        "idor": "idor_params.txt",
        "debug_logic": "debug_params.txt",
    }

    if os.path.isfile(param_urls):
        for pattern, outfile in gf_patterns.items():
            run_pipe(
                f"cat {param_urls} | gf {pattern}",
                output_file=f"{outdir}/{outfile}"
            )

    logger.success("Phase 5 complete. See param_urls.txt, arjun_params.txt, gf pattern files.")
