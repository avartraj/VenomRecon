"""
Phase 6 – Parameter Discovery
Tools: uro, arjun, paramspider, x8, gf (sqli, xss, lfi, redirect, ssrf, rce, ssti)
"""
import os
from core import logger
from core.runner import run, run_pipe
from core.config import config


def run_phase(target: str, outdir: str):
    import shlex
    logger.info("Phase 6: Parameter Discovery")
    all_crawled = f"{outdir}/all_crawled_urls.txt"

    if not os.path.isfile(all_crawled):
        logger.warning("all_crawled_urls.txt not found. Skipping Phase 5.")
        return

    # shlex.quote() to handle output directories that contain spaces or special chars.
    param_urls = f"{outdir}/param_urls.txt"
    run_pipe(
        f"cat {shlex.quote(all_crawled)} | grep '?' | uro | sort -u",
        validated_inputs={"all_crawled": all_crawled},
        output_file=param_urls,
    )

    # arjun – discover hidden parameters (list form avoids shell quoting issues)
    if not os.path.isfile(param_urls): return
        run(
            ["arjun", "-i", param_urls, "-oT", f"{outdir}/arjun_params.txt"],
            timeout=600,
        )

    # paramspider (target is already validated by sanitize_domain())
    run(
        ["paramspider", "--domain", target,
         "--exclude", "woff,css,png,jpg,svg,ttf",
         "--output", f"{outdir}/paramspider.txt"],
        timeout=300,
    )

    # x8 – secret parameter discovery
    if not os.path.isfile(param_urls): return
        run(
            ["x8", "-l", param_urls,
             "-w", "/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt",
             "--output", f"{outdir}/x8_params.txt"],
            timeout=300,
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

    if not os.path.isfile(param_urls): return
        for pattern, outfile in gf_patterns.items():
            run_pipe(
                f"cat {shlex.quote(param_urls)} | gf {shlex.quote(pattern)}",
                validated_inputs={"param_urls": param_urls, "pattern": pattern},
                output_file=f"{outdir}/{outfile}",
            )

    logger.success("Phase 6 complete. See param_urls.txt, arjun_params.txt, gf pattern files.")
