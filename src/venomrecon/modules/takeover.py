"""
Phase 3 – Subdomain Takeover
Tools: subzy, nuclei (takeover tags + templates), subjack, dnsx CNAME check, tko-subs
All tools run concurrently for maximum speed.
"""
import os
from core import logger
from core.runner import run, run_pipe, run_many, read_lines
from core.config import config


def run_phase(target: str, outdir: str):
    logger.info("Phase 2: Subdomain Takeover Checks (all concurrent)")
    all_subs = f"{outdir}/all_subdomains.txt"
    if not os.path.isfile(all_subs):
        logger.warning("all_subdomains.txt not found. Skipping takeover phase.")
        return

    takeover_tasks = {
        # subzy — fingerprint-based check
        "subzy": dict(
            cmd=[
                "subzy", "run", "--targets", all_subs,
                "--hide-fails", "--verify_ssl", "--concurrency", "20",
                "--output", f"{outdir}/subzy_results.txt"
            ],
            timeout=600,
        ),
        # nuclei takeover templates
        "nuclei_takeover": dict(
            cmd=[
                "nuclei", "-l", all_subs, "-tags", "takeover",
                "-severity", "high,critical", "-stats",
                "-o", f"{outdir}/nuclei_takeover.txt"
            ],
            timeout=900,
        ),
        # tko-subs
        "tko_subs": dict(
            cmd=[
                "tko-subs", "-domains", all_subs,
                "-data", "/usr/share/tko-subs/providers-data.csv",
                "-output", f"{outdir}/tkosubs_results.txt"
            ],
            timeout=300,
        ),
    }

    # subjack (optional – needs fingerprints file)
    if os.path.isfile(config.subjack_fingerprints):
        takeover_tasks["subjack"] = dict(
            cmd=[
                "subjack", "-w", all_subs, "-t", "100",
                "-timeout", "30", "-ssl", "-v",
                "-c", config.subjack_fingerprints,
                "-o", f"{outdir}/subjack_takeover.txt"
            ],
            timeout=600,
        )
    else:
        logger.warning(
            f"subjack fingerprints not found at {config.subjack_fingerprints}. "
            "Skipping subjack."
        )

    run_many(takeover_tasks, max_workers=len(takeover_tasks))

    # CNAME verification – dig on subzy results
    subzy_file = f"{outdir}/subzy_results.txt"
    cname_file = f"{outdir}/cname_verification.txt"
    if os.path.isfile(subzy_file):
        lines = read_lines(subzy_file)
        with open(cname_file, "w", encoding="utf-8") as cf:
            for line in lines:
                if "Not Vulnerable" not in line:
                    parts = line.split()
                    domain = parts[1] if len(parts) > 1 else ""
                    if domain:
                        dig_out = run(["dig", domain, "CNAME", "+short"], timeout=15)
                        cf.write(f"### {domain}\n{dig_out}\n\n")

    logger.success(
        "Phase 2 complete. See subzy_results.txt, nuclei_takeover.txt, "
        "subjack_takeover.txt, tkosubs_results.txt"
    )
