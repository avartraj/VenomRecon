"""Markdown and JSON report generation."""

import json
import os
from datetime import datetime

from core import logger
from core.config import config
from core.runner import read_lines


def _file_lines(path: str, limit: int = 0):
    lines = read_lines(path)
    return lines[:limit] if limit else lines


def _read_json(path: str, default):
    if not os.path.isfile(path):
        return default
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def collect_findings(domain: str, outdir: str) -> dict:
    secrets = _read_json(os.path.join(outdir, "js_secrets_all.json"), [])
    vulns = []
    for fname in [
        "all_confirmed_vulns.txt",
        "lfi_confirmed.txt",
        "openredirect_confirmed.txt",
        "dalfox_xss.txt",
        "ssti_confirmed.txt",
        "ssrf_fired.txt",
        "crlf_results.txt",
        "host_header_results.txt",
        "cors_bypass.txt",
        "nuclei_rce.txt",
    ]:
        for line in _file_lines(os.path.join(outdir, fname)):
            vulns.append({"source": fname, "detail": line})

    nuclei = []
    for fname in ["nuclei_critical_high_all.txt", "nuclei_critical.txt", "nuclei_cves.txt"]:
        for line in _file_lines(os.path.join(outdir, fname)):
            nuclei.append({"source": fname, "detail": line})

    summary = {
        "subdomains": len(_file_lines(os.path.join(outdir, "all_subdomains.txt"))),
        "live_hosts": len(_file_lines(os.path.join(outdir, "live_subdomains.txt"))),
        "secrets": len(secrets),
        "verified_secrets": len([s for s in secrets if s.get("verified")]),
        "vulnerabilities": len(vulns),
        "nuclei_critical_high": len(nuclei),
    }
    return {
        "target": domain,
        "timestamp": datetime.now().astimezone().isoformat(),
        "summary": summary,
        "subdomains": _file_lines(os.path.join(outdir, "all_subdomains.txt")),
        "live_hosts": _file_lines(os.path.join(outdir, "live_subdomains.txt")),
        "secrets": secrets,
        "vulnerabilities": vulns,
        "nuclei_findings": nuclei,
        "sourcemap_sources": _file_lines(os.path.join(outdir, "sourcemap_sources.txt")),
    }


def generate_json_report(domain: str, outdir: str, findings: dict = None) -> str:
    findings = findings or collect_findings(domain, outdir)
    path = os.path.join(outdir, "report.json")
    if config.dry_run:
        logger.info(f"[DRY-RUN] write {path}")
        return path
    with open(path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2, sort_keys=True)
    return path


def _write_lines_section(fh, title: str, lines: list[str], limit: int = 50):
    fh.write(f"## {title}\n\n")
    if not lines:
        fh.write("_No findings recorded._\n\n")
        return
    fh.write("```text\n")
    for line in lines[:limit]:
        fh.write(line + "\n")
    fh.write("```\n\n")


def generate_report(domain: str, outdir: str, findings: dict = None) -> str:
    logger.phase(13, "Report Generation")
    findings = findings or collect_findings(domain, outdir)
    markdown = os.path.join(outdir, "report.md")
    generate_json_report(domain, outdir, findings)
    if config.dry_run:
        logger.info(f"[DRY-RUN] write {markdown}")
        return markdown

    secrets_by_severity = {sev: [] for sev in ("critical", "high", "medium", "low")}
    for secret in findings.get("secrets", []):
        sev = secret.get("severity", "low")
        secrets_by_severity.setdefault(sev, []).append(
            f"{secret.get('type')} [{secret.get('confidence')}] "
            f"{secret.get('value_preview')} sha256={secret.get('value_hash')} "
            f"source={secret.get('source')}"
        )

    with open(markdown, "w", encoding="utf-8") as f:
        f.write(f"# VenomRecon Report - {domain}\n\n")
        f.write(f"*Generated: {findings.get('timestamp')}*\n\n")
        f.write("## Executive Summary\n\n")
        f.write("| Metric | Value |\n|--------|-------|\n")
        for key, value in findings.get("summary", {}).items():
            f.write(f"| {key.replace('_', ' ').title()} | {value} |\n")
        f.write("\n")

        _write_lines_section(f, "Live Subdomains", findings.get("live_hosts", []), 100)
        _write_lines_section(f, "Takeover Candidates", _file_lines(os.path.join(outdir, "cname_verification.txt")), 80)

        f.write("## JS Secrets\n\n")
        for sev in ("critical", "high", "medium", "low"):
            f.write(f"### {sev.title()}\n\n")
            rows = secrets_by_severity.get(sev, [])
            if rows:
                f.write("```text\n" + "\n".join(rows[:80]) + "\n```\n\n")
            else:
                f.write("_No findings recorded._\n\n")

        _write_lines_section(f, "Verified Secrets", _file_lines(os.path.join(outdir, "js_secrets_verified.txt")), 80)
        _write_lines_section(f, "Source Map Exposures", findings.get("sourcemap_sources", []), 80)

        sensitive = []
        for fname in ["git_exposed.txt", "env_exposed.txt", "admin_exposed.txt", "swagger_exposed.txt", "juicy_archive.txt"]:
            sensitive.extend(f"{fname}: {line}" for line in _file_lines(os.path.join(outdir, fname), 20))
        _write_lines_section(f, "Sensitive Files and Endpoints", sensitive, 100)

        _write_lines_section(
            f,
            "Vulnerability Findings",
            [f"{v['source']}: {v['detail']}" for v in findings.get("vulnerabilities", [])],
            120,
        )
        _write_lines_section(
            f,
            "Nuclei Critical/High Findings",
            [f"{n['source']}: {n['detail']}" for n in findings.get("nuclei_findings", [])],
            120,
        )

        cloud = []
        for fname in ["s3_confirmed.txt", "cloud_storage_exposed.txt", "cloud_enum_results.txt", "nuclei_misconfig.txt"]:
            cloud.extend(f"{fname}: {line}" for line in _file_lines(os.path.join(outdir, fname), 30))
        _write_lines_section(f, "Cloud and Misconfiguration Findings", cloud, 120)

        f.write("## Scan Metadata\n\n")
        f.write("```text\n")
        for name in sorted(os.listdir(outdir)):
            path = os.path.join(outdir, name)
            if os.path.isfile(path):
                f.write(f"{name}: {os.path.getsize(path)} bytes\n")
        f.write("```\n")

    logger.success(f"Report saved -> {markdown}")
    return markdown
