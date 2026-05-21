"""JavaScript secret, endpoint, and exposure detection."""

import json
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

import requests

from core import logger
from core.config import config
from core.runner import read_lines
from utils.fileops import atomic_write
from utils.secret_verifier import secret_hash, secret_preview, verify_secret


JS_SECRET_PATTERNS = {
    "aws_access_key": (r"(?:AKIA|AIPA|AROA|AIDA|ASIA)[A-Z0-9]{16}", "critical"),
    "aws_secret_key": (r"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key['\"\s:=]+([A-Za-z0-9/+]{40})", "critical"),
    "aws_session_token": (r"(?i)aws[_\-\s]?session[_\-\s]?token['\"\s:=]+([A-Za-z0-9/+=]{100,})", "critical"),
    "gcp_service_account": (r'"type"\s*:\s*"service_account"', "critical"),
    "gcp_api_key": (r"AIza[0-9A-Za-z\-_]{35}", "critical"),
    "azure_client_secret": (r"(?i)azure[_\-\s]?(?:client[_\-\s]?secret|ad[_\-\s]?secret)['\"\s:=]+([A-Za-z0-9\-_~.]{34,})", "critical"),
    "azure_storage_key": (r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}", "critical"),
    "cloudflare_api_key": (r"(?i)cloudflare[_\-\s]?(?:api[_\-\s]?)?(?:key|token)['\"\s:=]+([A-Za-z0-9_\-]{37,40})", "high"),
    "cloudflare_global_key": (r"[0-9a-f]{37}CLOUDFLARE", "high"),
    "supabase_key": (r"(?i)supabase[_\-\s]?(?:anon[_\-\s]?)?key['\"\s:=]+(eyJ[A-Za-z0-9._\-]{50,})", "critical"),
    "supabase_url": (r"https://[a-z0-9]{20}\.supabase\.co", "high"),
    "openai_key": (r"sk-[A-Za-z0-9]{48,}", "critical"),
    "openai_org": (r"org-[A-Za-z0-9]{24}", "medium"),
    "anthropic_key": (r"sk-ant-[A-Za-z0-9\-_]{93,}", "critical"),
    "cohere_key": (r"(?i)cohere[_\-\s]?(?:api[_\-\s]?)?key['\"\s:=]+([A-Za-z0-9]{40})", "critical"),
    "huggingface_token": (r"hf_[A-Za-z0-9]{34,}", "critical"),
    "replicate_token": (r"r8_[A-Za-z0-9]{40}", "high"),
    "mistral_key": (r"(?i)mistral[_\-\s]?(?:api[_\-\s]?)?key['\"\s:=]+([A-Za-z0-9]{32,})", "high"),
    "datadog_api_key": (r"(?i)datadog[_\-\s]?(?:api[_\-\s]?)?key['\"\s:=]+([A-Za-z0-9]{32,40})", "high"),
    "datadog_app_key": (r"(?i)datadog[_\-\s]?app[_\-\s]?key['\"\s:=]+([A-Za-z0-9]{40})", "high"),
    "newrelic_license": (r"(?i)new[_\-\s]?relic[_\-\s]?(?:license[_\-\s]?)?key['\"\s:=]+([A-Za-z0-9]{40})", "high"),
    "newrelic_insights": (r"NRIQ-[A-Za-z0-9\-_]{22}", "high"),
    "sentry_dsn": (r"https://[0-9a-f]{32}@o[0-9]+\.ingest\.sentry\.io/[0-9]+", "high"),
    "pagerduty_key": (r"(?i)pagerduty[_\-\s]?(?:api[_\-\s]?)?(?:key|token)['\"\s:=]+([A-Za-z0-9+/=_\-]{20,})", "high"),
    "npm_token": (r"(?i)npm[_\-\s]?(?:auth[_\-\s]?)?token['\"\s:=]+(npm_[A-Za-z0-9]{36})", "critical"),
    "pypi_token": (r"pypi-[A-Za-z0-9\-_]{50,}", "critical"),
    "nuget_key": (r"oy2[A-Za-z0-9]{43}", "high"),
    "rubygems_key": (r"rubygems_[A-Za-z0-9]{48}", "high"),
    "shopify_secret": (r"shpss_[A-Za-z0-9]{32}", "critical"),
    "shopify_access": (r"shpat_[A-Za-z0-9]{32}", "critical"),
    "shopify_partner": (r"shppa_[A-Za-z0-9]{32}", "high"),
    "woocommerce_key": (r"ck_[A-Za-z0-9]{40}", "high"),
    "woocommerce_secret": (r"cs_[A-Za-z0-9]{40}", "high"),
    "bigcommerce_token": (r"(?i)bigcommerce[_\-\s]?(?:api[_\-\s]?)?(?:key|token)['\"\s:=]+([A-Za-z0-9]{32,})", "high"),
    "auth0_secret": (r"(?i)auth0[_\-\s]?(?:client[_\-\s]?)?secret['\"\s:=]+([A-Za-z0-9_\-]{40,})", "critical"),
    "okta_token": (r"(?i)okta[_\-\s]?(?:api[_\-\s]?)?token['\"\s:=]+([A-Za-z0-9_\-]{40,})", "critical"),
    "firebase_key": (r"(?i)firebase[_\-\s]?(?:api[_\-\s]?)?key['\"\s:=]+(AIza[A-Za-z0-9\-_]{35})", "critical"),
    "firebase_config": (r"firebaseapp\.com", "medium"),
    "clerk_key": (r"(?:pk|sk)_(?:test|live)_[A-Za-z0-9]{40,}", "critical"),
    "jwt_token": (r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+", "medium"),
    "oauth_client_secret": (r"(?i)client[_\-\s]?secret['\"\s:=]+([A-Za-z0-9\-_]{20,})", "high"),
    "stripe_live_key": (r"sk_live_[A-Za-z0-9]{24,}", "critical"),
    "stripe_test_key": (r"sk_test_[A-Za-z0-9]{24,}", "high"),
    "stripe_restricted": (r"rk_(?:live|test)_[A-Za-z0-9]{24,}", "critical"),
    "stripe_publishable": (r"pk_(?:live|test)_[A-Za-z0-9]{24,}", "medium"),
    "razorpay_key": (r"rzp_(?:live|test)_[A-Za-z0-9]{14,}", "critical"),
    "paypal_client_id": (r"(?i)paypal[_\-\s]?client[_\-\s]?(?:id|secret)['\"\s:=]+([A-Za-z0-9\-_]{20,})", "high"),
    "braintree_token": (r"access_token\$production\$[A-Za-z0-9]{16}\$[A-Za-z0-9]{32}", "critical"),
    "github_pat_classic": (r"ghp_[A-Za-z0-9]{36}", "critical"),
    "github_pat_fine": (r"github_pat_[A-Za-z0-9_]{82}", "critical"),
    "github_oauth": (r"gho_[A-Za-z0-9]{36}", "critical"),
    "github_app_token": (r"(?:ghu|ghs)_[A-Za-z0-9]{36}", "critical"),
    "gitlab_token": (r"glpat-[A-Za-z0-9\-_]{20}", "critical"),
    "gitlab_runner": (r"GR1348941[A-Za-z0-9\-_]{20}", "high"),
    "bitbucket_app_pass": (r"(?i)bitbucket[_\-\s]?(?:app[_\-\s]?)?(?:password|token)['\"\s:=]+([A-Za-z0-9+/=]{20,})", "high"),
    "sendgrid_key": (r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}", "critical"),
    "mailgun_key": (r"key-[A-Za-z0-9]{32}", "critical"),
    "mailchimp_key": (r"[0-9a-f]{32}-us[0-9]{1,2}", "high"),
    "postmark_token": (r"(?i)postmark[_\-\s]?(?:api[_\-\s]?)?token['\"\s:=]+([A-Za-z0-9\-]{36})", "high"),
    "sparkpost_key": (r"(?i)sparkpost[_\-\s]?(?:api[_\-\s]?)?key['\"\s:=]+([A-Za-z0-9]{40})", "high"),
    "twilio_sid": (r"AC[a-z0-9]{32}", "critical"),
    "twilio_auth_token": (r"(?i)twilio[_\-\s]?auth[_\-\s]?token['\"\s:=]+([A-Za-z0-9]{32})", "critical"),
    "slack_webhook": (r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+", "critical"),
    "slack_bot_token": (r"xox[baprs]-[A-Za-z0-9\-]{10,}", "critical"),
    "slack_user_token": (r"xoxp-[A-Za-z0-9\-]{10,}", "critical"),
    "discord_bot_token": (r"[MN][A-Za-z0-9\-_]{23}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27}", "critical"),
    "discord_webhook": (r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+", "high"),
    "telegram_bot_token": (r"[0-9]{8,10}:[A-Za-z0-9_\-]{35}", "high"),
    "notion_token": (r"secret_[A-Za-z0-9]{43}", "critical"),
    "notion_int_token": (r"ntn_[A-Za-z0-9]{43}", "critical"),
    "algolia_admin_key": (r"(?i)algolia[_\-\s]?admin[_\-\s]?(?:api[_\-\s]?)?key['\"\s:=]+([A-Za-z0-9]{32})", "critical"),
    "algolia_app_id": (r"[A-Z0-9]{10}", "low"),
    "mapbox_token": (r"pk\.[A-Za-z0-9]{60,}\.[A-Za-z0-9]{20,}", "high"),
    "mapbox_secret_token": (r"sk\.[A-Za-z0-9]{60,}\.[A-Za-z0-9]{20,}", "critical"),
    "airtable_key": (r"(?:key|pat)[A-Za-z0-9]{14,17}\.[A-Za-z0-9]{64}", "critical"),
    "zendesk_token": (r"(?i)zendesk[_\-\s]?(?:api[_\-\s]?)?token['\"\s:=]+([A-Za-z0-9/+]{40,})", "high"),
    "intercom_token": (r"dG9rOm[A-Za-z0-9+/=]{40,}", "high"),
    "jenkins_token": (r"(?i)jenkins[_\-\s]?(?:api[_\-\s]?)?token['\"\s:=]+([A-Za-z0-9]{32,})", "critical"),
    "circleci_token": (r"(?i)circle[_\-\s]?(?:ci[_\-\s]?)?token['\"\s:=]+([A-Za-z0-9]{40})", "high"),
    "vercel_token": (r"(?i)vercel[_\-\s]?(?:token|secret)['\"\s:=]+([A-Za-z0-9_\-]{24,})", "high"),
    "netlify_token": (r"(?i)netlify[_\-\s]?(?:token|secret)['\"\s:=]+([A-Za-z0-9_\-]{40,})", "high"),
    "travis_token": (r"(?i)travis[_\-\s]?(?:ci[_\-\s]?)?token['\"\s:=]+([A-Za-z0-9_\-]{22,})", "high"),
    "heroku_api_key": (r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "high"),
    "mongodb_uri": (r"mongodb(?:\+srv)?://[^'\"\s<>]+:[^'\"\s<>]+@[^'\"\s<>]+", "critical"),
    "postgres_uri": (r"postgres(?:ql)?://[^'\"\s<>]+:[^'\"\s<>]+@[^'\"\s<>]+", "critical"),
    "mysql_uri": (r"mysql://[^'\"\s<>]+:[^'\"\s<>]+@[^'\"\s<>]+", "critical"),
    "redis_uri": (r"redis://(?:[^@]+@)?[^'\"\s<>]+:[0-9]+", "high"),
    "redis_auth_uri": (r"redis://:[^@'\"\s]+@[^'\"\s<>]+", "critical"),
    "elasticsearch_uri": (r"https?://[^'\"\s<>]+:[^'\"\s<>]+@[^'\"\s<>]+:9200", "high"),
    "planetscale_url": (r"mysql://[^'\"\s]+\.pscale\.dev[^'\"\s]*", "critical"),
    "private_key_header": (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----", "critical"),
    "certificate_header": (r"-----BEGIN CERTIFICATE-----", "medium"),
    "ssh_dsa_key": (r"-----BEGIN DSA PRIVATE KEY-----", "critical"),
    "ssh_ec_key": (r"-----BEGIN EC PRIVATE KEY-----", "critical"),
    "pkcs8_key": (r"-----BEGIN ENCRYPTED PRIVATE KEY-----", "critical"),
    "password_in_code": (r"(?i)(?:password|passwd|pwd)['\"\s]*[:=]['\"\s]*([^'\"\s]{8,})", "high"),
    "username_password": (r"(?i)(?:username|user)['\"\s]*[:=]['\"\s]*[^'\"\s]+['\"\s]*,?['\"\s]*(?:password|pwd)['\"\s]*[:=]['\"\s]*[^'\"\s]+", "high"),
    "default_credentials": (r"(?i)(?:admin|administrator|root)['\"\s]*[:=]['\"\s]*(?:admin|password|123456|root|toor|default)", "critical"),
    "basic_auth_url": (r"https?://[^'\"\s<>]+:[^'\"\s<>@]+@[^'\"\s<>]+", "high"),
    "dotenv_reference": (r"process\.env\.[A-Z_]{5,}(?:KEY|SECRET|TOKEN|PASSWORD|PWD|PASS)", "medium"),
    "admin_panel_route": (r"""['"`](/admin(?:/[^'"`\s]*)?|/wp-admin(?:/[^'"`\s]*)?|/dashboard(?:/[^'"`\s]*)?)['"`]""", "high"),
    "debug_route": (r"""['"`](/debug(?:/[^'"`\s]*)?|/test(?:/[^'"`\s]*)?|/dev(?:/[^'"`\s]*)?)['"`]""", "medium"),
    "internal_api_route": (r"""['"`](/(?:internal|private|hidden|secret)(?:/[^'"`\s]*)?)['"`]""", "high"),
    "graphql_endpoint": (r"""['"`](/graphql(?:/[^'"`\s]*)?)['"`]""", "medium"),
    "swagger_endpoint": (r"""['"`](/(?:swagger|openapi|api-docs)(?:[^'"`\s]*)?)['"`]""", "medium"),
    "staging_url": (r"https?://(?:staging|dev|test|uat|qa)\.[^'\"\s<>]+", "medium"),
    "localhost_reference": (r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0):[0-9]+", "medium"),
    "env_variable_exposure": (r"""(?:window\.|globalThis\.)?(?:ENV|env|config|CONFIG)\s*=\s*\{[^}]{20,}""", "high"),
    "secret_env_var": (r"""(?:SECRET|PRIVATE|SENSITIVE)[_A-Z]*\s*[:=]\s*['"][^'"]{8,}['"]""", "high"),
    "config_object": (r"""(?i)(?:apiKey|secretKey|privateKey|accessToken)\s*:\s*['"][A-Za-z0-9\-_./+=]{10,}['"]""", "high"),
    "sourcemap_comment": (r"//[#@] sourceMappingURL=([^\s]+\.map)", "medium"),
    "sourcemap_header": (r"X-SourceMap:\s*([^\s]+\.map)", "medium"),
    "s3_bucket_url": (r"https?://[a-z0-9.\-]+\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com", "high"),
    "gcs_bucket_url": (r"https?://storage\.googleapis\.com/[a-z0-9.\-]+", "high"),
    "azure_blob_url": (r"https?://[a-z0-9]+\.blob\.core\.windows\.net", "high"),
    "do_spaces_url": (r"https?://[a-z0-9.\-]+\.digitaloceanspaces\.com", "high"),
    "r2_bucket_url": (r"https?://[a-z0-9]+\.r2\.cloudflarestorage\.com", "high"),
    "clevrtap_id": (r"""['"`]([A-Z0-9]{3}-[A-Z0-9]{3}-[A-Z0-9]{4})['"`]""", "low"),
    "mixpanel_token": (r"""['"`]([a-f0-9]{32})['"`]""", "low"),
    "amplitude_key": (r"""['"`]([a-f0-9]{32})['"`]""", "low"),
    "segment_write_key": (r"""['"`]([A-Za-z0-9]{22,})['"`]""", "low"),
    "hotjar_id": (r"""hjid\s*:\s*([0-9]{5,})""", "low"),
    "ga4_measurement_id": (r"G-[A-Z0-9]{10,}", "low"),
    "google_tag_manager": (r"GTM-[A-Z0-9]{6,}", "low"),
    "facebook_pixel": (r"fbq\('init',\s*'([0-9]{15,})'", "low"),
}

COMPILED_JS_SECRET_PATTERNS = {
    name: (re.compile(pattern), severity)
    for name, (pattern, severity) in JS_SECRET_PATTERNS.items()
}

ENDPOINT_TYPES = {
    "js_endpoints.txt": {"graphql_endpoint", "swagger_endpoint"},
    "js_admin_routes.txt": {"admin_panel_route", "debug_route", "internal_api_route"},
    "js_cloud_storage.txt": {"s3_bucket_url", "gcs_bucket_url", "azure_blob_url", "do_spaces_url", "r2_bucket_url"},
}


def _match_value(match: re.Match) -> str:
    for group in match.groups():
        if group:
            return group
    return match.group(0)


def scan_text_for_secrets(text: str, source: str = "", verify: bool = None) -> list[dict]:
    findings = []
    verify_enabled = config.verify_secrets if verify is None else verify
    seen = set()

    for name, (regex, severity) in COMPILED_JS_SECRET_PATTERNS.items():
        for match in regex.finditer(text or ""):
            value = _match_value(match).strip()
            value_hash = secret_hash(value)
            key = (name, value_hash)
            if key in seen:
                continue
            seen.add(key)
            verification = verify_secret(name, value, source) if verify_enabled else verify_secret(name, value, source)
            findings.append({
                "type": name,
                "severity": severity,
                "value_hash": value_hash,
                "value_preview": secret_preview(value),
                "source": source,
                "verified": verification.get("verified", False),
                "confidence": verification.get("confidence", "possible"),
                "reason": verification.get("reason", ""),
                "action": verification.get("action", "review"),
                "match_start": match.start(),
            })
    return findings


def _fetch_url(url: str) -> str:
    if config.dry_run:
        logger.info(f"[DRY-RUN] fetch JS {url}")
        return ""
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code < 400:
            return resp.text
    except requests.RequestException as exc:
        logger.debug(f"JS fetch failed for {url}: {exc}")
    return ""


def scan_js_url(url: str) -> list[dict]:
    return scan_text_for_secrets(_fetch_url(url), url)


def scan_js_sources(js_urls: list[str], outdir: str, extra_files: list[str] = None) -> list[dict]:
    findings = []
    extra_files = extra_files or []

    with ThreadPoolExecutor(max_workers=max(1, config.threads)) as pool:
        futures = {pool.submit(scan_js_url, url): url for url in js_urls}
        for fut in as_completed(futures):
            try:
                findings.extend(fut.result())
            except Exception as exc:
                logger.warning(f"JS scan task failed: {exc}")

    for path in extra_files:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                findings.extend(scan_text_for_secrets(f.read(), path))
        except OSError as exc:
            logger.warning(f"Could not scan {path}: {exc}")

    deduped = {}
    for finding in findings:
        deduped[(finding["type"], finding["value_hash"])] = finding
    return list(deduped.values())


def write_js_findings(findings: list[dict], outdir: str) -> None:
    os.makedirs(outdir, exist_ok=True)
    for severity in ("critical", "high", "medium", "low"):
        rows = [
            f"{f['type']} [{f['confidence']}] {f['value_preview']} sha256={f['value_hash']} source={f['source']}"
            for f in findings if f["severity"] == severity
        ]
        atomic_write(os.path.join(outdir, f"js_secrets_{severity}.txt"), rows)

    verified = [
        f"{f['type']} {f['value_preview']} sha256={f['value_hash']} source={f['source']}"
        for f in findings if f.get("verified")
    ]
    atomic_write(os.path.join(outdir, "js_secrets_verified.txt"), verified)

    for filename, types in ENDPOINT_TYPES.items():
        rows = [
            f"{f['type']} {f['value_preview']} sha256={f['value_hash']} source={f['source']}"
            for f in findings if f["type"] in types
        ]
        atomic_write(os.path.join(outdir, filename), rows)

    atomic_write(
        os.path.join(outdir, "js_secrets.txt"),
        [f"{f['severity']} {f['type']} {f['value_preview']} sha256={f['value_hash']} source={f['source']}" for f in findings],
    )
    if not config.dry_run:
        with open(os.path.join(outdir, "js_secrets_all.json"), "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2, sort_keys=True)


def discover_and_fetch_sourcemaps(js_urls: list, outdir: str) -> list:
    sources = []
    maps_dir = os.path.join(outdir, "sourcemaps")
    if not config.dry_run:
        os.makedirs(maps_dir, exist_ok=True)

    for url in js_urls:
        map_urls = set()
        try:
            if config.dry_run:
                logger.info(f"[DRY-RUN] discover sourcemap {url}")
                continue
            resp = requests.get(url, timeout=5)
            header_map = resp.headers.get("X-SourceMap") or resp.headers.get("SourceMap")
            if header_map:
                map_urls.add(urljoin(url, header_map))
            tail = "\n".join(resp.text.splitlines()[-5:])
            for match in re.finditer(r"//[#@]\s*sourceMappingURL=([^\s]+\.map)", tail):
                map_urls.add(urljoin(url, match.group(1)))
        except requests.RequestException as exc:
            logger.debug(f"Sourcemap lookup failed for {url}: {exc}")
            continue

        for map_url in map_urls:
            try:
                map_resp = requests.get(map_url, timeout=5)
                if map_resp.status_code >= 400:
                    continue
                parsed = urlparse(map_url)
                name = os.path.basename(parsed.path) or (secret_hash(map_url) + ".map")
                map_path = os.path.join(maps_dir, name)
                with open(map_path, "w", encoding="utf-8") as f:
                    f.write(map_resp.text)
                data = map_resp.json()
                base = map_url.rsplit("/", 1)[0] + "/"
                for source in data.get("sources", []):
                    sources.append(urljoin(base, source))
            except (requests.RequestException, ValueError, OSError) as exc:
                logger.debug(f"Sourcemap fetch failed for {map_url}: {exc}")

    unique_sources = sorted(dict.fromkeys(sources))
    atomic_write(os.path.join(outdir, "sourcemap_sources.txt"), unique_sources)
    return unique_sources


def is_js_url(value: str) -> bool:
    return ".js" in value.split("?", 1)[0].lower()


def collect_js_urls_from_file(path: str) -> list[str]:
    return [line for line in read_lines(path) if is_js_url(line)]
