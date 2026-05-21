"""Secret verification helpers for JavaScript reconnaissance."""

import hashlib
import math
from collections import Counter

import requests

from core import logger
from core.config import config

_CACHE = {}


def secret_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def secret_preview(value: str) -> str:
    if len(value) <= 8:
        return value[:2] + "..." if value else ""
    return value[:4] + "..." + value[-4:]


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _result(verified: bool, confidence: str, reason: str, action: str) -> dict:
    return {
        "verified": verified,
        "confidence": confidence,
        "reason": reason,
        "action": action,
    }


def _get(url: str, headers: dict = None) -> requests.Response:
    return requests.get(url, headers=headers or {}, timeout=5)


def verify_secret(secret_type: str, secret_value: str, context: str = "") -> dict:
    """
    Verify a secret using read-only checks when opt-in verification is enabled.

    Raw secret values are never logged. Mutating checks such as webhook sends are
    intentionally not performed by default.
    """
    key = (secret_type, secret_hash(secret_value))
    if key in _CACHE:
        return _CACHE[key]

    logger.debug(
        f"verify_secret type={secret_type} preview={secret_preview(secret_value)} "
        f"hash={key[1]} context={context}"
    )

    score = entropy(secret_value)
    if not config.verify_secrets:
        confidence = "likely" if score >= 4.5 else "possible"
        result = _result(False, confidence, f"pattern match; entropy={score:.2f}", "review")
        _CACHE[key] = result
        return result

    try:
        if secret_type.startswith("github_"):
            resp = _get("https://api.github.com/user", {"Authorization": f"Bearer {secret_value}"})
            if resp.status_code == 200:
                result = _result(True, "confirmed", "GitHub /user endpoint accepted token", "revoke immediately")
            elif resp.status_code in (401, 403):
                result = _result(False, "fp", "GitHub rejected token", "review")
            else:
                result = _result(False, "possible", f"GitHub returned HTTP {resp.status_code}", "review")
        elif secret_type.startswith("stripe_") and secret_value.startswith("sk_"):
            resp = _get("https://api.stripe.com/v1/charges?limit=1", {"Authorization": f"Bearer {secret_value}"})
            if resp.status_code == 200:
                result = _result(True, "confirmed", "Stripe read endpoint accepted key", "revoke immediately")
            elif resp.status_code == 401:
                result = _result(False, "fp", "Stripe rejected key", "review")
            else:
                result = _result(False, "possible", f"Stripe returned HTTP {resp.status_code}", "review")
        elif secret_type == "sendgrid_key":
            resp = _get("https://api.sendgrid.com/v3/user/profile", {"Authorization": f"Bearer {secret_value}"})
            if resp.status_code == 200:
                result = _result(True, "confirmed", "SendGrid profile endpoint accepted key", "revoke immediately")
            elif resp.status_code in (401, 403):
                result = _result(False, "fp", "SendGrid rejected key", "review")
            else:
                result = _result(False, "possible", f"SendGrid returned HTTP {resp.status_code}", "review")
        elif secret_type.startswith("slack_") and "webhook" not in secret_type:
            resp = _get("https://slack.com/api/auth.test", {"Authorization": f"Bearer {secret_value}"})
            data = {}
            try:
                data = resp.json()
            except ValueError:
                pass
            if resp.status_code == 200 and data.get("ok") is True:
                result = _result(True, "confirmed", "Slack auth.test accepted token", "revoke immediately")
            elif resp.status_code == 200 and data.get("ok") is False:
                result = _result(False, "fp", "Slack auth.test rejected token", "review")
            else:
                result = _result(False, "possible", f"Slack returned HTTP {resp.status_code}", "review")
        elif secret_type == "slack_webhook":
            result = _result(False, "possible", "active webhook verification disabled to avoid mutating calls", "review")
        else:
            confidence = "likely" if score >= 4.5 else "possible"
            result = _result(False, confidence, f"pattern match; entropy={score:.2f}", "review")
    except requests.RequestException as exc:
        result = _result(False, "possible", f"verification request failed: {exc}", "review")

    _CACHE[key] = result
    return result
