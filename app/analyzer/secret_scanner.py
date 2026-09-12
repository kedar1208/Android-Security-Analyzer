"""
Hardcoded secret detection.

Scans two sources inside the APK:
  1. Resource strings (res/values/strings.xml and friends, via
     androguard's resource parser) -- catches secrets checked in as
     plain <string> resources.
  2. Decompiled DEX constant-pool strings -- catches secrets that are
     hardcoded directly in Java/Kotlin source (e.g. `String key =
     "AIza..."`) rather than externalised to resources.

Detection combines:
  - Curated regex signatures for well-known key/token formats.
  - Generic KEY=VALUE / assignment patterns with sensitive variable
    names (password, secret, token, apikey, ...).
  - Shannon-entropy screening for long base64/hex blobs that don't
    match a known signature but are statistically "key-like", to
    catch novel/unlabelled secrets.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass

from .risk_engine import Finding

# (rule name, compiled regex, severity)
SIGNATURES: list[tuple[str, re.Pattern, str]] = [
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}"), "Critical"),
    ("AWS Secret Access Key (heuristic)",
     re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"), "Critical"),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "High"),
    ("Firebase Cloud Messaging Key",
     re.compile(r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"), "High"),
    ("Firebase Database URL",
     re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"), "Medium"),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}"), "High"),
    ("Slack Webhook",
     re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"), "Medium"),
    ("Stripe Live Secret Key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "Critical"),
    ("Stripe Publishable Key", re.compile(r"pk_live_[0-9a-zA-Z]{24,}"), "Low"),
    ("GitHub Personal Access Token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), "Critical"),
    ("Generic Bearer Token",
     re.compile(r"(?i)bearer\s+[a-z0-9\-_\.]{20,}"), "Medium"),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "Medium"),
    ("PEM Private Key Block",
     re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----"), "Critical"),
    ("Basic Auth in URL", re.compile(r"[a-zA-Z]{2,8}://[^/\s:]+:[^/\s@]+@[^\s'\"]+"), "High"),
    ("Generic API Key Assignment",
     re.compile(r"(?i)\b(api[_-]?key|apikey|secret|access[_-]?token)\b\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"),
     "Medium"),
    ("Hardcoded Password Assignment",
     re.compile(r"(?i)\bpassword\b\s*[:=]\s*['\"][^'\"]{4,}['\"]"), "High"),
    ("Generic Encryption Key/IV",
     re.compile(r"(?i)\b(secret[_-]?key|encryption[_-]?key|\biv\b)\s*[:=]\s*['\"][A-Za-z0-9+/=]{8,}['\"]"), "Medium"),
]

# Substrings that, if found, strongly suggest a match is placeholder/
# sample/test data rather than a real leaked secret -- used to cut
# noise, not to hide real findings.
NOISE_HINTS = (
    "example", "sample", "test", "dummy", "changeme", "your_api_key",
    "xxxxxxxx", "placeholder", "TODO", "0000000000",
)

MIN_ENTROPY_LEN = 24
ENTROPY_THRESHOLD = 4.3  # bits/char; random base64/hex sits ~4.5-6.0


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    length = len(s)
    return -sum((n / length) * math.log2(n / length) for n in freq.values())


_ENTROPY_CANDIDATE = re.compile(r"['\"]([A-Za-z0-9+/_=-]{24,})['\"]")


def _looks_like_noise(text: str) -> bool:
    low = text.lower()
    return any(h in low for h in NOISE_HINTS)


@dataclass
class RawHit:
    rule: str
    severity: str
    matched_text: str
    source: str


def _scan_text_blob(text: str, source: str) -> list[RawHit]:
    hits: list[RawHit] = []
    if not text:
        return hits

    for rule, pattern, severity in SIGNATURES:
        for m in pattern.finditer(text):
            snippet = m.group(0)
            if _looks_like_noise(snippet):
                continue
            hits.append(RawHit(rule, severity, snippet, source))

    for m in _ENTROPY_CANDIDATE.finditer(text):
        candidate = m.group(1)
        if len(candidate) < MIN_ENTROPY_LEN or _looks_like_noise(candidate):
            continue
        ent = _shannon_entropy(candidate)
        if ent >= ENTROPY_THRESHOLD:
            hits.append(RawHit(
                "High-entropy string (possible unlabelled secret)",
                "Low", candidate, source,
            ))
    return hits


def _dedupe(hits: list[RawHit]) -> list[RawHit]:
    seen = set()
    out = []
    for h in hits:
        key = (h.rule, h.matched_text)
        if key in seen:
            continue
        seen.add(key)
        out.append(h)
    return out


def scan_secrets(apk, dx=None, max_hits: int = 200) -> dict:
    """
    apk: androguard APK object (for resource strings.xml values)
    dx:  androguard Analysis object (optional; for DEX constant-pool
         strings). If not supplied, only resource strings are scanned.
    """
    hits: list[RawHit] = []

    # -- 1. resource strings -------------------------------------------------
    try:
        for res_string in _iter_resource_strings(apk):
            hits.extend(_scan_text_blob(res_string, "res/values/strings.xml"))
    except Exception:
        pass  # malformed/obfuscated resources shouldn't crash the pipeline

    # -- 2. DEX constant pool -------------------------------------------------
    if dx is not None:
        try:
            for s in dx.get_strings():
                value = s.get_value() if hasattr(s, "get_value") else str(s)
                if value and len(value) >= 6:
                    hits.extend(_scan_text_blob(value, "DEX constant string pool"))
        except Exception:
            pass

    hits = _dedupe(hits)[:max_hits]

    findings: list[Finding] = []
    for h in hits:
        redacted = h.matched_text if len(h.matched_text) <= 12 else (
            h.matched_text[:6] + "…" + h.matched_text[-4:]
        )
        findings.append(Finding(
            category="secrets",
            title=f"{h.rule} detected",
            severity=h.severity,
            description=f"A string matching the '{h.rule}' pattern was found "
                         f"in {h.source}.",
            evidence=f"Source: {h.source} | Value (redacted): {redacted}",
            recommendation="Remove the hardcoded credential; load secrets from "
                            "a secure backend / Android Keystore / encrypted "
                            "remote config at runtime instead of shipping them "
                            "inside the APK, and rotate the exposed credential "
                            "immediately.",
            cwe="CWE-798",
        ))

    return {
        "findings": findings,
        "total_candidates": len(hits),
    }


def _iter_resource_strings(apk):
    """
    Yields decoded string values from the APK's resource table
    (all locales/configs, res_id-agnostic) using androguard's
    ARSCParser if resources.arsc is present.
    """
    try:
        ares = apk.get_android_resources()
    except Exception:
        ares = None
    if ares is None:
        return
    try:
        for package_name in ares.get_packages_names():
            for locale in ares.get_locales(package_name):
                try:
                    string_res = ares.get_string_resources(package_name, locale=locale)
                except Exception:
                    continue
                # get_string_resources returns raw XML bytes/str in most
                # androguard versions; fall back to str() defensively.
                text = string_res if isinstance(string_res, str) else \
                    string_res.decode("utf-8", errors="ignore") if isinstance(string_res, (bytes, bytearray)) else str(string_res)
                yield text
    except Exception:
        return
