"""
Network Security Configuration (res/xml/network_security_config.xml)
analysis.

The manifest <application> tag points at this file via
android:networkSecurityConfig="@xml/<name>". The file itself ships
inside the APK as compiled binary XML (AXML), so it must be located
by resource name and re-decoded with androguard's AXMLPrinter before
we can inspect it with a normal XML parser.
"""
from __future__ import annotations

from lxml import etree

from .risk_engine import Finding

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _get_axml_printer():
    try:
        from androguard.core.axml import AXMLPrinter
        return AXMLPrinter
    except ImportError:  # pragma: no cover
        from androguard.core.bytecodes.axml import AXMLPrinter
        return AXMLPrinter


def _find_nsc_path(apk, nsc_ref: str) -> str | None:
    """nsc_ref looks like '@xml/network_security_config'."""
    if not nsc_ref or "/" not in nsc_ref:
        return None
    short_name = nsc_ref.split("/")[-1]
    candidates = [
        f for f in apk.get_files()
        if f.lower().endswith(f"{short_name}.xml".lower()) and "xml" in f.lower()
    ]
    # Prefer the plain res/xml/ variant over qualified ones (res/xml-v24/...)
    candidates.sort(key=lambda p: (0 if p.lower().startswith("res/xml/") else 1, len(p)))
    return candidates[0] if candidates else None


def analyze_nsc(apk, manifest_meta: dict, nsc_ref: str | None) -> dict:
    findings: list[Finding] = []

    if not nsc_ref:
        # already flagged as a Low-severity finding by manifest_analyzer;
        # nothing further to inspect here.
        return {"findings": findings, "present": False, "raw_xml": None}

    path = _find_nsc_path(apk, nsc_ref)
    if not path:
        findings.append(Finding(
            category="nsc",
            title="networkSecurityConfig referenced but file not found",
            severity="Low",
            description=f"Manifest references '{nsc_ref}' but no matching "
                         "file could be located in the APK's res/xml "
                         "directory (possibly due to resource shrinking or "
                         "an unusual qualifier).",
        ))
        return {"findings": findings, "present": False, "raw_xml": None}

    try:
        raw = apk.get_file(path)
        AXMLPrinter = _get_axml_printer()
        xml_bytes = AXMLPrinter(raw).get_buff()
        root = etree.fromstring(xml_bytes)
    except Exception as exc:  # pragma: no cover
        findings.append(Finding(
            category="nsc",
            title="Could not decode Network Security Config",
            severity="Info",
            description=f"Found {path} but failed to decode it: {exc}",
        ))
        return {"findings": findings, "present": True, "raw_xml": None}

    def cleartext_flag(elem):
        v = elem.get("cleartextTrafficPermitted")
        return None if v is None else v.strip().lower() == "true"

    # -- base-config --------------------------------------------------------
    base_config = root.find("base-config")
    if base_config is not None:
        ct = cleartext_flag(base_config)
        if ct:
            findings.append(Finding(
                category="nsc",
                title="NSC base-config permits cleartext traffic app-wide",
                severity="High",
                description="<base-config cleartextTrafficPermitted=\"true\"> "
                             "allows unencrypted HTTP for every domain not "
                             "explicitly overridden by a domain-config.",
                evidence=etree.tostring(base_config, pretty_print=True).decode(errors="ignore")[:500],
                recommendation="Set cleartextTrafficPermitted=\"false\" on the "
                                "base-config and only allow cleartext for "
                                "specific, justified domains via domain-config.",
                cwe="CWE-319",
            ))
        _check_trust_anchors(base_config, findings, scope="base-config")

    # -- domain-config(s) -----------------------------------------------------
    domain_configs = root.findall("domain-config")
    cleartext_domains = []
    pinned_domains = []
    for dc in domain_configs:
        domains = [d.text.strip() for d in dc.findall("domain") if d.text]
        ct = cleartext_flag(dc)
        if ct:
            cleartext_domains.extend(domains)
        if dc.find("pin-set") is not None:
            pinned_domains.extend(domains)
        _check_trust_anchors(dc, findings, scope=f"domain-config ({', '.join(domains) or 'unnamed'})")

    if cleartext_domains:
        findings.append(Finding(
            category="nsc",
            title="Cleartext traffic permitted for specific domain(s)",
            severity="Medium",
            description="The following domains allow plaintext HTTP per "
                         "domain-config overrides: " + ", ".join(cleartext_domains),
            recommendation="Confirm these domains genuinely require HTTP "
                            "(e.g. legacy internal services) and are not "
                            "carrying sensitive data; migrate to HTTPS where "
                            "possible.",
            cwe="CWE-319",
        ))

    if pinned_domains:
        findings.append(Finding(
            category="nsc",
            title="Certificate pinning configured",
            severity="Info",
            description="pin-set entries were found for: " + ", ".join(pinned_domains) +
                         ". This is a positive control that mitigates "
                         "CA-compromise and some MITM attacks.",
        ))

    # -- debug-overrides ------------------------------------------------------
    debug_overrides = root.find("debug-overrides")
    if debug_overrides is not None:
        findings.append(Finding(
            category="nsc",
            title="debug-overrides block present in shipped APK",
            severity="Medium",
            description="A <debug-overrides> element (typically used to trust "
                         "a debug/proxy CA during development, e.g. Charles/"
                         "Burp) is present in the analyzed APK. If this is a "
                         "release build, it should not ship with debug trust "
                         "overrides.",
            recommendation="Verify this APK is a debug build; if it is a "
                            "release build, remove debug-overrides from the "
                            "release build variant.",
            cwe="CWE-489",
        ))

    return {
        "findings": findings,
        "present": True,
        "path": path,
        "raw_xml": xml_bytes.decode("utf-8", errors="ignore") if isinstance(xml_bytes, (bytes, bytearray)) else xml_bytes,
    }


def _check_trust_anchors(config_elem, findings: list[Finding], scope: str):
    trust_anchors = config_elem.find("trust-anchors")
    if trust_anchors is None:
        return
    for certs in trust_anchors.findall("certificates"):
        src = certs.get("src", "")
        if src == "user":
            findings.append(Finding(
                category="nsc",
                title=f"Trust anchor accepts user-installed CAs ({scope})",
                severity="High",
                description=f"In {scope}, <certificates src=\"user\"/> means "
                             "the app trusts CA certificates a user (or "
                             "attacker with device access) has manually "
                             "installed -- a common technique to MITM HTTPS "
                             "traffic with tools like Burp/mitmproxy without "
                             "root.",
                recommendation="Restrict trust-anchors to src=\"system\" for "
                                "production configs; only allow src=\"user\" "
                                "inside a debug-overrides block.",
                cwe="CWE-295",
            ))
