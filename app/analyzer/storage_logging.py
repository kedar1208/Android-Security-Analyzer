"""
Static bytecode heuristics for insecure data handling:

  - Sensitive-looking data passed to android.util.Log (info leakage
    into logcat, readable by any app with READ_LOGS on old devices,
    or via adb).
  - WebView misconfiguration: JS enabled + addJavascriptInterface
    (classic remote code execution bridge), overly permissive file
    access flags.
  - Custom TrustManager / HostnameVerifier implementations that
    accept everything (SSL validation bypass).
  - Weak crypto: ECB mode cipher usage.
  - Likely-unencrypted local SQLite usage (no SQLCipher in the
    dependency graph).
  - Insecure file mode constants passed to openFileOutput /
    getSharedPreferences (MODE_WORLD_READABLE / MODE_WORLD_WRITEABLE).

This module works purely on androguard's Analysis object (`dx`) --
no APK unzip/re-parse needed if the caller already built it. All
per-method inspection is wrapped defensively since exact bytecode
instruction APIs vary slightly across androguard releases; failures
degrade to "skip that method" rather than crashing the pipeline.
"""
from __future__ import annotations

import re

from .risk_engine import Finding

SENSITIVE_KEYWORDS = re.compile(
    r"(?i)(password|passwd|pwd|token|secret|api[_-]?key|auth[_-]?header|"
    r"session[_-]?id|credit[_-]?card|cvv|ssn|ficha|access[_-]?token)"
)


def _method_text(method_analysis) -> str:
    """Best-effort flattening of a method's instructions to text for
    regex-based heuristics. Defensive against API differences across
    androguard versions."""
    try:
        m = method_analysis.get_method()
    except Exception:
        return ""
    lines = []
    try:
        for ins in m.get_instructions():
            try:
                name = ins.get_name()
            except Exception:
                name = ""
            try:
                output = ins.get_output()
            except TypeError:
                try:
                    output = ins.get_output(0)
                except Exception:
                    output = ""
            except Exception:
                output = ""
            lines.append(f"{name} {output}")
    except Exception:
        return ""
    return "\n".join(lines)


def _class_name(method_analysis) -> str:
    try:
        return method_analysis.get_method().get_class_name()
    except Exception:
        return "<unknown class>"


def _method_name(method_analysis) -> str:
    try:
        return method_analysis.get_method().get_name()
    except Exception:
        return "<unknown method>"


def analyze_storage_and_logging(dx) -> dict:
    findings: list[Finding] = []
    if dx is None:
        return {"findings": findings}

    seen_log_leak = set()
    webview_js = set()
    webview_bridge = set()
    webview_file_access = set()
    trust_all_managers = set()
    trust_all_hostname = set()
    ecb_usage = False
    uses_sqlite = False
    uses_sqlcipher = False
    insecure_file_mode = set()

    try:
        all_methods = list(dx.get_methods())
    except Exception:
        all_methods = []

    for ma in all_methods:
        try:
            text = _method_text(ma)
        except Exception:
            continue
        if not text:
            continue

        cls = _class_name(ma)
        mname = _method_name(ma)

        # -- Log leakage heuristic -------------------------------------
        if re.search(r"Landroid/util/Log;->(d|v|i|w)\(", text) and SENSITIVE_KEYWORDS.search(text):
            key = (cls, mname)
            if key not in seen_log_leak:
                seen_log_leak.add(key)

        # -- WebView ------------------------------------------------------
        if "setJavaScriptEnabled" in text:
            webview_js.add(cls)
        if "addJavascriptInterface" in text:
            webview_bridge.add(cls)
        if "setAllowFileAccessFromFileURLs" in text or "setAllowUniversalAccessFromFileURLs" in text:
            webview_file_access.add(cls)

        # -- TrustManager / HostnameVerifier bypass -----------------------
        if mname == "checkServerTrusted":
            instr_count = text.count("\n") + 1
            if instr_count <= 4 and "throw" not in text.lower():
                trust_all_managers.add(cls)
        if mname == "verify" and "HostnameVerifier" in "".join(_interfaces(ma)):
            if "const/4" in text and "return" in text and "throw" not in text.lower():
                trust_all_hostname.add(cls)

        # -- Weak crypto ---------------------------------------------------
        if re.search(r"(?i)/ECB/|Cipher;->getInstance.*ECB", text):
            ecb_usage = True

        # -- SQLite / SQLCipher --------------------------------------------
        if "openOrCreateDatabase" in text or "SQLiteOpenHelper" in cls:
            uses_sqlite = True
        if "net/sqlcipher" in text.lower() or "sqlcipher" in cls.lower():
            uses_sqlcipher = True

        # -- insecure file mode ---------------------------------------------
        if ("openFileOutput" in text or "getSharedPreferences" in text) and \
           re.search(r"const/4 v\d+, 0x[12]\b", text):
            insecure_file_mode.add(f"{cls}->{mname}")

    if seen_log_leak:
        examples = ", ".join(f"{c}#{m}" for c, m in list(seen_log_leak)[:8])
        findings.append(Finding(
            category="storage",
            title=f"Potentially sensitive data written to logcat ({len(seen_log_leak)} method(s))",
            severity="Medium",
            description="Methods call android.util.Log while also referencing "
                         "variable/field names suggestive of sensitive data "
                         "(password, token, secret, session, ...). This is a "
                         "heuristic string-adjacency match, not confirmed "
                         "dataflow -- manual review of each site is needed.",
            evidence=examples,
            recommendation="Remove or strip verbose/debug logging from release "
                            "builds (e.g. via ProGuard/R8 rules or a logging "
                            "wrapper disabled in release), and never log "
                            "credentials, tokens or PII.",
            cwe="CWE-532",
        ))

    if webview_bridge:
        combined_risk = webview_js & webview_bridge
        sev = "Critical" if combined_risk else "High"
        findings.append(Finding(
            category="storage",
            title="WebView exposes a JavaScript bridge (addJavascriptInterface)",
            severity=sev,
            description="addJavascriptInterface() found in: " + ", ".join(list(webview_bridge)[:8]) +
                         (". JavaScript is also explicitly enabled in the same "
                          "app, which combined with a JS bridge is a well-known "
                          "remote code execution vector if the WebView ever "
                          "loads untrusted/remote content."
                          if combined_risk else "."),
            recommendation="Avoid addJavascriptInterface with untrusted content; "
                            "if required, restrict to API 17+ with @JavascriptInterface "
                            "annotations only on the minimal necessary methods, "
                            "and only load fully trusted, HTTPS-pinned content.",
            cwe="CWE-749",
        ))
    elif webview_js:
        findings.append(Finding(
            category="storage",
            title="WebView JavaScript execution enabled",
            severity="Low",
            description="setJavaScriptEnabled(true) found in: " + ", ".join(list(webview_js)[:8]),
            recommendation="Only enable JS for WebViews that load trusted, "
                            "controlled content over HTTPS.",
            cwe="CWE-749",
        ))

    if webview_file_access:
        findings.append(Finding(
            category="storage",
            title="WebView allows broad local/universal file access",
            severity="High",
            description="setAllowFileAccessFromFileURLs/setAllowUniversalAccessFromFileURLs "
                         "found in: " + ", ".join(list(webview_file_access)[:8]) +
                         ". Combined with JS execution, this can allow a "
                         "malicious page to read local files.",
            recommendation="Disable these flags unless strictly required; "
                            "prefer loading local content via a scoped, "
                            "read-only WebViewAssetLoader.",
            cwe="CWE-200",
        ))

    if trust_all_managers:
        findings.append(Finding(
            category="storage",
            title="Custom TrustManager appears to accept all certificates",
            severity="Critical",
            description="checkServerTrusted() implementations with a trivially "
                         "short, non-throwing body were found in: " +
                         ", ".join(list(trust_all_managers)[:8]) +
                         ". This is the classic 'trust everything' SSL "
                         "validation bypass, making the app fully vulnerable "
                         "to MITM regardless of certificate validity.",
            recommendation="Never implement a no-op TrustManager in shipped "
                            "code, including for debugging -- gate any such "
                            "logic behind BuildConfig.DEBUG and strip it "
                            "from release builds, or better, avoid it "
                            "entirely and use a Network Security Config.",
            cwe="CWE-295",
        ))

    if trust_all_hostname:
        findings.append(Finding(
            category="storage",
            title="Custom HostnameVerifier appears to accept all hostnames",
            severity="Critical",
            description="verify() implementations that unconditionally return "
                         "true were found in: " + ", ".join(list(trust_all_hostname)[:8]) +
                         ". This disables hostname verification, allowing "
                         "MITM with any valid certificate for any domain.",
            recommendation="Remove custom HostnameVerifier overrides that "
                            "always return true; rely on the platform default "
                            "verifier.",
            cwe="CWE-295",
        ))

    if ecb_usage:
        findings.append(Finding(
            category="storage",
            title="ECB cipher mode usage detected",
            severity="Medium",
            description="A Cipher transformation string referencing ECB mode "
                         "was found in the DEX constant pool. ECB does not "
                         "use an IV and produces identical ciphertext blocks "
                         "for identical plaintext blocks, leaking structural "
                         "information.",
            recommendation="Use an authenticated mode such as AES/GCM/NoPadding "
                            "with a unique, random IV/nonce per encryption.",
            cwe="CWE-327",
        ))

    if uses_sqlite and not uses_sqlcipher:
        findings.append(Finding(
            category="storage",
            title="Local SQLite database likely stored unencrypted",
            severity="Low",
            description="The app uses SQLiteOpenHelper/openOrCreateDatabase "
                         "but no SQLCipher (or equivalent encrypted-database "
                         "library) classes were found in the DEX. On a "
                         "rooted/compromised device the database file is "
                         "readable in plaintext from app-private storage.",
            recommendation="If the database stores sensitive data, encrypt it "
                            "at rest (e.g. SQLCipher for Android, or Jetpack "
                            "Security's EncryptedFile for smaller stores).",
            cwe="CWE-311",
        ))

    if insecure_file_mode:
        findings.append(Finding(
            category="storage",
            title="Possible MODE_WORLD_READABLE/WRITEABLE file mode usage",
            severity="Medium",
            description="openFileOutput/getSharedPreferences calls adjacent to "
                         "an int constant of 1 or 2 (matching the deprecated "
                         "MODE_WORLD_READABLE / MODE_WORLD_WRITEABLE values) "
                         "were found in: " + ", ".join(list(insecure_file_mode)[:8]) +
                         ". This is a bytecode-proximity heuristic and should "
                         "be manually confirmed by reviewing the call site.",
            recommendation="Use MODE_PRIVATE (0) for all file/SharedPreferences "
                            "access; these world-readable/writeable modes have "
                            "been removed/blocked on modern Android for good "
                            "reason.",
            cwe="CWE-732",
        ))

    return {"findings": findings}


def _interfaces(method_analysis) -> list[str]:
    try:
        cls_analysis = method_analysis.get_method().get_class_name()
        return [cls_analysis]
    except Exception:
        return []
