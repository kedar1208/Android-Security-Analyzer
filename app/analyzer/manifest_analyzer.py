"""
APK / AndroidManifest.xml analysis.

Responsibilities:
  - Basic app metadata (package, versions, SDK levels)
  - Exported activity / service / receiver / provider detection
    (handles both explicit android:exported and the pre-API31
    implicit-export-via-intent-filter rule)
  - Dangerous top level flags: debuggable, allowBackup, testOnly,
    usesCleartextTraffic, missing networkSecurityConfig
  - Dangerous / custom permission review

Defensive design note: every Androguard getter here is wrapped with
_safe() rather than called directly. Some commercial/hardened APKs
have resource tables (multi-locale ARSC, non-standard configs) that
trip bugs deep inside Androguard's own decoder -- those failures are
parser limitations, not findings about the app, so a getter failure
degrades that one field to None instead of crashing the whole
manifest analysis stage.
"""
from __future__ import annotations

try:
    from androguard.core.apk import APK
except ImportError:  # pragma: no cover - older androguard versions
    from androguard.core.bytecodes.apk import APK

from .risk_engine import Finding

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _safe(fn, default=None):
    """Call a zero-arg getter, swallowing any exception it raises."""
    try:
        return fn()
    except Exception:
        return default


def _attr(elem, name: str, default=None):
    return elem.get(f"{{{ANDROID_NS}}}{name}", default)


def _to_int(value) -> int | None:
    """Androguard returns SDK versions as str on some versions/APKs
    (and occasionally None for malformed manifests) -- normalize to
    int (or None) so every downstream comparison/DB column is
    consistently typed."""
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except (ValueError, TypeError):
        return None


def _is_exported(elem) -> tuple[bool, str]:
    """
    Returns (exported, reason). Mirrors Android's own resolution logic:
      1. android:exported explicit value wins.
      2. Otherwise, exported iff the component declares an
         intent-filter (implicit default, still honoured by the OS
         at install time for apps regardless of targetSdk quirks
         introduced in API 31, where an explicit value becomes
         *mandatory* -- its absence with an intent-filter present is
         itself a manifest-merger error we still want to flag).
    """
    explicit = _attr(elem, "exported")
    if explicit is not None:
        return explicit.strip().lower() == "true", "explicit android:exported"
    has_intent_filter = elem.find("intent-filter") is not None
    if has_intent_filter:
        return True, "implicit (has intent-filter, no explicit android:exported)"
    return False, "implicit (no intent-filter)"


DANGEROUS_PERMISSION_PREFIXES = (
    "android.permission.READ_SMS", "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.CAMERA", "android.permission.RECORD_AUDIO",
    "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_PHONE_STATE", "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.MANAGE_EXTERNAL_STORAGE", "android.permission.BIND_ACCESSIBILITY_SERVICE",
)


def analyze_manifest(apk_path: str | None = None, apk=None) -> dict:
    """
    Accepts either a raw apk_path (self-contained use) or an
    already-instantiated androguard APK object (preferred when the
    orchestrator has already parsed the APK once, to avoid re-unzipping
    a potentially large file for every analyzer module).
    """
    if apk is None:
        apk = APK(apk_path)

    root = _safe(apk.get_android_manifest_xml)
    findings: list[Finding] = []

    meta = {
        "package": _safe(apk.get_package),
        "app_name": _safe(apk.get_app_name),
        "version_name": _safe(apk.get_androidversion_name),
        "version_code": _safe(apk.get_androidversion_code),
        "min_sdk": _to_int(_safe(apk.get_min_sdk_version)),
        "target_sdk": _to_int(_safe(apk.get_target_sdk_version)),
        "permissions": _safe(apk.get_permissions, default=[]) or [],
        "nsc_ref": None,
    }

    if root is None:
        findings.append(Finding(
            category="manifest",
            title="AndroidManifest.xml could not be decoded",
            severity="Info",
            description="Androguard failed to decode the binary manifest for "
                         "this APK. Manifest-based checks (exported "
                         "components, debuggable/allowBackup flags, "
                         "permissions) could not run; other analysis stages "
                         "were not affected.",
        ))
        return {
            "meta": meta,
            "findings": findings,
            "exported_components": {},
            "raw_root": None,
            "apk_obj": apk,
        }

    application = root.find("application")
    if application is not None:
        debuggable = (_attr(application, "debuggable") or "false").lower() == "true"
        allow_backup = (_attr(application, "allowBackup") or "true").lower() == "true"
        test_only = (_attr(application, "testOnly") or "false").lower() == "true"
        uses_cleartext = _attr(application, "usesCleartextTraffic")
        nsc_ref = _attr(application, "networkSecurityConfig")
        meta["nsc_ref"] = nsc_ref

        if debuggable:
            findings.append(Finding(
                category="manifest", title="Application is debuggable",
                severity="Critical",
                description="android:debuggable=\"true\" allows attaching a "
                             "debugger / JDWP to the running app in production, "
                             "enabling full runtime inspection and code injection.",
                evidence="<application android:debuggable=\"true\" .../>",
                recommendation="Remove android:debuggable or ensure the release "
                                "build variant strips it (it should never reach "
                                "a shipped build.apk).",
                cwe="CWE-489",
            ))

        if allow_backup:
            findings.append(Finding(
                category="manifest", title="android:allowBackup is enabled",
                severity="Medium",
                description="App data can be extracted via 'adb backup' (or "
                             "cloud backup) on unpatched/rooted devices, "
                             "potentially exposing databases, shared "
                             "preferences and files.",
                evidence="<application android:allowBackup=\"true\" .../>",
                recommendation="Set android:allowBackup=\"false\", or scope a "
                                "custom android:fullBackupContent rule that "
                                "excludes sensitive files.",
                cwe="CWE-530",
            ))

        if test_only:
            findings.append(Finding(
                category="manifest", title="android:testOnly is set",
                severity="Medium",
                description="testOnly builds accept looser install/security "
                             "constraints and should never be distributed.",
                evidence="<application android:testOnly=\"true\" .../>",
                recommendation="Remove testOnly from release manifests.",
                cwe="CWE-489",
            ))

        target_sdk = meta["target_sdk"] or 0
        if uses_cleartext is not None and uses_cleartext.lower() == "true":
            findings.append(Finding(
                category="manifest", title="Cleartext traffic explicitly permitted",
                severity="High",
                description="android:usesCleartextTraffic=\"true\" allows plain "
                             "HTTP (and other unencrypted) traffic app-wide, "
                             "enabling network eavesdropping / MITM.",
                evidence="<application android:usesCleartextTraffic=\"true\" .../>",
                recommendation="Set to \"false\" and use HTTPS exclusively, or "
                                "scope exceptions per-domain in a Network "
                                "Security Config.",
                cwe="CWE-319",
            ))
        elif uses_cleartext is None and target_sdk and target_sdk < 28:
            findings.append(Finding(
                category="manifest",
                title="Cleartext traffic allowed by default (legacy targetSdk)",
                severity="Medium",
                description=f"targetSdkVersion={target_sdk} is below 28, so the "
                             "platform default of usesCleartextTraffic=\"true\" "
                             "applies, permitting plain HTTP unless a Network "
                             "Security Config overrides it.",
                recommendation="Raise targetSdkVersion or set "
                                "usesCleartextTraffic=\"false\" explicitly.",
                cwe="CWE-319",
            ))

        if not nsc_ref:
            findings.append(Finding(
                category="manifest", title="No Network Security Config declared",
                severity="Low",
                description="No android:networkSecurityConfig attribute found; "
                             "the app relies entirely on platform defaults for "
                             "TLS trust and cleartext policy, with no "
                             "certificate pinning.",
                recommendation="Add a Network Security Config with certificate "
                                "pinning for high value domains and an explicit "
                                "cleartext policy.",
                cwe="CWE-295",
            ))

    # -- exported component analysis -----------------------------------
    component_tags = {
        "activity": "Activity",
        "activity-alias": "Activity alias",
        "service": "Service",
        "receiver": "Broadcast receiver",
        "provider": "Content provider",
    }
    exported_components = {k: [] for k in component_tags}

    if application is not None:
        for tag, label in component_tags.items():
            for elem in application.findall(tag):
                name = _attr(elem, "name", "<unnamed>")
                exported, reason = _is_exported(elem)
                permission = _attr(elem, "permission")
                if not exported:
                    continue
                exported_components[tag].append({
                    "name": name, "reason": reason, "permission": permission,
                })

                if tag == "provider":
                    grant_uri = elem.find("grant-uri-permission") is not None
                    severity = "Critical" if not permission else "Medium"
                    findings.append(Finding(
                        category="manifest",
                        title=f"Exported content provider without adequate protection: {name}",
                        severity=severity,
                        description=(
                            f"{label} '{name}' is exported ({reason}) "
                            f"{'and defines no android:permission' if not permission else f'protected only by permission {permission}'}. "
                            f"{'It also declares grant-uri-permission, widening access further. ' if grant_uri else ''}"
                            "Exported providers without permission checks can "
                            "leak or allow tampering with app data (and are a "
                            "classic SQL injection surface via query()/insert())."
                        ),
                        evidence=f"<provider android:name=\"{name}\" android:exported=\"true\" .../>",
                        recommendation="Set android:exported=\"false\" unless the "
                                        "provider must be shared, restrict with a "
                                        "signature-level android:permission, and "
                                        "validate all incoming URIs/selection args.",
                        cwe="CWE-926",
                    ))
                else:
                    severity = "High" if not permission else "Low"
                    findings.append(Finding(
                        category="manifest",
                        title=f"Exported {label.lower()} without permission: {name}"
                        if not permission else
                        f"Exported {label.lower()}: {name}",
                        severity=severity,
                        description=(
                            f"{label} '{name}' is exported ({reason})"
                            + (f" and is protected by permission '{permission}'."
                               if permission else
                               ", with no android:permission guarding it, so any "
                               "other app on the device can launch/bind to it.")
                        ),
                        evidence=f"<{tag} android:name=\"{name}\" android:exported=\"true\" .../>",
                        recommendation="Set android:exported=\"false\" if the "
                                        "component is not meant to be used by "
                                        "other apps, or guard it with a "
                                        "signature-level permission and validate "
                                        "all Intent extras defensively.",
                        cwe="CWE-926",
                    ))

    # -- dangerous permissions -------------------------------------------
    declared = meta["permissions"] or []
    dangerous_used = [p for p in declared if p in DANGEROUS_PERMISSION_PREFIXES]
    if dangerous_used:
        findings.append(Finding(
            category="manifest",
            title=f"{len(dangerous_used)} dangerous/sensitive permission(s) requested",
            severity="Info",
            description="Dangerous permissions requested: " + ", ".join(
                p.split(".")[-1] for p in dangerous_used
            ),
            recommendation="Confirm each is required for core functionality "
                            "(principle of least privilege) and is requested "
                            "at runtime with clear justification to the user.",
            cwe="CWE-250",
        ))

    return {
        "meta": meta,
        "findings": findings,
        "exported_components": exported_components,
        "raw_root": root,
        "apk_obj": apk,
    }
