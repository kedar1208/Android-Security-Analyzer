"""
Optional dynamic analysis module.

Deliberately scoped to `adb` + `logcat` only (per the challenge's
constraint of "organizer-provided APKs and emulators only", and to
avoid the operational complexity/risk of instrumentation frameworks
like Frida in a shared challenge environment):

  1. Install the APK on the currently-connected/booted
     emulator (`adb install -r`).
  2. Clear logcat, launch the app's launcher activity.
  3. Capture logcat for a configurable window.
  4. Run the same secret/sensitive-keyword regex rules used by the
     static secret scanner against the captured log to catch
     runtime leakage that only appears once the app is exercised
     (crash traces, verbose network/debug logging, printed tokens).
  5. Uninstall (best-effort cleanup).

This is deliberately a thin orchestration layer around `adb` shell
commands, kept dependency-free so it works in any environment with
the Android platform-tools on PATH and exactly one connected device/
emulator. It is skipped entirely (and reported as such) if no device
is available -- static analysis results are never blocked on it.
"""
from __future__ import annotations

import re
import subprocess
import time

from ..analyzer.risk_engine import Finding
from ..analyzer.secret_scanner import SIGNATURES, _looks_like_noise

DEFAULT_CAPTURE_SECONDS = 25


def _run(cmd: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _device_available() -> bool:
    try:
        out = _run(["adb", "devices"], timeout=10)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    lines = [l for l in out.stdout.splitlines()[1:] if l.strip()]
    return any(l.split()[1] == "device" for l in lines if len(l.split()) > 1)


def run_dynamic_analysis(apk_path: str, package_name: str,
                          capture_seconds: int = DEFAULT_CAPTURE_SECONDS) -> dict:
    """
    Returns a dict with findings + a status message. Never raises --
    any failure is captured as a low-noise Info finding explaining
    what was skipped and why, so the overall pipeline/report is
    unaffected.
    """
    findings: list[Finding] = []

    if not _device_available():
        findings.append(Finding(
            category="dynamic",
            title="Dynamic analysis skipped: no emulator/device connected",
            severity="Info",
            description="`adb devices` reported no device in 'device' state. "
                         "Connect/boot an organizer-provided emulator and "
                         "re-run with dynamic analysis enabled to capture "
                         "runtime logcat evidence.",
        ))
        return {"findings": findings, "ran": False}

    try:
        install = _run(["adb", "install", "-r", apk_path], timeout=120)
        if install.returncode != 0:
            findings.append(Finding(
                category="dynamic",
                title="Dynamic analysis: install failed",
                severity="Info",
                description=f"`adb install -r` failed: {install.stderr.strip()[:500]}",
            ))
            return {"findings": findings, "ran": False}

        _run(["adb", "logcat", "-c"], timeout=15)  # clear existing buffer

        # Launch the default/launcher activity for the package.
        _run(["adb", "shell", "monkey", "-p", package_name,
              "-c", "android.intent.category.LAUNCHER", "1"], timeout=30)

        time.sleep(capture_seconds)

        logcat = _run(["adb", "logcat", "-d"], timeout=30)
        log_text = logcat.stdout or ""

        # Best-effort cleanup; ignore failures.
        try:
            _run(["adb", "uninstall", package_name], timeout=30)
        except Exception:
            pass

        findings.extend(_scan_runtime_log(log_text, package_name))
        findings.append(Finding(
            category="dynamic",
            title="Dynamic analysis executed",
            severity="Info",
            description=f"Installed, launched and captured {capture_seconds}s "
                         f"of logcat for package '{package_name}'. "
                         f"{len(log_text.splitlines())} log lines analyzed.",
        ))
        return {"findings": findings, "ran": True, "log_lines": len(log_text.splitlines())}

    except subprocess.TimeoutExpired as exc:
        findings.append(Finding(
            category="dynamic",
            title="Dynamic analysis timed out",
            severity="Info",
            description=str(exc),
        ))
        return {"findings": findings, "ran": False}
    except Exception as exc:  # pragma: no cover
        findings.append(Finding(
            category="dynamic",
            title="Dynamic analysis failed",
            severity="Info",
            description=f"Unexpected error: {exc}",
        ))
        return {"findings": findings, "ran": False}


def _scan_runtime_log(log_text: str, package_name: str) -> list[Finding]:
    findings: list[Finding] = []
    if not log_text:
        return findings

    # Only look at lines associated with the target package's process
    # where possible, to reduce noise from unrelated system logs.
    relevant_lines = [l for l in log_text.splitlines() if package_name in l] or \
        log_text.splitlines()
    blob = "\n".join(relevant_lines)

    hits = []
    for rule, pattern, severity in SIGNATURES:
        for m in pattern.finditer(blob):
            snippet = m.group(0)
            if _looks_like_noise(snippet):
                continue
            hits.append((rule, severity, snippet))

    seen = set()
    for rule, severity, snippet in hits:
        key = (rule, snippet)
        if key in seen:
            continue
        seen.add(key)
        redacted = snippet if len(snippet) <= 12 else snippet[:6] + "…" + snippet[-4:]
        findings.append(Finding(
            category="dynamic",
            title=f"Runtime log leak: {rule}",
            severity=severity,
            description=f"A string matching '{rule}' appeared in logcat "
                         "output while the app was running.",
            evidence=f"Value (redacted): {redacted}",
            recommendation="Remove verbose/debug logging that prints "
                            "credentials or tokens; strip Log calls from "
                            "release builds.",
            cwe="CWE-532",
        ))

    crash_matches = re.findall(r"FATAL EXCEPTION.*(?:\n.+){0,5}", blob)
    if crash_matches:
        findings.append(Finding(
            category="dynamic",
            title="App crashed during dynamic analysis run",
            severity="Low",
            description=f"{len(crash_matches)} FATAL EXCEPTION block(s) "
                         "observed in logcat during the capture window. "
                         "Crash traces can incidentally leak internal "
                         "class/package structure and, occasionally, "
                         "in-memory sensitive values via stack frames.",
            evidence=crash_matches[0][:500],
            recommendation="Investigate and fix the crash; ensure crash "
                            "reporting does not forward stack traces "
                            "containing sensitive data to third parties.",
        ))

    return findings
