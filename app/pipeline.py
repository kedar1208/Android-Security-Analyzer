"""
Orchestrates the full static (+ optional dynamic) analysis pipeline
for a single APK, and persists the results to the database.

Resilience notes:
  - Some commercial/hardened APKs (multi-locale resource tables with
    non-standard configs, obfuscated/packed DEX) trip bugs deep
    inside Androguard's own AXML/ARSC decoder. Those failures are
    NOT security findings about the target app -- they are parser
    limitations -- so every analyzer stage is individually isolated:
    a stage that fails is recorded as a single Info finding and the
    pipeline continues with whatever stages *did* succeed, instead
    of a single crash discarding the entire scan.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime

from .analyzer.manifest_analyzer import analyze_manifest
from .analyzer.secret_scanner import scan_secrets
from .analyzer.nsc_analyzer import analyze_nsc
from .analyzer.storage_logging import analyze_storage_and_logging
from .analyzer.risk_engine import score_findings, Finding
from .db.models import Scan, Finding as FindingModel


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _stage_failed_finding(stage: str, exc: Exception) -> Finding:
    return Finding(
        category="manifest",
        title=f"{stage} analysis stage failed for this APK",
        severity="Info",
        description=(
            f"The {stage} analysis stage raised an error and was skipped: "
            f"{type(exc).__name__}: {exc}. This usually reflects a parser "
            "limitation on an unusual/hardened resource table or packed "
            "DEX, not a security property of the app itself. Other stages "
            "still ran normally."
        ),
    )


def _load_apk_and_dex(apk_path: str):
    """
    Single AnalyzeAPK pass, reused by every analyzer module. Falls
    back to a manifest-only APK object (no DEX/resource-table cross-
    referencing) if the full analysis pass fails, so a scan never
    hard-fails outright -- it just loses the DEX-dependent checks
    (secrets-in-DEX, storage/logging heuristics) for that one APK.
    """
    try:
        from androguard.misc import AnalyzeAPK
        apk, dex_list, dx = AnalyzeAPK(apk_path)
        return apk, dx, None
    except Exception as exc:
        try:
            from androguard.core.apk import APK
        except ImportError:  # pragma: no cover - older androguard
            from androguard.core.bytecodes.apk import APK
        apk = APK(apk_path)
        return apk, None, exc


def run_pipeline(db_session, apk_path: str, original_filename: str,
                  run_dynamic: bool = False, dynamic_seconds: int = 25) -> Scan:
    all_findings: list[Finding] = []

    apk, dx, load_error = _load_apk_and_dex(apk_path)
    if load_error is not None:
        all_findings.append(_stage_failed_finding("Full DEX/resource (AnalyzeAPK)", load_error))

    # -- manifest (always attempted; APK object is guaranteed by this point) --
    try:
        manifest_result = analyze_manifest(apk=apk)
        all_findings.extend(manifest_result["findings"])
    except Exception as exc:
        all_findings.append(_stage_failed_finding("Manifest", exc))
        manifest_result = {"meta": {}, "findings": [], "exported_components": {}}

    meta = manifest_result.get("meta", {})

    # -- secrets (resource strings always attempted; DEX strings only if dx available) --
    try:
        secrets_result = scan_secrets(apk, dx)
        all_findings.extend(secrets_result["findings"])
    except Exception as exc:
        all_findings.append(_stage_failed_finding("Secret scanning", exc))

    # -- network security config --
    try:
        nsc_result = analyze_nsc(apk, meta, meta.get("nsc_ref"))
        all_findings.extend(nsc_result["findings"])
    except Exception as exc:
        all_findings.append(_stage_failed_finding("Network Security Config", exc))

    # -- storage / logging / crypto heuristics (needs dx) --
    if dx is not None:
        try:
            storage_result = analyze_storage_and_logging(dx)
            all_findings.extend(storage_result["findings"])
        except Exception as exc:
            all_findings.append(_stage_failed_finding("Storage/logging heuristics", exc))
    else:
        all_findings.append(Finding(
            category="storage",
            title="Storage/logging heuristics skipped (no DEX analysis available)",
            severity="Info",
            description="DEX bytecode analysis was unavailable for this APK "
                         "(see the earlier DEX/resource stage failure, if "
                         "any), so Log/WebView/TrustManager/crypto/storage "
                         "heuristics could not run.",
        ))

    # -- optional dynamic analysis --
    dynamic_ran = False
    if run_dynamic:
        try:
            from .dynamic.dynamic_analysis import run_dynamic_analysis
            pkg = meta.get("package")
            if not pkg:
                raise ValueError("package name unavailable from manifest analysis")
            dyn_result = run_dynamic_analysis(apk_path, pkg, capture_seconds=dynamic_seconds)
            all_findings.extend(dyn_result["findings"])
            dynamic_ran = dyn_result.get("ran", False)
        except Exception as exc:
            all_findings.append(_stage_failed_finding("Dynamic", exc))

    risk = score_findings(all_findings)

    scan = Scan(
        filename=original_filename,
        package_name=meta.get("package"),
        app_name=meta.get("app_name"),
        version_name=str(meta.get("version_name")) if meta.get("version_name") is not None else None,
        min_sdk=meta.get("min_sdk"),
        target_sdk=meta.get("target_sdk"),
        sha256=_sha256(apk_path),
        timestamp=datetime.utcnow(),
        risk_score=risk["score"],
        risk_rating=risk["rating"],
        dynamic_analysis_run=1 if dynamic_ran else 0,
        status="completed",
        exported_components_json=json.dumps(manifest_result.get("exported_components", {})),
    )
    db_session.add(scan)
    db_session.flush()  # get scan.id before adding findings

    for f in all_findings:
        db_session.add(FindingModel(
            scan_id=scan.id,
            category=f.category,
            title=f.title,
            severity=f.severity,
            weight=f.weight,
            description=f.description,
            evidence=f.evidence,
            recommendation=f.recommendation,
            cwe=f.cwe,
        ))

    db_session.commit()
    db_session.refresh(scan)
    return scan
