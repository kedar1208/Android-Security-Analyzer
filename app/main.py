"""
FastAPI entrypoint for APKWatchtower.

Run with:
    uvicorn app.main:app --reload --port 8000

Then open http://localhost:8000/ for the upload + dashboard UI.
"""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, Response, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from .db.models import init_db, get_session, Scan, Finding as FindingModel
from .pipeline import run_pipeline
from .reporting.report_generator import render_html, render_pdf

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title="APKWatchtower",
    description="Static (+ optional dynamic) security analysis for Android APKs.",
    version="1.0.0",
)

init_db()

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
def index():
    return (STATIC_DIR / "index.html").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Scan endpoints
# ---------------------------------------------------------------------------

@app.post("/api/scan")
async def create_scan(
    file: UploadFile = File(...),
    dynamic: bool = Form(False),
    dynamic_seconds: int = Form(25),
    db: Session = Depends(get_session),
):
    if not file.filename.lower().endswith(".apk"):
        raise HTTPException(400, "Only .apk files are accepted.")

    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = tmp.name

    try:
        scan = run_pipeline(
            db, tmp_path, file.filename,
            run_dynamic=dynamic, dynamic_seconds=dynamic_seconds,
        )
    except Exception as exc:
        raise HTTPException(500, f"Analysis failed: {exc}")
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    return {"scan_id": scan.id, "risk_score": scan.risk_score, "risk_rating": scan.risk_rating}


@app.get("/api/scans")
def list_scans(db: Session = Depends(get_session)):
    scans = db.query(Scan).order_by(Scan.timestamp.desc()).all()
    return [_scan_summary(s) for s in scans]


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_session)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found.")
    findings = db.query(FindingModel).filter(FindingModel.scan_id == scan_id).all()
    return {
        **_scan_summary(scan),
        "exported_components": json.loads(scan.exported_components_json or "{}"),
        "findings": [_finding_dict(f) for f in findings],
    }


@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: int, db: Session = Depends(get_session)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found.")
    db.delete(scan)
    db.commit()
    return {"deleted": scan_id}


@app.get("/api/scans/{scan_id}/report.html", response_class=HTMLResponse)
def report_html(scan_id: int, db: Session = Depends(get_session)):
    scan, findings, risk, exported = _load_report_context(db, scan_id)
    html = render_html(scan, findings, risk, exported)
    return HTMLResponse(html)


@app.get("/api/scans/{scan_id}/report.pdf")
def report_pdf(scan_id: int, db: Session = Depends(get_session)):
    scan, findings, risk, exported = _load_report_context(db, scan_id)
    html = render_html(scan, findings, risk, exported)
    try:
        pdf_bytes = render_pdf(html)
    except Exception as exc:
        raise HTTPException(
            500,
            f"PDF generation failed ({exc}). Run `pip install xhtml2pdf` "
            "(no native dependencies required), or use the /report.html "
            "endpoint instead.",
        )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}_report.pdf"'},
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _scan_summary(s: Scan) -> dict:
    return {
        "id": s.id,
        "filename": s.filename,
        "package_name": s.package_name,
        "app_name": s.app_name,
        "version_name": s.version_name,
        "min_sdk": s.min_sdk,
        "target_sdk": s.target_sdk,
        "sha256": s.sha256,
        "timestamp": s.timestamp.isoformat() if s.timestamp else None,
        "risk_score": s.risk_score,
        "risk_rating": s.risk_rating,
        "dynamic_analysis_run": bool(s.dynamic_analysis_run),
        "status": s.status,
    }


def _finding_dict(f: FindingModel) -> dict:
    return {
        "id": f.id,
        "category": f.category,
        "title": f.title,
        "severity": f.severity,
        "weight": f.weight,
        "description": f.description,
        "evidence": f.evidence,
        "recommendation": f.recommendation,
        "cwe": f.cwe,
    }


def _load_report_context(db: Session, scan_id: int):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found.")
    findings = db.query(FindingModel).filter(FindingModel.scan_id == scan_id).all()
    by_severity = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    risk = {
        "score": scan.risk_score,
        "rating": scan.risk_rating,
        "total_findings": len(findings),
        "by_severity": by_severity,
    }
    exported = json.loads(scan.exported_components_json or "{}")
    return scan, findings, risk, exported
