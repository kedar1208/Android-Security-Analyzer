"""
Renders the Jinja2 HTML report and converts it to PDF. Kept as a
single template so HTML and PDF output never drift apart.

PDF engine choice: xhtml2pdf (pisa) is used as the primary backend
because it's pure Python -- no native Cairo/Pango/GdkPixbuf binaries
required, which is what breaks WeasyPrint on a lot of Windows setups
(missing gobject-2.0-0.dll and friends). xhtml2pdf's CSS support is
more limited (no flexbox/grid), which is why the report template
uses a plain <table> for the summary cards instead of flex layout --
that keeps the exact same markup rendering correctly in both the
browser and both PDF engines.

If xhtml2pdf isn't installed, WeasyPrint is tried as a fallback (for
environments that do have its native deps set up). If neither is
available/working, render_pdf raises a clear, actionable error and
the HTML report endpoint remains fully unaffected either way.
"""
from __future__ import annotations

from collections import defaultdict
from io import BytesIO
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"

_env = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=select_autoescape(["html"]),
)

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def render_html(scan, findings, risk, exported_components: dict | None = None) -> str:
    """
    scan: ORM Scan object (or any object/dict with the expected attrs)
    findings: list of ORM Finding objects (or Finding dataclasses)
    risk: dict from risk_engine.score_findings()
    """
    by_category = defaultdict(list)
    for f in findings:
        by_category[f.category].append(f)
    for cat in by_category:
        by_category[cat].sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))

    template = _env.get_template("report.html")
    return template.render(
        scan=scan,
        risk=risk,
        findings_by_category=dict(by_category),
        exported_components=exported_components or {},
    )


def render_pdf(html_content: str) -> bytes:
    errors: list[str] = []

    # -- primary: xhtml2pdf (pure Python, no native deps) --------------
    try:
        from xhtml2pdf import pisa
        buffer = BytesIO()
        result = pisa.CreatePDF(src=html_content, dest=buffer, encoding="utf-8")
        if not result.err:
            return buffer.getvalue()
        errors.append(f"xhtml2pdf reported {result.err} error(s) during rendering.")
    except ImportError:
        errors.append("xhtml2pdf is not installed (pip install xhtml2pdf).")
    except Exception as exc:
        errors.append(f"xhtml2pdf failed: {exc}")

    # -- fallback: WeasyPrint (needs native Cairo/Pango/GdkPixbuf) ------
    try:
        from weasyprint import HTML
        return HTML(string=html_content).write_pdf()
    except ImportError:
        errors.append("WeasyPrint is not installed.")
    except Exception as exc:
        errors.append(
            f"WeasyPrint failed: {exc}. This is usually a missing native "
            "dependency (Cairo/Pango/GdkPixbuf) rather than a code issue."
        )

    raise RuntimeError(
        "PDF generation failed with every available engine. "
        + " | ".join(errors)
        + " Use the /report.html endpoint in the meantime, or run "
          "`pip install xhtml2pdf` for dependency-free PDF export."
    )
