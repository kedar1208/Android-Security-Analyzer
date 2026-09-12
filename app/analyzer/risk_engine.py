"""
Risk scoring engine.

Each analyzer module emits Finding objects with a severity label.
This module assigns a numeric weight to each severity, aggregates
findings into a 0-100 risk score, and maps that score onto a
human-readable risk rating band.

Extensibility: to add a new severity or change weighting, edit
SEVERITY_WEIGHTS / RATING_BANDS only -- nothing else needs to change.
"""
from dataclasses import dataclass, field
from typing import Optional


SEVERITY_WEIGHTS = {
    "Critical": 10.0,
    "High": 6.0,
    "Medium": 3.0,
    "Low": 1.0,
    "Info": 0.0,
}

# Diminishing returns cap so that e.g. 50 "Low" findings don't
# mathematically outweigh a single "Critical" -- score contribution
# per category is capped before summing.
CATEGORY_CAP = 40.0

RATING_BANDS = [
    (75.0, "Critical"),
    (50.0, "High"),
    (25.0, "Medium"),
    (1.0, "Low"),
    (0.0, "Info"),
]


@dataclass
class Finding:
    category: str           # manifest | secrets | nsc | storage | dynamic
    title: str
    severity: str            # Critical | High | Medium | Low | Info
    description: str = ""
    evidence: str = ""
    recommendation: str = ""
    cwe: Optional[str] = None
    weight: float = field(init=False, default=0.0)

    def __post_init__(self):
        self.weight = SEVERITY_WEIGHTS.get(self.severity, 0.0)


def score_findings(findings: list[Finding]) -> dict:
    """
    Aggregate a list of Finding objects into an overall risk score
    (0-100) and rating band, plus a per-category and per-severity
    breakdown useful for charting on the dashboard.
    """
    by_category: dict[str, float] = {}
    by_severity: dict[str, int] = {k: 0 for k in SEVERITY_WEIGHTS}

    for f in findings:
        by_category.setdefault(f.category, 0.0)
        by_category[f.category] += f.weight
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

    capped_total = sum(min(v, CATEGORY_CAP) for v in by_category.values())

    # Normalise against a ceiling roughly equal to "every category
    # maxed out" so the score saturates at 100 rather than growing
    # unbounded on huge APKs with many low-severity noise findings.
    ceiling = CATEGORY_CAP * max(len(by_category), 1)
    score = min(100.0, (capped_total / ceiling) * 100.0) if ceiling else 0.0

    rating = "Info"
    for threshold, label in RATING_BANDS:
        if score >= threshold:
            rating = label
            break

    return {
        "score": round(score, 1),
        "rating": rating,
        "by_category": {k: round(v, 1) for k, v in by_category.items()},
        "by_severity": by_severity,
        "total_findings": len(findings),
    }
