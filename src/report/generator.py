"""Responsible disclosure report generator.

Produces a structured JSON report suitable for submission to bug-bounty
platforms (Immunefi, Code4rena, HackenProof, Cantina).

Output schema
-------------
{
  "target": { "name": ..., "scope_url": ..., "authorized_date": ... },
  "scan_date": "YYYY-MM-DD",
  "findings": [ <Finding.to_dict()>, ... ],
  "summary": {
    "total": N,
    "by_severity": { "CRITICAL": N, ... }
  }
}
"""

from __future__ import annotations

import json
from datetime import date, datetime
from pathlib import Path

from ..scanners.models import Finding, Severity
from ..targets.scope_registry import Target


class ReportGenerator:
    """
    Collects findings and renders a structured disclosure report.

    Parameters
    ----------
    target:
        The authorized Target this report covers.
    """

    def __init__(self, target: Target) -> None:
        self.target = target
        self._findings: list[Finding] = []

    def add_findings(self, findings: list[Finding]) -> None:
        self._findings.extend(findings)

    def build(self) -> dict:
        """Return the full report as a plain dict."""
        by_severity: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self._findings:
            by_severity[f.severity] += 1

        return {
            "target": {
                "name": self.target.name,
                "scope_url": self.target.scope_url,
                "authorized_date": self.target.authorized_date.isoformat(),
            },
            "scan_date": date.today().isoformat(),
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "findings": [f.to_dict() for f in self._findings],
            "summary": {
                "total": len(self._findings),
                "by_severity": by_severity,
            },
        }

    def write_json(self, output_path: str | Path) -> Path:
        """Write the report to a JSON file and return the path."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        report = self.build()
        with output_path.open("w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
        return output_path
