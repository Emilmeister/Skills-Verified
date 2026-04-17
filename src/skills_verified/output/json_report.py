import json
from pathlib import Path

from skills_verified.core.models import Report


def report_to_dict(report: Report, aibom: dict | None = None) -> dict:
    data = {
        "repo_url": report.repo_url,
        "overall_score": report.overall_score,
        "overall_grade": report.overall_grade.value,
        "categories": [
            {
                "category": cs.category.value,
                "score": cs.score,
                "grade": cs.grade.value,
                "findings_count": cs.findings_count,
                "critical_count": cs.critical_count,
                "high_count": cs.high_count,
            }
            for cs in report.categories
        ],
        "findings": [
            {
                "title": f.title,
                "description": f.description,
                "severity": f.severity.value,
                "category": f.category.value,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "analyzer": f.analyzer,
                "cve_id": f.cve_id,
                "confidence": f.confidence,
            }
            for f in report.findings
        ],
        "analyzers_used": report.analyzers_used,
        "llm_used": report.llm_used,
        "scan_duration_seconds": report.scan_duration_seconds,
    }
    if aibom is not None:
        data["aibom"] = aibom
    return data


def save_json_report(report: Report, path: Path, aibom: dict | None = None) -> None:
    data = report_to_dict(report, aibom=aibom)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
