from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(Enum):
    CODE_SAFETY = "code_safety"
    CVE = "cve"
    GUARDRAILS = "guardrails"
    PERMISSIONS = "permissions"
    SUPPLY_CHAIN = "supply_chain"


class Grade(Enum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


@dataclass
class Finding:
    title: str
    description: str
    severity: Severity
    category: Category
    file_path: str | None
    line_number: int | None
    analyzer: str
    cve_id: str | None = None
    confidence: float = 1.0


@dataclass
class CategoryScore:
    category: Category
    score: int
    grade: Grade
    findings_count: int
    critical_count: int
    high_count: int


@dataclass
class Report:
    repo_url: str
    overall_score: int
    overall_grade: Grade
    categories: list[CategoryScore]
    findings: list[Finding]
    analyzers_used: list[str]
    llm_used: bool
    scan_duration_seconds: float
