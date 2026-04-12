import json
import logging
from dataclasses import dataclass
from pathlib import Path

from skills_verified.core.analyzer import Analyzer
from skills_verified.core.models import Category, Finding, Severity

logger = logging.getLogger(__name__)

SCAN_EXTENSIONS = {".py", ".js", ".mjs", ".ts", ".sh", ".ps1", ".rb"}

ANALYSIS_PROMPT = """You are a security auditor. Analyze the following code files for security vulnerabilities.
Focus on:
- Logic errors that could lead to security issues
- Unsafe data handling
- Authentication/authorization flaws
- Information disclosure
- Race conditions

Return your findings as JSON with this exact structure:
{
  "findings": [
    {
      "title": "Short description",
      "description": "Detailed explanation",
      "severity": "critical|high|medium|low|info",
      "file_path": "relative/path.py",
      "line_number": 42,
      "confidence": 0.85
    }
  ]
}

If no vulnerabilities found, return: {"findings": []}

CODE FILES:
"""

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


@dataclass
class LlmConfig:
    url: str
    model: str
    key: str


class LlmAnalyzer(Analyzer):
    name = "llm"

    def __init__(self, config: LlmConfig | None):
        self.config = config

    def is_available(self) -> bool:
        return self.config is not None

    def analyze(self, repo_path: Path) -> list[Finding]:
        if not self.config:
            return []
        try:
            from openai import OpenAI
        except ImportError:
            logger.warning("openai package not installed, skipping LLM analysis")
            return []
        files = self._collect_files(repo_path)
        if not files:
            return []
        client = OpenAI(base_url=self.config.url, api_key=self.config.key)
        all_findings: list[Finding] = []
        for batch in self._batch_files(files, max_chars=50000):
            prompt = ANALYSIS_PROMPT
            for path, content in batch.items():
                prompt += f"\n--- {path} ---\n{content}\n"
            try:
                response = client.chat.completions.create(
                    model=self.config.model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.1,
                )
                text = response.choices[0].message.content or ""
                all_findings.extend(self._parse_response(text))
            except Exception:
                logger.exception("LLM API call failed")
        return all_findings

    def _collect_files(self, repo_path: Path) -> dict[str, str]:
        files: dict[str, str] = {}
        for file_path in repo_path.rglob("*"):
            if not file_path.is_file():
                continue
            if file_path.suffix not in SCAN_EXTENSIONS:
                continue
            try:
                content = file_path.read_text(errors="ignore")
                rel_path = str(file_path.relative_to(repo_path))
                files[rel_path] = content
            except OSError:
                continue
        return files

    def _batch_files(self, files: dict[str, str], max_chars: int = 50000) -> list[dict[str, str]]:
        batches: list[dict[str, str]] = []
        current_batch: dict[str, str] = {}
        current_size = 0
        for path, content in files.items():
            # Truncate individual files that exceed the limit on their own
            content = content[:max_chars]
            file_size = len(content)
            if current_size + file_size > max_chars and current_batch:
                batches.append(current_batch)
                current_batch = {}
                current_size = 0
            current_batch[path] = content
            current_size += file_size
            if current_size >= max_chars:
                batches.append(current_batch)
                current_batch = {}
                current_size = 0
        if current_batch:
            batches.append(current_batch)
        return batches

    def _parse_response(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        json_str = text
        if "```json" in text:
            json_str = text.split("```json")[1].split("```")[0]
        elif "```" in text:
            json_str = text.split("```")[1].split("```")[0]
        try:
            data = json.loads(json_str.strip())
        except json.JSONDecodeError:
            logger.warning("Failed to parse LLM response as JSON")
            return []
        for item in data.get("findings", []):
            severity_str = item.get("severity", "medium").lower()
            severity = SEVERITY_MAP.get(severity_str, Severity.MEDIUM)
            confidence = item.get("confidence", 0.7)
            if confidence < 0.5 and severity in (Severity.CRITICAL, Severity.HIGH):
                severity = Severity.MEDIUM
            findings.append(Finding(
                title=item.get("title", "LLM finding"),
                description=item.get("description", ""),
                severity=severity,
                category=Category.CODE_SAFETY,
                file_path=item.get("file_path"),
                line_number=item.get("line_number"),
                analyzer=self.name,
                confidence=confidence,
            ))
        return findings
