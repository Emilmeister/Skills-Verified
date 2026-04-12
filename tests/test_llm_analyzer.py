import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from skills_verified.analyzers.llm_analyzer import LlmAnalyzer, LlmConfig
from skills_verified.core.models import Category, Severity


def test_name():
    config = LlmConfig(url="http://localhost", model="test", key="k")
    analyzer = LlmAnalyzer(config)
    assert analyzer.name == "llm"


def test_is_available_with_config():
    config = LlmConfig(url="http://localhost", model="test", key="k")
    analyzer = LlmAnalyzer(config)
    assert analyzer.is_available() is True


def test_is_available_without_config():
    analyzer = LlmAnalyzer(config=None)
    assert analyzer.is_available() is False


def test_parse_llm_response():
    config = LlmConfig(url="http://localhost", model="test", key="k")
    analyzer = LlmAnalyzer(config)
    llm_response = json.dumps({
        "findings": [
            {
                "title": "SQL injection risk",
                "description": "User input concatenated into SQL query",
                "severity": "high",
                "file_path": "db.py",
                "line_number": 42,
                "confidence": 0.85,
            }
        ]
    })
    findings = analyzer._parse_response(llm_response)
    assert len(findings) == 1
    assert findings[0].title == "SQL injection risk"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].confidence == 0.85
    assert findings[0].analyzer == "llm"


def test_parse_llm_response_invalid_json():
    config = LlmConfig(url="http://localhost", model="test", key="k")
    analyzer = LlmAnalyzer(config)
    findings = analyzer._parse_response("not json at all")
    assert findings == []


def test_batch_files():
    config = LlmConfig(url="http://localhost", model="test", key="k")
    analyzer = LlmAnalyzer(config)
    files = {f"file{i}.py": f"content{i}" * 1000 for i in range(10)}
    batches = analyzer._batch_files(files, max_chars=5000)
    assert len(batches) > 1
    for batch in batches:
        total = sum(len(v) for v in batch.values())
        assert total <= 5000
