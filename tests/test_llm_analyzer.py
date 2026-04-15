from skills_verified.analyzers.llm_analyzer import LlmAnalyzer, LlmConfig, _LlmResponse
from skills_verified.core.models import Severity


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


def test_convert_findings():
    config = LlmConfig(url="http://localhost", model="test", key="k")
    analyzer = LlmAnalyzer(config)
    parsed = _LlmResponse.model_validate({
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
    findings = analyzer._convert_findings(parsed)
    assert len(findings) == 1
    assert findings[0].title == "SQL injection risk"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].confidence == 0.85
    assert findings[0].analyzer == "llm"


def test_convert_findings_low_confidence_downgrade():
    config = LlmConfig(url="http://localhost", model="test", key="k")
    analyzer = LlmAnalyzer(config)
    parsed = _LlmResponse.model_validate({
        "findings": [
            {
                "title": "Maybe a bug",
                "description": "Not sure",
                "severity": "critical",
                "confidence": 0.3,
            }
        ]
    })
    findings = analyzer._convert_findings(parsed)
    assert findings[0].severity == Severity.MEDIUM


def test_extract_json_direct():
    assert LlmAnalyzer._extract_json('{"findings": []}') == {"findings": []}


def test_extract_json_from_markdown():
    text = 'Some text\n```json\n{"findings": []}\n```\nmore text'
    assert LlmAnalyzer._extract_json(text) == {"findings": []}


def test_extract_json_from_braces():
    text = 'Here is my analysis: {"findings": [{"title": "x"}]} end.'
    data = LlmAnalyzer._extract_json(text)
    assert data is not None
    assert "findings" in data


def test_extract_json_returns_none_on_garbage():
    assert LlmAnalyzer._extract_json("no json here at all") is None


def test_batch_files():
    config = LlmConfig(url="http://localhost", model="test", key="k")
    analyzer = LlmAnalyzer(config)
    files = {f"file{i}.py": f"content{i}" * 1000 for i in range(10)}
    batches = analyzer._batch_files(files, max_chars=5000)
    assert len(batches) > 1
    for batch in batches:
        total = sum(len(v) for v in batch.values())
        assert total <= 5000
