import re
from pathlib import Path

from skills_verified.analyzers.code_reduce import reduce_context
from skills_verified.core.models import Category, Finding, Severity


def _make_finding(line_number: int | None, title: str = "x") -> Finding:
    return Finding(
        title=title,
        description="",
        severity=Severity.HIGH,
        category=Category.CODE_SAFETY,
        file_path="sample.py",
        line_number=line_number,
        analyzer="pattern",
    )


def test_reduces_to_minimal_skeleton(tmp_path: Path):
    src = [
        "import os",
        "import sys",
        "def greet(name):",
        "    print('hello ' + name)",
        "",
        "def unrelated():",
        "    return 42",
        "",
        "def run(user):",
        "    import urllib.request",
        "    result = urllib.request.urlopen(user)  # sink",
        "    return result",
        "",
        "x = 1",
        "y = 2",
    ]
    file_path = tmp_path / "sample.py"
    file_path.write_text("\n".join(src))
    seed = _make_finding(line_number=11)
    sink_rx = re.compile(r"urlopen\s*\(")

    def probe(text: str) -> bool:
        return bool(sink_rx.search(text))

    reduced = reduce_context(file_path, seed, tmp_path, probe, max_iterations=100)

    assert "urlopen" in reduced
    assert len(reduced.splitlines()) <= 5


def test_preserves_anchor_line(tmp_path: Path):
    src = ["line1", "ANCHOR", "line3", "line4"]
    file_path = tmp_path / "f.py"
    file_path.write_text("\n".join(src))
    seed = _make_finding(line_number=2)

    def probe(text: str) -> bool:
        return "ANCHOR" in text or "line4" in text

    reduced = reduce_context(file_path, seed, tmp_path, probe)
    assert "ANCHOR" in reduced


def test_returns_full_file_when_probe_fails_on_original(tmp_path: Path):
    file_path = tmp_path / "f.py"
    original = "print('no vuln')\n"
    file_path.write_text(original)
    seed = _make_finding(line_number=1)

    def probe(text: str) -> bool:
        return "__nonexistent__" in text

    reduced = reduce_context(file_path, seed, tmp_path, probe)
    assert reduced == original


def test_anchor_out_of_range_returns_full_file(tmp_path: Path):
    file_path = tmp_path / "f.py"
    original = "a\nb\nc\n"
    file_path.write_text(original)
    seed = _make_finding(line_number=999)

    def probe(text: str) -> bool:
        return "a" in text

    reduced = reduce_context(file_path, seed, tmp_path, probe)
    assert reduced == original


def test_timeout_returns_best_so_far(tmp_path: Path):
    file_path = tmp_path / "f.py"
    file_path.write_text("\n".join(f"line{i}" for i in range(200)))
    seed = _make_finding(line_number=1)

    import time

    def slow_probe(text: str) -> bool:
        time.sleep(0.05)
        return "line0" in text

    reduced = reduce_context(
        file_path, seed, tmp_path, slow_probe,
        max_iterations=1000, timeout_seconds=0.2,
    )
    assert "line0" in reduced


def test_probe_exception_treated_as_false(tmp_path: Path):
    file_path = tmp_path / "f.py"
    file_path.write_text("a\nb\nc\n")
    seed = _make_finding(line_number=1)

    calls = {"n": 0}

    def flaky(text: str) -> bool:
        calls["n"] += 1
        if calls["n"] == 1:
            return True
        raise RuntimeError("boom")

    reduced = reduce_context(file_path, seed, tmp_path, flaky)
    assert reduced is not None


def test_empty_file(tmp_path: Path):
    file_path = tmp_path / "empty.py"
    file_path.write_text("")
    seed = _make_finding(line_number=None)
    reduced = reduce_context(file_path, seed, tmp_path, lambda t: True)
    assert reduced == ""
