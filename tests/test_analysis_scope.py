from pathlib import Path
from types import SimpleNamespace

from skills_verified.analyzers.pattern_analyzer import PatternAnalyzer
from skills_verified.core.context import analysis_roots, iter_analysis_files


def test_analysis_scope_excludes_product_code_outside_skill_roots(tmp_path):
    skill = tmp_path / "skills" / "demo"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("# Demo\n")
    product = tmp_path / "packages" / "app"
    product.mkdir(parents=True)
    (product / "danger.py").write_text("eval(user_input)\n")
    context = SimpleNamespace(
        skill_roots=[Path("skills/demo")],
        files=[skill / "SKILL.md", product / "danger.py"],
    )

    assert analysis_roots(tmp_path, context) == [skill]
    assert list(iter_analysis_files(tmp_path, context)) == [skill / "SKILL.md"]
    assert PatternAnalyzer().analyze(tmp_path, context=context) == []


def test_analysis_roots_drop_nested_duplicates(tmp_path):
    skill = tmp_path / "skills" / "demo"
    nested = skill / "references"
    nested.mkdir(parents=True)
    context = SimpleNamespace(
        skill_roots=[Path("skills/demo/references"), Path("skills/demo")]
    )

    assert analysis_roots(tmp_path, context) == [skill]
