from pathlib import Path
from types import SimpleNamespace

import pytest

from skills_verified.analyzers.privilege_analyzer import PrivilegeAnalyzer
from skills_verified.core.models import Category
from skills_verified.platforms.base import SkillMetadata


def test_is_available():
    analyzer = PrivilegeAnalyzer()
    assert analyzer.is_available() is True
    assert analyzer.name == "privilege"


def test_finds_undeclared_shell(tmp_path):
    """Code uses subprocess but metadata only declares ['filesystem']."""
    code = tmp_path / "main.py"
    code.write_text(
        "import subprocess\n"
        "import socket\n"
        "\n"
        "subprocess.run(['ls', '-la'])\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
    )

    metadata = SkillMetadata(
        name="test-skill",
        description="A test skill.",
        author="dev",
        permissions_declared=["filesystem"],
        entry_points=[],
        platform="claude_code",
    )

    analyzer = PrivilegeAnalyzer()
    findings = analyzer.analyze(tmp_path, platforms=[metadata])

    undeclared_findings = [f for f in findings if "undeclared" in f.title.lower()]
    assert len(undeclared_findings) >= 1
    assert undeclared_findings[0].category == Category.PERMISSIONS

    # Should flag shell and/or network as undeclared
    undeclared_perms = {f.title.split(": ")[-1] for f in undeclared_findings}
    assert "shell" in undeclared_perms or "network" in undeclared_perms


def test_shell_entry_point_counts_as_shell_capability(tmp_path):
    skill = tmp_path / "skills" / "demo"
    script = skill / "scripts" / "run"
    script.parent.mkdir(parents=True)
    script.write_text("#!/bin/sh\nprintf '%s\\n' ok\n", encoding="utf-8")
    metadata = SimpleNamespace(
        name="demo",
        permissions_declared=["filesystem"],
        entry_points=[Path("skills/demo/scripts/run")],
        skill_root=Path("skills/demo"),
    )

    findings = PrivilegeAnalyzer().analyze(tmp_path, metadata=[metadata])

    assert any(
        finding.title == "Undeclared permission usage: shell" for finding in findings
    )


def test_no_findings_without_metadata(tmp_path):
    """Returns empty when no platforms are provided."""
    code = tmp_path / "main.py"
    code.write_text("import subprocess\nsubprocess.run(['ls'])\n")

    analyzer = PrivilegeAnalyzer()
    findings = analyzer.analyze(tmp_path, platforms=[])
    assert findings == []


def test_no_findings_without_declarations(tmp_path):
    """Returns empty when permissions_declared is empty (cannot compare)."""
    code = tmp_path / "main.py"
    code.write_text("import subprocess\nsubprocess.run(['ls'])\n")

    metadata = SkillMetadata(
        name="test-skill",
        description="A test skill.",
        author="dev",
        permissions_declared=[],
        entry_points=[],
        platform="claude_code",
    )

    analyzer = PrivilegeAnalyzer()
    findings = analyzer.analyze(tmp_path, platforms=[metadata])
    assert findings == []


def test_reuses_central_inventory(tmp_path, monkeypatch):
    code = tmp_path / "main.py"
    code.write_text("from pathlib import Path\nPath('x').read_text()\n")
    metadata = SkillMetadata(
        name="test-skill",
        description="A test skill.",
        author="dev",
        permissions_declared=["filesystem"],
        platform="agent_skills",
    )
    monkeypatch.setattr(
        "skills_verified.analyzers.privilege_analyzer.collect_safe_files",
        lambda _path: pytest.fail("must not rebuild inventory"),
    )

    assert (
        PrivilegeAnalyzer().analyze(
            tmp_path,
            context=SimpleNamespace(files=[code], metadata=[metadata]),
        )
        == []
    )


def test_entry_point_cannot_escape_repository(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.py").write_text("print('safe')\n")
    outside = tmp_path / "outside.py"
    outside.write_text("import os\nsecret = os.getenv('CANARY')\n")
    metadata = SkillMetadata(
        name="test-skill",
        description="A test skill.",
        author="dev",
        permissions_declared=["network"],
        entry_points=[Path("../outside.py"), outside],
        platform="agent_skills",
    )

    findings = PrivilegeAnalyzer().analyze(repo, metadata=[metadata])

    assert not any(finding.title.endswith(": env") for finding in findings)
    assert all("outside.py" not in finding.description for finding in findings)


def test_scopes_each_skill_to_its_own_root(tmp_path):
    safe_root = tmp_path / "skills" / "safe"
    other_root = tmp_path / "skills" / "other"
    safe_root.mkdir(parents=True)
    other_root.mkdir(parents=True)
    (safe_root / "main.py").write_text(
        "from pathlib import Path\nPath('x').read_text()\n"
    )
    (other_root / "main.py").write_text(
        "import requests\nrequests.get('https://example.test')\n"
    )
    metadata = SkillMetadata(
        name="safe",
        description="A safe skill.",
        author="dev",
        permissions_declared=["filesystem"],
        skill_root=Path("skills/safe"),
        platform="agent_skills",
    )

    assert PrivilegeAnalyzer().analyze(tmp_path, metadata=[metadata]) == []


def test_indexes_shared_inventory_once_for_many_skills(tmp_path):
    class CountingFiles(list):
        iterations = 0

        def __iter__(self):
            self.iterations += 1
            return super().__iter__()

    files = CountingFiles()
    metadata = []
    for index in range(20):
        root = tmp_path / "skills" / str(index)
        root.mkdir(parents=True)
        source = root / "main.py"
        source.write_text("print('ok')\n")
        files.append(source)
        metadata.append(
            SkillMetadata(
                name=str(index),
                description="demo",
                author=None,
                permissions_declared=["filesystem"],
                skill_root=Path("skills") / str(index),
            )
        )

    PrivilegeAnalyzer().analyze(
        tmp_path,
        context=SimpleNamespace(files=files, metadata=metadata),
    )

    assert files.iterations == 1
