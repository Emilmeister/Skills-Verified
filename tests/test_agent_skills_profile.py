from pathlib import Path

from skills_verified.platforms.agent_skills import AgentSkillsProfile


def _write_skill(path: Path, frontmatter: str, body: str = "# Instructions\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"---\n{frontmatter}---\n\n{body}")


def test_discovers_recursive_skills_and_parses_open_spec(tmp_path):
    _write_skill(
        tmp_path / "skills" / "pdf-tools" / "SKILL.md",
        "name: pdf-tools\n"
        "description: Process PDF documents when the user asks about forms.\n"
        "license: Apache-2.0\n"
        "compatibility: Requires Python and network access.\n"
        "metadata:\n"
        "  author: example-org\n"
        '  version: "1.2.3"\n'
        "allowed-tools: Bash(git:*) Read\n",
    )
    _write_skill(
        tmp_path / ".agents" / "skills" / "code-review" / "SKILL.md",
        "name: code-review\ndescription: Review changes when asked for code review.\n",
    )

    profile = AgentSkillsProfile()
    assert profile.detect(tmp_path)
    assert profile.discover_skill_roots(tmp_path) == [
        Path(".agents/skills/code-review"),
        Path("skills/pdf-tools"),
    ]

    metadata = {item.name: item for item in profile.get_skill_metadata_all(tmp_path)}
    pdf = metadata["pdf-tools"]
    assert pdf.manifest_path == Path("skills/pdf-tools/SKILL.md")
    assert pdf.skill_root == Path("skills/pdf-tools")
    assert pdf.license == "Apache-2.0"
    assert pdf.compatibility == "Requires Python and network access."
    assert pdf.author == "example-org"
    assert pdf.metadata == {"author": "example-org", "version": "1.2.3"}
    assert pdf.allowed_tools == ["Bash(git:*)", "Read"]
    assert pdf.permissions_declared == ["shell", "filesystem"]
    assert pdf.validation_errors == []


def test_reports_manifest_validation_errors_without_losing_scope(tmp_path):
    _write_skill(
        tmp_path / "wrong-directory" / "SKILL.md",
        "name: Wrong--Name\n"
        "description: ''\n"
        "compatibility: ''\n"
        "metadata: not-a-map\n"
        "allowed-tools:\n"
        "  shell: true\n",
    )

    metadata = AgentSkillsProfile().get_skill_metadata_all(tmp_path)[0]

    assert metadata.skill_root == Path("wrong-directory")
    assert set(metadata.validation_errors) == {
        "name_invalid",
        "name_must_match_directory",
        "description_required",
        "compatibility_must_be_non_empty_string",
        "metadata_must_be_mapping",
        "allowed_tools_must_be_space_separated_string",
    }
    assert metadata.allowed_tools == []


def test_does_not_discover_dependencies_or_symlinks(tmp_path):
    _write_skill(
        tmp_path / "node_modules" / "dependency" / "SKILL.md",
        "name: dependency\ndescription: A dependency skill.\n",
    )
    outside = tmp_path.parent / f"{tmp_path.name}-outside-SKILL.md"
    outside.write_text("---\nname: outside\ndescription: Outside.\n---\n")
    (tmp_path / "linked-skill").mkdir()
    (tmp_path / "linked-skill" / "SKILL.md").symlink_to(outside)

    profile = AgentSkillsProfile()
    assert not profile.detect(tmp_path)
    assert profile.get_skill_metadata_all(tmp_path) == []


def test_rejects_entry_points_outside_skill_root(tmp_path):
    _write_skill(
        tmp_path / "skills" / "safe-skill" / "SKILL.md",
        "name: safe-skill\n"
        "description: A test skill.\n"
        "entry_points:\n"
        "  - scripts/main.py\n"
        "  - ../../outside.py\n"
        "  - /etc/passwd\n",
    )

    metadata = AgentSkillsProfile().get_skill_metadata_all(tmp_path)[0]

    assert metadata.entry_points == [Path("skills/safe-skill/scripts/main.py")]
    assert metadata.validation_errors.count("entry_point_must_be_relative") == 2
