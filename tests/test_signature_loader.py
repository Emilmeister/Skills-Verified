import pytest

from skills_verified.data.loader import SignatureLoadError, SignatureLoader


def test_load_valid_yaml(tmp_path):
    """Create a tmp yaml file and verify it loads correctly."""
    yaml_file = tmp_path / "test_sigs.yaml"
    yaml_file.write_text(
        "version: '1.0'\n"
        "signatures:\n"
        "  - id: test_sig_1\n"
        "    pattern: 'foo.*bar'\n"
        "    severity: HIGH\n"
        "    description: Test signature\n"
    )

    loader = SignatureLoader(data_dir=tmp_path)
    data = loader.load("test_sigs.yaml")
    assert isinstance(data, dict)
    assert "version" in data
    assert "signatures" in data
    assert len(data["signatures"]) == 1
    assert data["signatures"][0]["id"] == "test_sig_1"


def test_load_missing_file(tmp_path):
    """A missing ruleset is an explicit scanner failure."""
    loader = SignatureLoader(data_dir=tmp_path)
    with pytest.raises(SignatureLoadError, match="not found"):
        loader.load("nonexistent.yaml")


def test_load_signatures(tmp_path):
    """load_signatures returns the list from the 'signatures' key."""
    yaml_file = tmp_path / "sigs.yaml"
    yaml_file.write_text(
        "signatures:\n"
        "  - id: sig_a\n"
        "    pattern: 'alpha'\n"
        "    severity: HIGH\n"
        "  - id: sig_b\n"
        "    pattern: 'beta'\n"
        "    severity: MEDIUM\n"
    )

    loader = SignatureLoader(data_dir=tmp_path)
    sigs = loader.load_signatures("sigs.yaml")
    assert isinstance(sigs, list)
    assert len(sigs) == 2
    assert sigs[0]["id"] == "sig_a"
    assert sigs[1]["id"] == "sig_b"


def test_load_malformed_yaml(tmp_path):
    """Malformed YAML is an explicit scanner failure."""
    yaml_file = tmp_path / "bad.yaml"
    yaml_file.write_text("this: is: not: valid: yaml:\n  - [unclosed\n  {broken\n")

    loader = SignatureLoader(data_dir=tmp_path)
    with pytest.raises(SignatureLoadError, match="Failed to parse"):
        loader.load("bad.yaml")


def test_default_loader_reads_packaged_rules():
    loader = SignatureLoader()

    assert loader.load_signatures("reverse_shell_signatures.yaml")


def test_loader_rejects_path_traversal(tmp_path):
    loader = SignatureLoader(data_dir=tmp_path)

    with pytest.raises(SignatureLoadError, match="plain filename"):
        loader.load("../rules.yaml")


def test_loader_rejects_missing_signature_key(tmp_path):
    (tmp_path / "rules.yaml").write_text("version: '1.0'\n")
    loader = SignatureLoader(data_dir=tmp_path)

    with pytest.raises(SignatureLoadError, match="missing required key 'signatures'"):
        loader.load_signatures("rules.yaml")
