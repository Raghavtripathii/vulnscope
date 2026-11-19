from app.detectors import semgrep_detector
from app.detectors.semgrep_detector import REGISTRY_PACKS, build_rulesets


def test_falls_back_to_registry_names_when_nothing_is_vendored(tmp_path):
    rulesets = build_rulesets(tmp_path)
    for pack in REGISTRY_PACKS:
        assert pack in rulesets


def test_uses_the_local_copy_when_it_exists(tmp_path):
    (tmp_path / "secrets.yml").write_text("rules: []\n")
    rulesets = build_rulesets(tmp_path)
    assert str(tmp_path / "secrets.yml") in rulesets
    assert "p/secrets" not in rulesets
    assert "p/security-audit" in rulesets


def test_all_packs_vendored_means_no_registry_access(tmp_path):
    for filename in REGISTRY_PACKS.values():
        (tmp_path / filename).write_text("rules: []\n")
    rulesets = build_rulesets(tmp_path)
    assert not any(item.startswith("p/") for item in rulesets)


def test_our_own_rules_are_always_included(tmp_path):
    rulesets = build_rulesets(tmp_path)
    assert str(semgrep_detector.CUSTOM_RULES_FILE) in rulesets
    assert str(semgrep_detector.AUTH_RULES_FILE) in rulesets


def test_the_version_check_is_switched_off():
    import os

    assert os.environ.get("SEMGREP_ENABLE_VERSION_CHECK") == "0"