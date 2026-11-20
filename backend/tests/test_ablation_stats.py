import pytest

from app.ablation_stats import blind_assignment, mcnemar_exact, parse_model_json, wilson_interval


def test_wilson_interval_matches_known_values():
    low, high = wilson_interval(8, 10)
    assert low == pytest.approx(0.490, abs=0.002)
    assert high == pytest.approx(0.943, abs=0.002)


def test_wilson_interval_handles_extremes_and_empty():
    assert wilson_interval(0, 0) == (0.0, 0.0)
    low, high = wilson_interval(10, 10)
    assert high == 1.0 and 0.6 < low < 0.8
    low, high = wilson_interval(0, 10)
    assert low == 0.0 and 0.2 < high < 0.4


def test_mcnemar_exact_known_values():
    assert mcnemar_exact(5, 0) == pytest.approx(0.0625)
    assert mcnemar_exact(3, 3) == 1.0
    assert mcnemar_exact(0, 0) == 1.0
    assert mcnemar_exact(0, 5) == mcnemar_exact(5, 0)


def test_parse_model_json_accepts_plain_and_fenced_replies():
    assert parse_model_json('{"exploit_scenario": "a", "fixed_code": "b"}') == ("a", "b")
    fenced = '```json\n{"exploit_scenario": "a", "fixed_code": "b"}\n```'
    assert parse_model_json(fenced) == ("a", "b")


@pytest.mark.parametrize(
    "bad",
    [
        "not json",
        "[]",
        '{"exploit_scenario": "a"}',
        '{"exploit_scenario": "a", "fixed_code": 5}',
        '{"exploit_scenario": " ", "fixed_code": "b"}',
    ],
)
def test_parse_model_json_rejects_unusable_replies(bad):
    assert parse_model_json(bad) is None


def test_blind_assignment_is_deterministic_and_uses_both_arms():
    ids = [f"s{i}" for i in range(20)]
    first = blind_assignment(ids, seed=1)
    assert first == blind_assignment(ids, seed=1)
    for pair in first.values():
        assert sorted(pair) == ["free_form", "grounded"]
    assert len({pair[0] for pair in first.values()}) == 2