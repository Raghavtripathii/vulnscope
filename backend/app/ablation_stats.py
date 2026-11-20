"""Small, dependency-free helpers for the grounding ablation (scripts/ablation.py)."""

import json
import math
import random
import re

FENCE = re.compile(r"^```(?:json)?\s*|\s*```$")


def wilson_interval(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a proportion."""
    if n == 0:
        return (0.0, 0.0)
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def mcnemar_exact(only_a: int, only_b: int) -> float:
    """Two-sided exact McNemar test (paired binary outcomes).

    only_a: pairs where arm A succeeded and arm B failed. only_b: the reverse.
    """
    n = only_a + only_b
    if n == 0:
        return 1.0
    k = min(only_a, only_b)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2**n
    return min(1.0, 2 * tail)


def parse_model_json(text: str) -> tuple[str, str] | None:
    """Return (exploit_scenario, fixed_code) or None if the reply is not usable."""
    try:
        data = json.loads(FENCE.sub("", text.strip()))
    except (json.JSONDecodeError, AttributeError):
        return None
    if not isinstance(data, dict):
        return None
    exploit = data.get("exploit_scenario")
    fixed = data.get("fixed_code")
    if not isinstance(exploit, str) or not isinstance(fixed, str):
        return None
    if not exploit.strip() or not fixed.strip():
        return None
    return exploit, fixed


def blind_assignment(ids: list[str], seed: int = 42) -> dict[str, tuple[str, str]]:
    """Randomly decide, per item, which arm is shown as A and which as B."""
    rng = random.Random(seed)
    result = {}
    for item_id in ids:
        order = ["grounded", "free_form"]
        rng.shuffle(order)
        result[item_id] = (order[0], order[1])
    return result