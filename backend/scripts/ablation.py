"""Offline grounding ablation: detector-grounded vs free-form explanations.

Both arms see the same full code and must return the same two fields. The only
difference is that the grounded arm is also told what the static analysers found
(class, CWE, line, evidence) and is told to explain only that finding.

Objective outcome: the fixed code the model returns is scanned again with the real
detectors. A fix counts as "good" when it still parses, keeps most of the code, the
scan finished, the target class is gone and no new class appears.

Run inside the backend container:
  docker compose exec -w /app -e PYTHONPATH=/app backend python scripts/ablation.py
Add --dry-run to test the pipeline without calling Gemini.
"""

import argparse
import ast
import csv
import json
import shutil
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path

import httpx
from ablation_corpus import NEW_SNIPPETS

from app.ablation_stats import blind_assignment, mcnemar_exact, parse_model_json, wilson_interval
from app.config import settings
from app.exercises import EXERCISES
from app.explanations.grouping import group_findings
from app.explanations.schema import CLASS_LABELS
from app.scanner import scan_with_status

GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
RETRY_STATUS = {429, 500, 502, 503, 504}
ARMS = ("grounded", "free_form")
MIN_KEPT_RATIO = 0.5

COMMON = (
    "You are a secure coding tutor for students. "
    "Never include or invent real credentials. "
    "Reply with JSON only, with exactly these keys: exploit_scenario, fixed_code. "
    "exploit_scenario explains how an attacker could exploit the problem. "
    "fixed_code is the complete corrected version of the code, not just the changed line."
)
FREE_FORM_TASK = "Review the code below. Explain the most important security vulnerability in it."
GROUNDED_TASK = (
    "Explain ONLY the finding below, which was reported by automated static analysis tools. "
    "Do not report any other vulnerability. "
    "If the code does not give enough information, say what is missing instead of guessing."
)


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def code_block(language: str, code: str) -> str:
    return f"Language: {language}\nCode:\n<<<\n{code.rstrip()}\n>>>"


def free_form_prompt(language: str, code: str) -> str:
    return "\n".join([COMMON, FREE_FORM_TASK, "", code_block(language, code)])


def grounded_prompt(language: str, code: str, issue) -> str:
    lines = [
        COMMON,
        GROUNDED_TASK,
        "",
        code_block(language, code),
        "",
        "Finding from static analysis:",
        f"Class: {CLASS_LABELS.get(issue.vulnerability_class, issue.vulnerability_class)}",
        f"CWE: {issue.cwe or 'not reported'}",
        f"OWASP: {issue.owasp or 'not reported'}",
        f"Line: {issue.line_number if issue.line_number is not None else 'unknown'}",
        "Evidence from detectors:",
    ]
    for item in issue.evidence:
        lines.append(f"- {item.get('detector')} {item.get('rule_id')}: {item.get('message')}")
    return "\n".join(lines)


def call_gemini(prompt: str, retries: int = 4) -> str:
    key = settings.gemini_api_key.get_secret_value()
    if not key:
        raise RuntimeError("GEMINI_API_KEY is not set in backend/.env")
    url = GEMINI_URL.format(model=settings.gemini_model)
    body = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0, "responseMimeType": "application/json"},
    }
    last_status = None
    for attempt in range(retries):
        response = httpx.post(url, json=body, headers={"x-goog-api-key": key}, timeout=60.0)
        last_status = response.status_code
        if response.status_code in RETRY_STATUS:
            wait = 12 * (attempt + 1)
            log(f"    model returned {response.status_code}, waiting {wait}s")
            time.sleep(wait)
            continue
        if response.status_code != 200:
            raise RuntimeError(f"model returned HTTP {response.status_code}")
        try:
            return response.json()["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError, TypeError, ValueError):
            raise RuntimeError("model reply had an unexpected shape")
    raise RuntimeError(f"model still failing after {retries} tries (last HTTP {last_status})")


def fake_model(snippet: dict) -> str:
    """Offline stand-in used by --dry-run: returns the reference fix when one exists."""
    fixed = snippet.get("reference_fix") or snippet["code"]
    return json.dumps({"exploit_scenario": "(dry run)", "fixed_code": fixed})


def valid_syntax(code: str, language: str):
    if language == "python":
        try:
            ast.parse(code)
            return True
        except SyntaxError:
            return False
    node = shutil.which("node")
    if node is None:
        return None
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as tmp:
        tmp.write(code)
        path = tmp.name
    try:
        done = subprocess.run([node, "--check", path], capture_output=True, timeout=15)
        return done.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return None
    finally:
        Path(path).unlink(missing_ok=True)


def analyse_fix(original: str, fixed: str, language: str, target_class: str, original_classes: set) -> dict:
    scan = scan_with_status(fixed, language)
    classes_after = {issue.vulnerability_class for issue in group_findings(scan.findings)}
    syntax_ok = valid_syntax(fixed, language)
    kept_code = len(fixed.strip()) >= MIN_KEPT_RATIO * len(original.strip())
    target_cleared = target_class not in classes_after
    new_classes = sorted(classes_after - original_classes)
    good_fix = (
        syntax_ok is not False
        and kept_code
        and scan.complete
        and target_cleared
        and not new_classes
    )
    return {
        "syntax_ok": syntax_ok,
        "kept_code": kept_code,
        "scan_complete": scan.complete,
        "target_cleared": target_cleared,
        "new_classes": new_classes,
        "good_fix": good_fix,
    }


def build_corpus(only_language: str | None) -> list[dict]:
    corpus = [
        dict(
            id=e.id,
            language=e.language,
            vulnerability_class=e.vulnerability_class,
            code=e.vulnerable_code,
            reference_fix=e.reference_fix,
            source="exercise",
        )
        for e in EXERCISES
    ]
    corpus += [dict(item, source="new") for item in NEW_SNIPPETS]
    if only_language:
        corpus = [item for item in corpus if item["language"] == only_language]
    return corpus


def run_arm(arm: str, snippet: dict, issue, original_classes: set, dry_run: bool, delay: float) -> dict:
    prompt = (
        grounded_prompt(snippet["language"], snippet["code"], issue)
        if arm == "grounded"
        else free_form_prompt(snippet["language"], snippet["code"])
    )
    try:
        text = fake_model(snippet) if dry_run else call_gemini(prompt)
    except (RuntimeError, httpx.HTTPError) as error:
        return {"status": "no_output", "error": str(error)[:200]}
    finally:
        if not dry_run:
            time.sleep(delay)

    parsed = parse_model_json(text)
    if parsed is None:
        return {"status": "no_output", "error": "reply was not the required JSON"}
    exploit, fixed = parsed
    analysis = analyse_fix(
        snippet["code"], fixed, snippet["language"], snippet["vulnerability_class"], original_classes
    )
    return {"status": "ok", "exploit_scenario": exploit, "fixed_code": fixed, "analysis": analysis}


def percent(successes: int, n: int) -> str:
    if n == 0:
        return "n/a"
    low, high = wilson_interval(successes, n)
    return f"{successes}/{n} = {100 * successes / n:.0f}% (95% CI {100 * low:.0f}-{100 * high:.0f}%)"


def summarise(records: list[dict], excluded: list[dict]) -> str:
    lines = ["# Grounding ablation summary", ""]
    lines.append(f"Snippets tried: {len(records) + len(excluded)}. Used: {len(records)}. Excluded: {len(excluded)}.")
    for item in excluded:
        lines.append(f"- excluded {item['id']}: {item['reason']}")
    lines.append("")

    lines += ["| Measure | Grounded | Free-form |", "|---|---|---|"]
    stats = {}
    for arm in ARMS:
        ok = [r["arms"][arm] for r in records if r["arms"][arm]["status"] == "ok"]
        stats[arm] = {
            "outputs": ok,
            "n_all": len(records),
            "no_output": len(records) - len(ok),
            "good": sum(1 for a in ok if a["analysis"]["good_fix"]),
            "cleared": sum(1 for a in ok if a["analysis"]["target_cleared"]),
            "new": sum(1 for a in ok if a["analysis"]["new_classes"]),
            "syntax_bad": sum(1 for a in ok if a["analysis"]["syntax_ok"] is False),
        }
    g, f = stats["grounded"], stats["free_form"]
    lines.append(f"| Usable replies | {len(g['outputs'])}/{g['n_all']} | {len(f['outputs'])}/{f['n_all']} |")
    lines.append(f"| Good fix (of usable replies) | {percent(g['good'], len(g['outputs']))} | {percent(f['good'], len(f['outputs']))} |")
    lines.append(f"| Target class gone | {percent(g['cleared'], len(g['outputs']))} | {percent(f['cleared'], len(f['outputs']))} |")
    lines.append(f"| Fix introduces a new class | {g['new']} | {f['new']} |")
    lines.append(f"| Fix does not parse | {g['syntax_bad']} | {f['syntax_bad']} |")
    lines.append("")

    both = [r for r in records if all(r["arms"][a]["status"] == "ok" for a in ARMS)]
    only_g = sum(1 for r in both if r["arms"]["grounded"]["analysis"]["good_fix"] and not r["arms"]["free_form"]["analysis"]["good_fix"])
    only_f = sum(1 for r in both if r["arms"]["free_form"]["analysis"]["good_fix"] and not r["arms"]["grounded"]["analysis"]["good_fix"])
    lines.append(f"Paired comparison on {len(both)} snippets where both arms gave a usable reply:")
    lines.append(f"- good fix only with grounding: {only_g}; only without grounding: {only_f}")
    lines.append(f"- exact McNemar p-value (two-sided): {mcnemar_exact(only_g, only_f):.3f}")
    lines.append("")

    lines += ["By source and class (good fix, grounded vs free-form, usable replies only):", ""]
    groups = defaultdict(list)
    for r in records:
        groups[f"source={r['source']}"].append(r)
        groups[f"class={r['vulnerability_class']}"].append(r)
        groups[f"language={r['language']}"].append(r)
    for name in sorted(groups):
        row = []
        for arm in ARMS:
            ok = [x["arms"][arm] for x in groups[name] if x["arms"][arm]["status"] == "ok"]
            row.append(f"{sum(1 for a in ok if a['analysis']['good_fix'])}/{len(ok)}")
        lines.append(f"- {name}: grounded {row[0]}, free-form {row[1]}")
    lines += [
        "",
        "Limits: small corpus; snippets were kept only if the detectors flag them; 'good fix' means",
        "the detectors no longer flag the target class, not that the code is proven secure; one run,",
        "temperature 0, one model. Human ratings (ratings_blind.csv) are a separate measure.",
    ]
    return "\n".join(lines)


def write_ratings(records: list[dict], out: Path, seed: int) -> None:
    usable = [r for r in records if all(r["arms"][a]["status"] == "ok" for a in ARMS)]
    assignment = blind_assignment([r["id"] for r in usable], seed)
    rating_columns = []
    for side in ("A", "B"):
        rating_columns += [f"{side}_correct_1to5", f"{side}_clear_1to5", f"{side}_useful_1to5"]
    with open(out / "ratings_blind.csv", "w", newline="", encoding="utf-8") as blind, open(
        out / "ratings_key.csv", "w", newline="", encoding="utf-8"
    ) as key:
        blind_writer = csv.writer(blind)
        key_writer = csv.writer(key)
        blind_writer.writerow(["id", "language", "code", "A_explanation", "A_fixed_code", "B_explanation", "B_fixed_code", *rating_columns])
        key_writer.writerow(["id", "A_is", "B_is"])
        for r in usable:
            first, second = assignment[r["id"]]
            a, b = r["arms"][first], r["arms"][second]
            blind_writer.writerow(
                [r["id"], r["language"], r["code"], a["exploit_scenario"], a["fixed_code"], b["exploit_scenario"], b["fixed_code"], *[""] * len(rating_columns)]
            )
            key_writer.writerow([r["id"], first, second])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="do not call Gemini; use a fake model")
    parser.add_argument("--limit", type=int, default=0, help="only use the first N snippets")
    parser.add_argument("--language", choices=["python", "javascript"], default=None)
    parser.add_argument("--delay", type=float, default=5.0, help="seconds between model calls (free tier: 15/min)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", default="/app/ablation_out")
    args = parser.parse_args()

    corpus = build_corpus(args.language)
    if args.limit:
        corpus = corpus[: args.limit]
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    log(f"{len(corpus)} snippets, model {settings.gemini_model}, dry_run={args.dry_run}")

    records, excluded = [], []
    for number, snippet in enumerate(corpus, start=1):
        log(f"[{number}/{len(corpus)}] {snippet['id']}")
        scan = scan_with_status(snippet["code"], snippet["language"])
        if not scan.complete:
            excluded.append({"id": snippet["id"], "reason": f"a detector did not finish: {scan.detectors}"})
            continue
        issues = group_findings(scan.findings)
        targets = [i for i in issues if i.vulnerability_class == snippet["vulnerability_class"]]
        if not targets:
            excluded.append({"id": snippet["id"], "reason": "detectors did not flag the intended class"})
            continue
        original_classes = {i.vulnerability_class for i in issues}
        arms = {arm: run_arm(arm, snippet, targets[0], original_classes, args.dry_run, args.delay) for arm in ARMS}
        records.append(
            {
                "id": snippet["id"],
                "language": snippet["language"],
                "vulnerability_class": snippet["vulnerability_class"],
                "source": snippet["source"],
                "code": snippet["code"],
                "arms": arms,
            }
        )

    (out / "results.json").write_text(json.dumps({"records": records, "excluded": excluded}, indent=2), encoding="utf-8")
    summary = summarise(records, excluded)
    (out / "summary.md").write_text(summary, encoding="utf-8")
    write_ratings(records, out, args.seed)
    print(summary)
    log(f"\nFiles written to {out}")


if __name__ == "__main__":
    main()