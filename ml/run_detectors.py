import csv
import json
import shutil
import subprocess
import sys
import textwrap
import time
from collections import Counter
from pathlib import Path

csv.field_size_limit(sys.maxsize)

WORK = Path("/tmp/rd_work")
ESLINT_DIR = Path("/app/app/detectors/eslint-config")
EXTENSIONS = {"python": ".py", "javascript": ".js"}
SEMGREP_CONFIGS = ["p/security-audit", "p/owasp-top-ten"]


def index_of(path):
    return int(Path(path).stem)


def run(cmd):
    started = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True)
    print(f"{cmd[0]} finished in {time.time() - started:.0f}s, exit code {proc.returncode}")
    if not proc.stdout.strip():
        print(proc.stderr[:1000])
        sys.exit(f"{cmd[0]} produced no output")
    return proc


def semgrep_dir(lang_dir):
    cmd = ["semgrep"]
    for config in SEMGREP_CONFIGS:
        cmd += ["--config", config]
    cmd += ["--metrics=off", "--json", "--quiet", str(lang_dir)]
    payload = json.loads(run(cmd).stdout)
    scanned = {index_of(p) for p in payload["paths"]["scanned"]}
    hits = {}
    for item in payload["results"]:
        hits.setdefault(index_of(item["path"]), []).append(item["check_id"])
    return scanned, hits


def bandit_dir(lang_dir):
    payload = json.loads(run(["bandit", "-r", str(lang_dir), "-f", "json", "-q"]).stdout)
    scanned = {index_of(p) for p in payload["metrics"] if p != "_totals"}
    failed = {index_of(e["filename"]) for e in payload["errors"]}
    hits = {}
    for item in payload["results"]:
        hits.setdefault(index_of(item["filename"]), []).append(item["test_id"])
    return scanned - failed, hits


def eslint_dir(lang_dir):
    cmd = [
        "npx", "--prefix", str(ESLINT_DIR), "eslint",
        "--no-eslintrc", "-c", str(ESLINT_DIR / ".eslintrc.json"),
        "--format", "json", str(lang_dir),
    ]
    payload = json.loads(run(cmd).stdout)
    scanned = set()
    hits = {}
    failures = Counter()
    for file_result in payload:
        idx = index_of(file_result["filePath"])
        messages = file_result["messages"]
        fatal = [m for m in messages if m.get("fatal")]
        if fatal:
            failures[fatal[0]["message"][:70]] += 1
            continue
        scanned.add(idx)
        rules = [m["ruleId"] for m in messages if m.get("ruleId")]
        if rules:
            hits[idx] = rules
    print("eslint parse failures:", failures.most_common(5))
    return scanned, hits


def main(in_path, out_path):
    with open(in_path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    found = {row["lang"] for row in rows}
    if not found <= set(EXTENSIONS):
        sys.exit(f"unexpected lang values: {found}")

    if WORK.exists():
        shutil.rmtree(WORK)
    for lang in EXTENSIONS:
        (WORK / lang).mkdir(parents=True)
    for i, row in enumerate(rows):
        target = WORK / row["lang"] / f"{i:05d}{EXTENSIONS[row['lang']]}"
        target.write_text(textwrap.dedent(row["code"]), encoding="utf-8", newline="")
    print(f"wrote {len(rows)} functions")

    results = {
        "semgrep_python": semgrep_dir(WORK / "python"),
        "semgrep_javascript": semgrep_dir(WORK / "javascript"),
        "bandit": bandit_dir(WORK / "python"),
        "eslint": eslint_dir(WORK / "javascript"),
    }

    columns = [
        "code_hash", "repo_url", "lang", "category", "label",
        "semgrep_scanned", "semgrep_n", "semgrep_rules",
        "bandit_scanned", "bandit_n", "bandit_rules",
        "eslint_scanned", "eslint_n", "eslint_rules",
    ]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        for i, row in enumerate(rows):
            lang = row["lang"]
            out = {k: row[k] for k in ["code_hash", "repo_url", "lang", "category", "label"]}
            for tool, key in [("semgrep", f"semgrep_{lang}"),
                              ("bandit", "bandit" if lang == "python" else None),
                              ("eslint", "eslint" if lang == "javascript" else None)]:
                if key is None:
                    out[f"{tool}_scanned"] = out[f"{tool}_n"] = out[f"{tool}_rules"] = ""
                    continue
                scanned, hits = results[key]
                out[f"{tool}_scanned"] = int(i in scanned)
                out[f"{tool}_n"] = len(hits.get(i, []))
                out[f"{tool}_rules"] = ";".join(hits.get(i, []))
            writer.writerow(out)

    print("\ncoverage and hits (functions with at least one finding)")
    totals = {lang: sum(1 for r in rows if r["lang"] == lang) for lang in EXTENSIONS}
    for name, key, lang in [
        ("semgrep python", "semgrep_python", "python"),
        ("semgrep javascript", "semgrep_javascript", "javascript"),
        ("bandit python", "bandit", "python"),
        ("eslint javascript", "eslint", "javascript"),
    ]:
        scanned, hits = results[key]
        print(f"{name}: functions {totals[lang]}, scanned {len(scanned)}, with findings {len(hits)}")
    print(f"saved {out_path}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])