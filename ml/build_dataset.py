"""
Phase 1 ML, step 1: build a labeled Python/JS function dataset from CVEfixes.

Run from the ml/ folder:   python build_dataset.py
Output:                    data/processed/dataset.csv
"""
import argparse
import hashlib
import re
import sqlite3
import sys
from pathlib import Path

import pandas as pd

DEFAULT_DB = "D:/vulnscope-data/raw/CVEfixes.db"
OUT_DIR = Path("data/processed")

LANGS = {"python", "javascript"}
MIN_CHARS, MAX_CHARS = 30, 10000

# Your locked scope (docs/scope.md) mapped to CWE numbers.
SCOPE = {
    "sql_injection": {89},
    "xss": {79},
    "secrets": {798, 259, 321},
    "auth": {287, 306, 862, 863},
}


def to_label(value):
    """'True' = method as it was BEFORE the fix (vulnerable). 'False' = AFTER the fix."""
    s = str(value).strip().lower()
    if s in ("true", "1"):
        return 1
    if s in ("false", "0"):
        return 0
    raise ValueError(f"Unexpected before_change value: {value!r}")


def cwe_number(x):
    """'CWE-89' -> 89, '89' -> 89, 'NVD-CWE-Other' -> None."""
    m = re.fullmatch(r"\s*(?:CWE-)?(\d+)\s*", str(x), flags=re.I)
    return int(m.group(1)) if m else None


def require_columns(conn, table, cols):
    have = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
    if not have:
        sys.exit(f"[SCHEMA ERROR] table '{table}' does not exist in this database.")
    missing = set(cols) - have
    if missing:
        sys.exit(
            f"[SCHEMA ERROR] table '{table}' is missing {sorted(missing)}.\n"
            f"Columns actually found: {sorted(have)}\n"
            "Copy this whole message and send it to me."
        )


def categorize(cwes):
    if not isinstance(cwes, str) or not cwes:
        return "other"
    nums = {int(c) for c in cwes.split(";") if c.isdigit()}
    for cat, ids in SCOPE.items():
        if nums & ids:
            return cat
    return "other"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DEFAULT_DB)
    args = ap.parse_args()

    if not Path(args.db).exists():
        sys.exit(f"[ERROR] Database not found: {args.db}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(f"file:{Path(args.db).as_posix()}?mode=ro", uri=True)

    require_columns(conn, "method_change", ["file_change_id", "name", "code", "before_change"])
    require_columns(conn, "file_change", ["file_change_id", "hash", "programming_language"])
    require_columns(conn, "fixes", ["cve_id", "hash", "repo_url"])
    require_columns(conn, "cwe_classification", ["cve_id", "cwe_id"])

    print("Loading file_change ...")
    fc = pd.read_sql("SELECT file_change_id, hash, programming_language FROM file_change", conn)
    print("Language values in DB (top 15):")
    print(fc["programming_language"].value_counts().head(15).to_string())
    fc["lang"] = fc["programming_language"].astype(str).str.strip().str.lower()
    fc = fc[fc["lang"].isin(LANGS)].copy()
    fc["file_change_id"] = fc["file_change_id"].astype(str)
    if fc.empty:
        sys.exit("[ERROR] No python/javascript rows. Check the language values printed above.")

    print("Loading fixes + CWE ...")
    fixes = pd.read_sql("SELECT cve_id, hash, repo_url FROM fixes", conn)
    cwe = pd.read_sql("SELECT cve_id, cwe_id FROM cwe_classification", conn)
    cwe["num"] = cwe["cwe_id"].apply(cwe_number)
    cwe = cwe.dropna(subset=["num"])
    cwe["num"] = cwe["num"].astype(int)
    cwe_map = cwe.groupby("cve_id")["num"].apply(set).to_dict()

    fixes_agg = (
        fixes.groupby("hash")
        .agg(repo_url=("repo_url", "first"), cve_ids=("cve_id", lambda s: sorted(set(s))))
        .reset_index()
    )

    def cwes_for(cves):
        s = set()
        for c in cves:
            s |= cwe_map.get(c, set())
        return ";".join(str(n) for n in sorted(s))

    fixes_agg["cwes"] = fixes_agg["cve_ids"].apply(cwes_for)

    before = len(fc)
    fc = fc.merge(fixes_agg[["hash", "repo_url", "cwes"]], on="hash", how="inner")
    print(f"file_changes (py/js): {before} -> {len(fc)} after linking to a fix/repo")

    print("Streaming method_change (a few minutes is normal) ...")
    # Filter inside SQLite so huge/other-language rows never reach Python (fixes MemoryError).
    conn.execute("CREATE TEMP TABLE pyjs_ids(file_change_id TEXT PRIMARY KEY)")
    conn.executemany(
        "INSERT OR IGNORE INTO pyjs_ids VALUES (?)",
        [(x,) for x in fc["file_change_id"].unique()],
    )
    cur = conn.execute(
        """
        SELECT m.file_change_id, m.name, m.code, m.before_change
        FROM method_change m CROSS JOIN pyjs_ids t
          ON CAST(m.file_change_id AS TEXT) = t.file_change_id
        WHERE length(m.code) BETWEEN ? AND ?
        """,
        (MIN_CHARS, MAX_CHARS),
    )
    cols = ["file_change_id", "name", "code", "before_change"]
    fc_small = fc[["file_change_id", "lang", "repo_url", "cwes"]]
    parts, total = [], 0
    while True:
        rows = cur.fetchmany(5000)
        if not rows:
            break
        chunk = pd.DataFrame(rows, columns=cols)
        total += len(chunk)
        chunk["file_change_id"] = chunk["file_change_id"].astype(str)
        merged = chunk.merge(fc_small, on="file_change_id", how="inner")
        if len(merged):
            parts.append(merged)
        if total % 50000 < 5000:
            print(f"  ... {total} rows read")
    conn.close()

    if not parts:
        sys.exit("[ERROR] No method_change rows matched the py/js file_changes. "
                 "file_change_id types may differ; send me the output above.")

    m = pd.concat(parts, ignore_index=True)
    print(f"method_change rows read (py/js, length-filtered): {total}, linked: {len(m)}")

    m["label"] = m["before_change"].map(to_label)
    m = m.dropna(subset=["code"])
    m["code"] = m["code"].astype(str)
    m = m[(m["code"].str.len() >= MIN_CHARS) & (m["code"].str.len() <= MAX_CHARS)].copy()
    print(f"after length filter: {len(m)}")

    m["code_hash"] = m["code"].apply(
        lambda c: hashlib.sha1(" ".join(c.split()).encode()).hexdigest()
    )

    # same code text appearing with both labels = ambiguous, drop it
    nlabels = m.groupby("code_hash")["label"].nunique()
    conflicting = set(nlabels[nlabels > 1].index)
    m = m[~m["code_hash"].isin(conflicting)]
    print(f"dropped {len(conflicting)} code strings that appear with BOTH labels")

    n_before = len(m)
    m = m.drop_duplicates("code_hash").copy()
    print(f"deduplicated: {n_before} -> {len(m)}")

    m["category"] = m["cwes"].apply(categorize)
    m = m[["code_hash", "repo_url", "lang", "name", "file_change_id",
           "cwes", "category", "label", "code"]]
    m.to_csv(OUT_DIR / "dataset.csv", index=False)

    print("\n================ DATASET REPORT ================")
    print(f"Total rows        : {len(m)}")
    print(f"Distinct repos    : {m['repo_url'].nunique()}")
    print("Label counts      :", m["label"].value_counts().to_dict(), "(1=vulnerable, 0=patched)")
    print("\nBy language x label:")
    print(pd.crosstab(m["lang"], m["label"]).to_string())
    print("\nBy scope category x label (your 4 locked classes + other):")
    print(pd.crosstab(m["category"], m["label"]).to_string())
    top = m[m["label"] == 1]["cwes"].fillna("").str.split(";").explode()
    top = top[top != ""].value_counts().head(15)
    print("\nTop CWE numbers among vulnerable rows:")
    print(top.to_string())

    g = m.groupby(["file_change_id", "name"])["label"].nunique()
    pairs = g[g == 2]
    print("\n================ SANITY PAIR ================")
    if len(pairs):
        fcid, name = pairs.index[0]
        sub = m[(m["file_change_id"] == fcid) & (m["name"] == name)]
        for lab in (1, 0):
            row = sub[sub["label"] == lab].iloc[0]
            tag = "BEFORE fix / vulnerable" if lab else "AFTER fix / patched"
            print(f"\n--- label={lab} ({tag}) ---")
            print(row["code"][:600])
    else:
        print("No before/after pair found after dedup.")

    print(f"\nSaved: {OUT_DIR / 'dataset.csv'}")


if __name__ == "__main__":
    main()