from pathlib import Path

import pandas as pd

RES = Path("results")
PROC = Path("data/processed")

JS_FOREIGN = ("def ", "fn ", "func ", "bool ", "void ", "int ", "<?php", "public function", "private function", "#include")
PY_FOREIGN = ("function ", "const ", "var ", "let ", "<?php", "#include", "public function", "private function")
PY_STARTS = ("def ", "async def ", "class ", "@")
JS_BAD_FIRST = list("})],;.`")


def flag_rows(frame):
    code = frame["code"].fillna("")
    stripped = code.str.lstrip()
    longest = code.apply(lambda c: max((len(line) for line in c.splitlines()), default=0))
    line_count = code.str.count("\n") + 1
    is_python = frame["lang"] == "python"

    out = pd.DataFrame(index=frame.index)
    out["minified"] = (longest > 400) | ((line_count == 1) & (code.str.len() > 300))
    out["wrong_language"] = (~is_python & stripped.str.startswith(JS_FOREIGN)) | (
        is_python & stripped.str.startswith(PY_FOREIGN)
    )
    python_fragment = is_python & ~stripped.str.startswith(PY_STARTS)
    js_fragment = ~is_python & stripped.str[:1].isin(JS_BAD_FIRST)
    out["fragment"] = python_fragment | js_fragment
    out["suspect"] = out.any(axis=1)
    return out


def pair_length_direction(frame):
    key = frame["file_change_id"].astype(str) + "|" + frame["name"].astype(str)
    sizes = frame.groupby(key)["label"].agg(["size", "sum"])
    valid = sizes[(sizes["size"] == 2) & (sizes["sum"] == 1)].index
    paired = frame[key.isin(valid)].copy()
    paired["key"] = key[paired.index]
    paired["length"] = paired["code"].str.len()
    vulnerable = paired[paired["label"] == 1].set_index("key")["length"].rename("vulnerable")
    fixed = paired[paired["label"] == 0].set_index("key")["length"].rename("fixed")
    both = pd.concat([vulnerable, fixed], axis=1).dropna()
    return len(both), (both["vulnerable"] < both["fixed"]).mean(), (both["vulnerable"] == both["fixed"]).mean()


def pct(value):
    return f"{value * 100:.1f}%"


lines = ["# Dataset audit (heuristic checks, not ground truth)", ""]
lines.append("Flags are simple text rules. minified: a line over 400 characters, or one line over 300 characters. wrong_language: code starts like another language. fragment: Python not starting with def, async def, class or a decorator; JavaScript starting with a closing bracket, comma, dot or backtick. suspect: any of the three.")
lines.append("")
lines.append("| split | language | rows | minified | wrong language | fragment | suspect | vulnerable rate in suspect rows | vulnerable rate in other rows |")
lines.append("|---|---|---|---|---|---|---|---|---|")

frames = {}
for split in ["train", "test"]:
    frame = pd.read_csv(PROC / f"{split}.csv")
    frames[split] = frame
    flags = flag_rows(frame)
    for lang in ["python", "javascript"]:
        mask = (frame["lang"] == lang).values
        sub = frame[mask]
        sub_flags = flags[mask]
        suspect = sub_flags["suspect"].values
        label = sub["label"].values
        rate_suspect = label[suspect].mean() if suspect.any() else float("nan")
        rate_other = label[~suspect].mean() if (~suspect).any() else float("nan")
        lines.append(
            f"| {split} | {lang} | {len(sub)} | {pct(sub_flags['minified'].mean())} | "
            f"{pct(sub_flags['wrong_language'].mean())} | {pct(sub_flags['fragment'].mean())} | "
            f"{pct(suspect.mean())} ({int(suspect.sum())}) | {pct(rate_suspect)} | {pct(rate_other)} |"
        )

lines.append("")
lines.append("## Before-fix vs after-fix pairs: is the vulnerable version shorter")
lines.append("")
lines.append("| split | pairs | vulnerable shorter than fixed | same length |")
lines.append("|---|---|---|---|")
for split, frame in frames.items():
    n_pairs, shorter, same = pair_length_direction(frame)
    lines.append(f"| {split} | {n_pairs} | {pct(shorter)} | {pct(same)} |")

text = "\n".join(lines)
(RES / "dataset_audit.md").write_text(text, encoding="utf-8")
print(text)