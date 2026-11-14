import pandas as pd

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


def pair_keys(frame):
    return frame["file_change_id"].astype(str) + "|" + frame["name"].astype(str)