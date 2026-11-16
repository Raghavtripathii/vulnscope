import re

QUOTED_LITERAL = re.compile(r"\"[^\"\n]*\"|'[^'\n]*'|`[^`\n]*`")
TOKEN_LIKE = re.compile(r"[A-Za-z0-9_\-+/=]{32,}")

REDACTED = "<REDACTED>"


def mask_literal(match: re.Match) -> str:
    text = match.group(0)
    return text[0] + REDACTED + text[-1]


def redact(text: str | None, mask_all_strings: bool = False) -> str | None:
    if text is None:
        return None
    result = text
    if mask_all_strings:
        result = QUOTED_LITERAL.sub(mask_literal, result)
    return TOKEN_LIKE.sub(REDACTED, result)