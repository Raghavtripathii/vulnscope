from app.explanations.redaction import REDACTED, redact


def test_none_stays_none():
    assert redact(None) is None


def test_quoted_strings_are_masked_when_requested():
    assert redact('api_key = "sk_live_abcdef123456"', mask_all_strings=True) == f'api_key = "{REDACTED}"'


def test_single_and_backtick_quotes_are_masked():
    assert redact("token = 'abc12345'", mask_all_strings=True) == f"token = '{REDACTED}'"
    assert redact("const t = `abc12345`;", mask_all_strings=True) == f"const t = `{REDACTED}`;"


def test_a_string_containing_another_quote_type_is_masked():
    assert redact("""pw = "it's-a-secret" """.strip(), mask_all_strings=True) == f'pw = "{REDACTED}"'


def test_strings_are_kept_when_not_requested():
    assert redact('cur.execute("SELECT 1")') == 'cur.execute("SELECT 1")'


def test_long_token_like_values_are_masked_everywhere():
    token = "a" * 40
    assert REDACTED in redact(f"x = foo({token})")
    assert token not in redact(f"x = foo({token})")


def test_short_identifiers_are_kept():
    assert redact("render_template_string(name)") == "render_template_string(name)"