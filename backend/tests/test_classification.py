import pytest

from app.explanations.classification import classify

XSS_TYPE = "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
STATIC_CODE_TYPE = "CWE-96: Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')"

OBSERVED = [
    ("bandit", "B608", "hardcoded_sql_expressions", "sql_injection", "CWE-89", "A05:2025 Injection"),
    ("semgrep", "python.django.security.injection.raw-html-format.raw-html-format", XSS_TYPE, "xss", "CWE-79", "A05:2025 Injection"),
    ("semgrep", "app.detectors.semgrep-rules.vulnscope-xss-html-sink", XSS_TYPE, "xss", "CWE-79", "A05:2025 Injection"),
    ("semgrep", "python.flask.security.audit.render-template-string.render-template-string", STATIC_CODE_TYPE, "other", "CWE-96", "A05:2025 Injection"),
    ("semgrep", "app.detectors.semgrep-rules.vulnscope-hardcoded-secret-python", "CWE-798: Use of Hard-coded Credentials", "hardcoded_secret", "CWE-798", "A07:2025 Authentication Failures"),
    ("bandit", "B105", "hardcoded_password_string", "hardcoded_secret", "CWE-259", "A07:2025 Authentication Failures"),
    ("semgrep", "python.jwt.security.unverified-jwt-decode.unverified-jwt-decode", "CWE-287: Improper Authentication", "broken_authentication", "CWE-287", "A07:2025 Authentication Failures"),
    ("semgrep", "javascript.jsonwebtoken.security.jwt-none-alg.jwt-none-alg", "CWE-327: Use of a Broken or Risky Cryptographic Algorithm", "other", "CWE-327", "A04:2025 Cryptographic Failures"),
    ("eslint", "security/detect-eval-with-expression", "security/detect-eval-with-expression", "other", "CWE-95", "A05:2025 Injection"),
    ("eslint", "security/detect-object-injection", "security/detect-object-injection", "other", None, None),
    ("bandit", "B404", "blacklist", "other", None, None),
    ("semgrep", "some.rule.without.cwe", "some.rule.without.cwe", "other", None, None),
]


@pytest.mark.parametrize("detector,rule_id,vulnerability_type,expected_class,expected_cwe,expected_owasp", OBSERVED)
def test_observed_findings_are_classified(detector, rule_id, vulnerability_type, expected_class, expected_cwe, expected_owasp):
    result = classify({"detector": detector, "rule_id": rule_id, "vulnerability_type": vulnerability_type})
    assert result.vulnerability_class == expected_class
    assert result.cwe == expected_cwe
    assert result.owasp == expected_owasp


def test_empty_finding_is_other():
    result = classify({})
    assert result.vulnerability_class == "other"
    assert result.cwe is None
    assert result.owasp is None