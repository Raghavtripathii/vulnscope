from app.explanations.grouping import group_findings

XSS_TYPE = "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
STATIC_CODE_TYPE = "CWE-96: Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')"
SECRET_TYPE = "CWE-798: Use of Hard-coded Credentials"


def finding(**overrides):
    base = {
        "detector": "semgrep",
        "rule_id": "some.rule",
        "vulnerability_type": "some.rule",
        "severity": "medium",
        "line_number": 1,
        "message": "",
        "code_snippet": None,
    }
    base.update(overrides)
    return base


def test_empty_input_gives_no_issues():
    assert group_findings([]) == []


def test_same_class_on_same_line_becomes_one_issue():
    findings = [
        finding(rule_id="python.django.security.injection.raw-html-format.raw-html-format", vulnerability_type=XSS_TYPE, line_number=8),
        finding(rule_id="python.flask.security.injection.raw-html-concat.raw-html-format", vulnerability_type=XSS_TYPE, line_number=8),
        finding(rule_id="python.flask.security.audit.render-template-string.render-template-string", vulnerability_type=STATIC_CODE_TYPE, line_number=8),
    ]
    issues = group_findings(findings)
    assert len(issues) == 2
    xss = next(issue for issue in issues if issue.vulnerability_class == "xss")
    assert len(xss.evidence) == 2
    other = next(issue for issue in issues if issue.vulnerability_class == "other")
    assert other.cwe == "CWE-96"


def test_two_detectors_agreeing_on_a_line_are_counted():
    findings = [
        finding(rule_id="vulnscope-hardcoded-secret-python", vulnerability_type=SECRET_TYPE, line_number=1, code_snippet='api_key = "sk_live_abcdef123456"'),
        finding(rule_id="vulnscope-hardcoded-secret-python", vulnerability_type=SECRET_TYPE, line_number=2, code_snippet='password = "supersecret123"'),
        finding(detector="bandit", rule_id="B105", vulnerability_type="hardcoded_password_string", line_number=2, code_snippet='1 api_key = "x"\n2 password = "supersecret123"'),
    ]
    issues = group_findings(findings)
    assert [issue.line_number for issue in issues] == [1, 2]
    assert issues[0].detector_count == 1
    assert issues[1].detector_count == 2
    assert issues[1].code_snippet == 'password = "supersecret123"'


def test_highest_severity_wins():
    findings = [
        finding(vulnerability_type=XSS_TYPE, severity="low"),
        finding(rule_id="other.rule", vulnerability_type=XSS_TYPE, severity="high"),
    ]
    assert group_findings(findings)[0].severity == "high"


def test_unclassified_findings_stay_separate_unless_same_rule():
    findings = [
        finding(rule_id="rule.one"),
        finding(rule_id="rule.two"),
        finding(rule_id="rule.one"),
    ]
    issues = group_findings(findings)
    assert len(issues) == 2


def test_issues_are_ordered_by_line():
    findings = [
        finding(vulnerability_type=XSS_TYPE, line_number=9),
        finding(vulnerability_type=SECRET_TYPE, line_number=3),
    ]
    assert [issue.line_number for issue in group_findings(findings)] == [3, 9]