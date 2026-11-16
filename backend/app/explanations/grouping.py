from dataclasses import dataclass

from app.explanations.classification import OTHER, classify

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}


@dataclass
class Issue:
    line_number: int | None
    vulnerability_class: str
    cwe: str | None
    owasp: str | None
    severity: str
    code_snippet: str | None
    evidence: list[dict]

    @property
    def detector_count(self) -> int:
        return len({item["detector"] for item in self.evidence})


def group_key(finding: dict, vulnerability_class: str, cwe: str | None) -> tuple:
    line = finding.get("line_number")
    if vulnerability_class != OTHER:
        return (line, vulnerability_class)
    if cwe:
        return (line, OTHER, cwe)
    return (line, OTHER, finding.get("detector"), finding.get("rule_id"))


def pick_snippet(evidence: list[dict]) -> str | None:
    snippets = [item.get("code_snippet") for item in evidence if item.get("code_snippet")]
    for snippet in snippets:
        if "\n" not in snippet:
            return snippet
    return snippets[0] if snippets else None


def group_findings(findings: list[dict]) -> list[Issue]:
    groups: dict[tuple, list[dict]] = {}
    labels: dict[tuple, object] = {}
    for finding in findings:
        label = classify(finding)
        key = group_key(finding, label.vulnerability_class, label.cwe)
        groups.setdefault(key, []).append(finding)
        labels.setdefault(key, label)

    issues = []
    for key, evidence in groups.items():
        label = labels[key]
        severity = max((item.get("severity", "medium") for item in evidence), key=lambda s: SEVERITY_RANK.get(s, 1))
        issues.append(
            Issue(
                line_number=key[0],
                vulnerability_class=label.vulnerability_class,
                cwe=label.cwe,
                owasp=label.owasp,
                severity=severity,
                code_snippet=pick_snippet(evidence),
                evidence=evidence,
            )
        )
    issues.sort(key=lambda issue: (issue.line_number or 0, issue.vulnerability_class, issue.cwe or ""))
    return issues