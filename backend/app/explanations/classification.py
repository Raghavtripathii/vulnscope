import re
from dataclasses import dataclass

CWE_PATTERN = re.compile(r"CWE-(\d+)")

SQL_INJECTION = "sql_injection"
XSS = "xss"
HARDCODED_SECRET = "hardcoded_secret"
BROKEN_AUTHENTICATION = "broken_authentication"
OTHER = "other"

CLASS_BY_CWE = {
    "89": SQL_INJECTION,
    "79": XSS,
    "798": HARDCODED_SECRET,
    "259": HARDCODED_SECRET,
    "287": BROKEN_AUTHENTICATION,
    "306": BROKEN_AUTHENTICATION,
    "307": BROKEN_AUTHENTICATION,
    "384": BROKEN_AUTHENTICATION,
    "521": BROKEN_AUTHENTICATION,
    "613": BROKEN_AUTHENTICATION,
}

BANDIT_CWE = {
    "B608": "89",
    "B105": "259",
    "B106": "259",
    "B107": "259",
}

ESLINT_CWE = {
    "security/detect-eval-with-expression": "95",
    "security/detect-child-process": "78",
}

OWASP_A05_INJECTION = "A05:2025 Injection"
OWASP_A07_AUTHENTICATION = "A07:2025 Authentication Failures"
OWASP_A04_CRYPTOGRAPHIC = "A04:2025 Cryptographic Failures"

OWASP_CWES = {
    OWASP_A05_INJECTION: {
        "20", "74", "76", "77", "78", "79", "80", "83", "86", "88", "89", "90", "91", "93", "94", "95",
        "96", "97", "98", "99", "103", "104", "112", "113", "114", "115", "116", "129", "159", "470",
        "493", "500", "564", "610", "643", "644", "917",
    },
    OWASP_A07_AUTHENTICATION: {
        "258", "259", "287", "288", "289", "290", "291", "293", "294", "295", "297", "298", "299", "300",
        "302", "303", "304", "305", "306", "307", "308", "309", "346", "350", "384", "521", "613", "620",
        "640", "798", "940", "941", "1390", "1391", "1392", "1393",
    },
    OWASP_A04_CRYPTOGRAPHIC: {
        "261", "296", "319", "320", "321", "322", "323", "324", "325", "326", "327", "328", "329", "330",
        "331", "332", "334", "335", "336", "337", "338", "340", "342", "347", "523", "757", "759", "760",
        "780", "916", "1240", "1241",
    },
}


@dataclass(frozen=True)
class Classification:
    vulnerability_class: str
    cwe: str | None
    owasp: str | None


def extract_cwe(finding: dict) -> str | None:
    detector = finding.get("detector")
    if detector == "bandit":
        return BANDIT_CWE.get(finding.get("rule_id"))
    if detector == "eslint":
        return ESLINT_CWE.get(finding.get("rule_id"))
    match = CWE_PATTERN.search(finding.get("vulnerability_type") or "")
    return match.group(1) if match else None


def owasp_for(cwe: str | None) -> str | None:
    if cwe is None:
        return None
    for category, cwes in OWASP_CWES.items():
        if cwe in cwes:
            return category
    return None


def classify(finding: dict) -> Classification:
    cwe = extract_cwe(finding)
    return Classification(
        vulnerability_class=CLASS_BY_CWE.get(cwe, OTHER) if cwe else OTHER,
        cwe=f"CWE-{cwe}" if cwe else None,
        owasp=owasp_for(cwe),
    )