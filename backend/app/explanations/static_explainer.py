from app.explanations.classification import OTHER
from app.explanations.grouping import Issue
from app.explanations.schema import CLASS_LABELS, Explanation

STATIC_EXPLANATIONS = {
    "sql_injection": {
        "exploit_scenario": (
            "The query is built by pasting a value straight into the SQL text. An attacker types SQL into that value "
            "instead of a normal one. For example, entering ' OR '1'='1 as the name makes the WHERE condition always "
            "true, so the query returns every user. Stronger inputs can read other tables or change data."
        ),
        "fixed_code_example": {
            "python": (
                "def find_user(cur, name):\n"
                "    # \"?\" works for sqlite3; psycopg and MySQL drivers use %s\n"
                "    cur.execute(\"SELECT * FROM users WHERE name = ?\", (name,))\n"
                "    return cur.fetchall()\n"
            ),
            "javascript": (
                "function findUser(db, name) {\n"
                "  // \"?\" works for mysql2; the pg package uses $1, $2 ...\n"
                "  return db.query(\"SELECT * FROM users WHERE name = ?\", [name]);\n"
                "}\n"
            ),
        },
    },
    "xss": {
        "exploit_scenario": (
            "A value that can come from a user is written into the page as HTML. An attacker supplies markup such as "
            "<img src=x onerror=...> or a <script> tag. It then runs in other visitors' browsers, where it can read "
            "their session data or act as them."
        ),
        "fixed_code_example": {
            "python": (
                "@app.route(\"/\")\n"
                "def hello():\n"
                "    name = request.args.get(\"name\", \"\")\n"
                "    return render_template(\"hello.html\", name=name)\n"
            ),
            "javascript": (
                "const out = document.getElementById(\"out\");\n"
                "out.textContent = userInput;\n"
            ),
        },
    },
    "hardcoded_secret": {
        "exploit_scenario": (
            "The secret is written in the source code. Anyone who can see the code, including anyone with repository "
            "access or a leaked copy, can read it and use it as you. A key committed to git stays in the history even "
            "after you delete the line, so the key must also be revoked and replaced."
        ),
        "fixed_code_example": {
            "python": (
                "import os\n"
                "\n"
                "api_key = os.environ[\"API_KEY\"]\n"
            ),
            "javascript": (
                "const apiKey = process.env.API_KEY;\n"
            ),
        },
    },
    "broken_authentication": {
        "exploit_scenario": (
            "The code accepts a login or token without checking it properly, for example decoding a JWT without "
            "verifying its signature. An attacker can then forge a token that claims to be any user, such as an "
            "administrator, and the application will believe it."
        ),
        "fixed_code_example": {
            "python": (
                "import jwt\n"
                "\n"
                "def read_token(token, secret):\n"
                "    return jwt.decode(token, secret, algorithms=[\"HS256\"])\n"
            ),
            "javascript": (
                "const jwt = require(\"jsonwebtoken\");\n"
                "\n"
                "function readToken(token) {\n"
                "  return jwt.verify(token, process.env.JWT_SECRET, { algorithms: [\"HS256\"] });\n"
                "}\n"
            ),
        },
    },
}

GENERIC_EXPLOIT_SCENARIO = (
    "The analysis tools marked this line as risky for the reason given in their message. Treat any value that comes "
    "from outside your program, such as user input, files or the network, as untrusted. An attacker who controls "
    "that value may be able to change what this line does."
)

GENERIC_FIXED_EXAMPLE = (
    "There is no ready-made code example for this kind of finding. Read the detector's message, validate or escape "
    "the untrusted value before using it here, then scan again to check the finding is gone."
)


class StaticExplainer:
    def explain(self, issue: Issue, language: str) -> Explanation:
        entry = STATIC_EXPLANATIONS.get(issue.vulnerability_class)
        label = CLASS_LABELS.get(issue.vulnerability_class, CLASS_LABELS[OTHER])

        if entry is None:
            if issue.cwe:
                label = f"{label} ({issue.cwe})"
            return Explanation(
                vulnerability_type=label,
                exploit_scenario=GENERIC_EXPLOIT_SCENARIO,
                fixed_code_example=GENERIC_FIXED_EXAMPLE,
                owasp_mapping=issue.owasp,
                source="static",
            )

        examples = entry["fixed_code_example"]
        example = examples.get(language) or next(iter(examples.values()))
        return Explanation(
            vulnerability_type=label,
            exploit_scenario=entry["exploit_scenario"],
            fixed_code_example=example,
            owasp_mapping=issue.owasp,
            source="static",
        )