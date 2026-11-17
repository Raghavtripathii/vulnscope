from dataclasses import dataclass


@dataclass(frozen=True)
class Exercise:
    id: str
    vulnerability_class: str
    language: str
    title: str
    scenario: str
    vulnerable_code: str
    hint: str
    reference_fix: str


EXERCISES = [
    Exercise(
        id="sqli-py-login",
        vulnerability_class="sql_injection",
        language="python",
        title="Look up a user by username",
        scenario="A login page passes the typed username straight into this function. An attacker types a quote followed by SQL as the username. Rewrite the query so typed text can never change the meaning of the SQL.",
        vulnerable_code='''import sqlite3


def find_user(conn, username):
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE username = '" + username + "'")
    return cur.fetchone()
''',
        hint="Keep the SQL text fixed and pass the value separately as a query parameter.",
        reference_fix='''import sqlite3


def find_user(conn, username):
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE username = ?", (username,))
    return cur.fetchone()
''',
    ),
    Exercise(
        id="sqli-py-search",
        vulnerability_class="sql_injection",
        language="python",
        title="Search products by name",
        scenario="A shop search box sends the typed term to this function. An f-string looks tidy, but it still lets the visitor write their own SQL. Fix it while keeping the partial-match behaviour.",
        vulnerable_code='''def search_products(cur, term):
    cur.execute(f"SELECT name, price FROM products WHERE name LIKE '%{term}%'")
    return cur.fetchall()
''',
        hint="The percent signs belong inside the parameter value, not inside the SQL text.",
        reference_fix='''def search_products(cur, term):
    cur.execute("SELECT name, price FROM products WHERE name LIKE ?", ("%" + term + "%",))
    return cur.fetchall()
''',
    ),
    Exercise(
        id="sqli-js-delete",
        vulnerability_class="sql_injection",
        language="javascript",
        title="Delete a comment by id",
        scenario="An Express route reads a comment id from the URL and calls this function. Ids look like numbers, but the value is still text the visitor controls. Make the query safe.",
        vulnerable_code='''function deleteComment(db, commentId) {
  return db.run("DELETE FROM comments WHERE id = " + commentId);
}
''',
        hint="Use a placeholder in the SQL and pass the id in an array as the second argument.",
        reference_fix='''function deleteComment(db, commentId) {
  return db.run("DELETE FROM comments WHERE id = ?", [commentId]);
}
''',
    ),
    Exercise(
        id="xss-js-greeting",
        vulnerability_class="xss",
        language="javascript",
        title="Greet the visitor by name",
        scenario="A page reads the name from the address bar (?name=...) and shows a greeting. An attacker shares a link whose name contains HTML with a script. Show the name as plain text.",
        vulnerable_code='''const params = new URLSearchParams(window.location.search);
const name = params.get("name");
document.getElementById("welcome").innerHTML = "Hello, " + name;
''',
        hint="Some DOM properties treat the value as HTML, others as plain text.",
        reference_fix='''const params = new URLSearchParams(window.location.search);
const name = params.get("name");
document.getElementById("welcome").textContent = "Hello, " + name;
''',
    ),
    Exercise(
        id="xss-js-comment",
        vulnerability_class="xss",
        language="javascript",
        title="Show a comment under a post",
        scenario="Comments written by any visitor are added to the page with this function. A comment containing an img tag with an onerror handler runs code in every reader's browser. Build the element safely instead of gluing HTML together.",
        vulnerable_code='''function renderComment(container, comment) {
  container.insertAdjacentHTML("beforeend", "<p>" + comment.text + "</p>");
}
''',
        hint="Create the paragraph element, set its text, then append it.",
        reference_fix='''function renderComment(container, comment) {
  const paragraph = document.createElement("p");
  paragraph.textContent = comment.text;
  container.appendChild(paragraph);
}
''',
    ),
    Exercise(
        id="xss-py-flask",
        vulnerability_class="xss",
        language="python",
        title="Echo a name back in a Flask page",
        scenario="This Flask route builds an HTML page by adding the visitor's name to a string. A name containing a script tag is sent back to the browser unchanged. Move the HTML into a template and let Flask build the page. The template file hello.html would contain <h1>Hello, {{ name }}</h1>.",
        vulnerable_code='''from flask import Flask, request

app = Flask(__name__)


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return "<h1>Hello, " + name + "</h1>"
''',
        hint="Flask's template engine escapes values automatically. Call render_template instead of building the string.",
        reference_fix='''from flask import Flask, render_template, request

app = Flask(__name__)


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return render_template("hello.html", name=name)
''',
    ),
    Exercise(
        id="secret-py-api-key",
        vulnerability_class="hardcoded_secret",
        language="python",
        title="Remove the payment key from the source",
        scenario="This file is in a Git repository that classmates can read. Anyone who sees it can charge the payment account. Load the key from the environment instead of writing it in the code.",
        vulnerable_code='''import requests

PAYMENT_API_KEY = "demo_payments_key_9f8e7d6c5b4a39"


def charge(amount):
    return requests.post(
        "https://payments.example.com/charge",
        headers={"Authorization": "Bearer " + PAYMENT_API_KEY},
        json={"amount": amount},
        timeout=10,
    )
''',
        hint="Read the value from an environment variable with the os module.",
        reference_fix='''import os

import requests

PAYMENT_API_KEY = os.environ["PAYMENT_API_KEY"]


def charge(amount):
    return requests.post(
        "https://payments.example.com/charge",
        headers={"Authorization": "Bearer " + PAYMENT_API_KEY},
        json={"amount": amount},
        timeout=10,
    )
''',
    ),
    Exercise(
        id="secret-py-db-password",
        vulnerability_class="hardcoded_secret",
        language="python",
        title="Remove the database password",
        scenario="The database password is typed into the connection call. It also ends up in every copy of the repository and every backup of it. Fix it so the password is not in the file.",
        vulnerable_code='''import psycopg


def connect():
    return psycopg.connect(host="db.internal", user="app", password="Sup3rS3cret!2024")
''',
        hint="Pass an environment variable as the password argument.",
        reference_fix='''import os

import psycopg


def connect():
    return psycopg.connect(host="db.internal", user="app", password=os.environ["DB_PASSWORD"])
''',
    ),
    Exercise(
        id="secret-js-admin-token",
        vulnerability_class="hardcoded_secret",
        language="javascript",
        title="Remove the admin token",
        scenario="This Express app protects its admin page with a token written in the file. Anyone who reads the code or the repository can open the admin page. Read the token from the environment instead.",
        vulnerable_code='''const express = require("express");
const app = express();

const adminToken = "demo-admin-token-48213";

app.get("/admin", (req, res) => {
  if (req.headers["x-admin-token"] === adminToken) {
    res.send("welcome");
  } else {
    res.status(403).send("forbidden");
  }
});
''',
        hint="In Node.js, environment variables are available on process.env.",
        reference_fix='''const express = require("express");
const app = express();

const adminToken = process.env.ADMIN_TOKEN;

app.get("/admin", (req, res) => {
  if (req.headers["x-admin-token"] === adminToken) {
    res.send("welcome");
  } else {
    res.status(403).send("forbidden");
  }
});
''',
    ),
    Exercise(
        id="auth-py-jwt-unverified",
        vulnerability_class="broken_authentication",
        language="python",
        title="Trust only signed login tokens",
        scenario="This function reads the user id from a login token without checking the signature. Anyone can forge a token that says they are another user, such as the admin. Verify the token before trusting what is inside it.",
        vulnerable_code='''import jwt


def current_user(token):
    claims = jwt.decode(token, options={"verify_signature": False})
    return claims["sub"]
''',
        hint="Pass the secret key and the allowed algorithm so the library checks the signature.",
        reference_fix='''import os

import jwt


def current_user(token):
    claims = jwt.decode(token, os.environ["JWT_SECRET"], algorithms=["HS256"])
    return claims["sub"]
''',
    ),
    Exercise(
        id="auth-js-jwt-unverified",
        vulnerability_class="broken_authentication",
        language="javascript",
        title="Verify the login token in the middleware",
        scenario="This Express middleware reads the user's role from a token using decode, which never checks the signature. A visitor can edit the token to say they are an admin. Use the function that verifies the signature.",
        vulnerable_code='''const jwt = require("jsonwebtoken");

function requireAdmin(req, res, next) {
  const claims = jwt.decode(req.headers.authorization);
  if (claims && claims.role === "admin") {
    return next();
  }
  return res.status(403).send("forbidden");
}
''',
        hint="The jsonwebtoken library has one function that decodes only and one that also verifies.",
        reference_fix='''const jwt = require("jsonwebtoken");

function requireAdmin(req, res, next) {
  let claims;
  try {
    claims = jwt.verify(req.headers.authorization, process.env.JWT_SECRET, { algorithms: ["HS256"] });
  } catch (error) {
    return res.status(401).send("invalid token");
  }
  if (claims.role === "admin") {
    return next();
  }
  return res.status(403).send("forbidden");
}
''',
    ),
]


def get_exercise(exercise_id: str) -> Exercise | None:
    for exercise in EXERCISES:
        if exercise.id == exercise_id:
            return exercise
    return None


def exercises_for(vulnerability_class: str | None = None) -> list[Exercise]:
    if vulnerability_class is None:
        return list(EXERCISES)
    return [item for item in EXERCISES if item.vulnerability_class == vulnerability_class]