"""Extra vulnerable snippets for the grounding ablation.

Every secret below is a made-up placeholder in a credential-looking variable name.
None of them has the shape of a real provider key.
"""

NEW_SNIPPETS = [
    # --- Python: SQL injection ---
    dict(id="py-sqli-fstring", language="python", vulnerability_class="sql_injection", code='''def get_order(conn, order_id):
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM orders WHERE id = {order_id}")
    return cur.fetchall()
'''),
    dict(id="py-sqli-percent", language="python", vulnerability_class="sql_injection", code='''def find_product(cursor, name):
    query = "SELECT * FROM products WHERE name = '%s'" % name
    cursor.execute(query)
    return cursor.fetchall()
'''),
    dict(id="py-sqli-format", language="python", vulnerability_class="sql_injection", code='''def delete_user(cursor, user_id):
    cursor.execute("DELETE FROM users WHERE id = {}".format(user_id))
'''),
    dict(id="py-sqli-sqlalchemy", language="python", vulnerability_class="sql_injection", code='''from sqlalchemy import text


def search(session, term):
    return session.execute(text("SELECT * FROM posts WHERE title LIKE '%" + term + "%'")).fetchall()
'''),
    # --- Python: XSS ---
    dict(id="py-xss-flask-concat", language="python", vulnerability_class="xss", code='''from flask import Flask, request

app = Flask(__name__)


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return "<h1>Hello " + name + "</h1>"
'''),
    dict(id="py-xss-markup", language="python", vulnerability_class="xss", code='''from flask import request
from markupsafe import Markup


def banner():
    return Markup("<div class='banner'>" + request.args.get("msg", "") + "</div>")
'''),
    dict(id="py-xss-template-string", language="python", vulnerability_class="xss", code='''from flask import render_template_string, request


def profile():
    bio = request.form["bio"]
    return render_template_string("<p>" + bio + "</p>")
'''),
    # --- Python: hardcoded secrets ---
    dict(id="py-secret-api-key", language="python", vulnerability_class="hardcoded_secret", code='''import requests

api_key = "d41d8cd98f00b204e9800998ecf8427e"


def fetch_weather(city):
    return requests.get(
        "https://api.example.com/weather",
        params={"q": city, "key": api_key},
        timeout=10,
    ).json()
'''),
    dict(id="py-secret-db-password", language="python", vulnerability_class="hardcoded_secret", code='''import psycopg2

db_password = "S3cureP@ssw0rd!2024"


def connect():
    return psycopg2.connect(host="db.internal", user="app", password=db_password, dbname="shop")
'''),
    dict(id="py-secret-flask-key", language="python", vulnerability_class="hardcoded_secret", code='''from flask import Flask

app = Flask(__name__)
app.secret_key = "change-me-1234567890abcdef"
'''),
    # --- Python: broken authentication ---
    dict(id="py-auth-verify-false", language="python", vulnerability_class="broken_authentication", code='''import jwt


def current_user(token):
    claims = jwt.decode(token, options={"verify_signature": False})
    return claims["sub"]
'''),
    dict(id="py-auth-decode-no-key", language="python", vulnerability_class="broken_authentication", code='''import jwt


def read_token(token):
    return jwt.decode(token, verify=False)
'''),
    # --- JavaScript: SQL injection ---
    dict(id="js-sqli-template", language="javascript", vulnerability_class="sql_injection", code='''function getUser(db, id) {
  return db.query(`SELECT * FROM users WHERE id = ${id}`);
}
'''),
    dict(id="js-sqli-concat", language="javascript", vulnerability_class="sql_injection", code='''const mysql = require("mysql");

function search(connection, term, callback) {
  connection.query("SELECT * FROM items WHERE name = '" + term + "'", callback);
}
'''),
    # --- JavaScript: XSS ---
    dict(id="js-xss-innerhtml", language="javascript", vulnerability_class="xss", code='''function showMessage(text) {
  document.getElementById("out").innerHTML = text;
}
'''),
    dict(id="js-xss-document-write", language="javascript", vulnerability_class="xss", code='''function render(name) {
  document.write("<h2>Welcome " + name + "</h2>");
}
'''),
    dict(id="js-xss-express-send", language="javascript", vulnerability_class="xss", code='''const express = require("express");
const app = express();

app.get("/greet", (req, res) => {
  res.send("<h1>Hello " + req.query.name + "</h1>");
});
'''),
    dict(id="js-xss-insert-adjacent", language="javascript", vulnerability_class="xss", code='''function addRow(table, cells) {
  table.insertAdjacentHTML("beforeend", "<tr><td>" + cells + "</td></tr>");
}
'''),
    # --- JavaScript: hardcoded secrets ---
    dict(id="js-secret-api-key", language="javascript", vulnerability_class="hardcoded_secret", code='''const apiKey = "d41d8cd98f00b204e9800998ecf8427e";

async function load(city) {
  const response = await fetch(`https://api.example.com/weather?q=${city}&key=${apiKey}`);
  return response.json();
}
'''),
    dict(id="js-secret-password-config", language="javascript", vulnerability_class="hardcoded_secret", code='''const config = {
  host: "db.internal",
  user: "app",
  password: "S3cureP@ssw0rd!2024",
};

module.exports = config;
'''),
    dict(id="js-secret-jwt-sign", language="javascript", vulnerability_class="hardcoded_secret", code='''const jwt = require("jsonwebtoken");

const secret = "change-me-1234567890abcdef";

function issue(userId) {
  return jwt.sign({ sub: userId }, secret);
}
'''),
    # --- JavaScript: broken authentication ---
    dict(id="js-auth-jwt-decode", language="javascript", vulnerability_class="broken_authentication", code='''const jwt = require("jsonwebtoken");

function currentUser(token) {
  const claims = jwt.decode(token);
  return claims.sub;
}
'''),
]