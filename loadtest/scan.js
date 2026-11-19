import http from "k6/http";
import { check, sleep } from "k6";

const BASE_URL = __ENV.BASE_URL || "http://host.docker.internal:8001";

const CODE = `import sqlite3

password = "hunter2hunter2"


def find_user(conn, name):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return cur.fetchone()
`;

export const options = {
  stages: [
    { duration: "20s", target: 2 },
    { duration: "40s", target: 5 },
    { duration: "20s", target: 0 },
  ],
  thresholds: {
    http_req_failed: ["rate<0.05"],
    checks: ["rate>0.95"],
  },
};

export default function () {
  const response = http.post(
    `${BASE_URL}/scan`,
    JSON.stringify({ code: CODE, language: "python" }),
    { headers: { "Content-Type": "application/json" }, timeout: "90s" }
  );

  check(response, {
    "status is 200": (r) => r.status === 200,
    "all detectors finished": (r) => r.status === 200 && r.json("complete") === true,
    "found the two planted issues": (r) => r.status === 200 && r.json("findings").length >= 2,
  });

  sleep(1);
}