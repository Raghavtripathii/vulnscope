"use client";

import { useState } from "react";
import dynamic from "next/dynamic";
import Link from "next/link";
import FindingsList from "@/components/FindingsList";
import IssueCard from "@/components/IssueCard";
import { get, post, ApiError } from "@/lib/api";
import type { Issue } from "@/types/learning";
import type { Language, ScanResponse } from "@/types/scan";

const CodeEditor = dynamic(() => import("@/components/CodeEditor"), { ssr: false });

const DEFAULT_CODE: Record<Language, string> = {
  python:
    'import sqlite3\n\npassword = "hunter2hunter2"\n\n\ndef find_user(conn, name):\n    cur = conn.cursor()\n    cur.execute("SELECT * FROM users WHERE name = \'" + name + "\'")\n    return cur.fetchone()\n',
  javascript:
    'const password = "hunter2hunter2";\n\nfunction show(el, name) {\n  el.innerHTML = "Hello, " + name;\n}\n',
};

export default function ScanPage() {
  const [language, setLanguage] = useState<Language>("python");
  const [code, setCode] = useState(DEFAULT_CODE.python);
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [issues, setIssues] = useState<Issue[]>([]);
  const [needLogin, setNeedLogin] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function handleLanguageChange(next: Language) {
    setLanguage(next);
    setCode(DEFAULT_CODE[next]);
    setResult(null);
    setIssues([]);
    setNeedLogin(false);
  }

  async function handleScan() {
    setLoading(true);
    setError(null);
    setIssues([]);
    setNeedLogin(false);
    try {
      const response = await post<ScanResponse>("/scan", { code, language });
      setResult(response);
      try {
        setIssues(await get<Issue[]>(`/scans/${response.scan_id}/issues`));
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) {
          setNeedLogin(true);
        } else {
          setError(err instanceof ApiError ? err.message : "Could not load the issue list");
        }
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    } finally {
      setLoading(false);
    }
  }

  const unfinished = result
    ? Object.entries(result.detectors).filter(([, status]) => status !== "ok")
    : [];

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Scan your code</h1>
        <div className="flex gap-2">
          <button
            onClick={() => handleLanguageChange("python")}
            className={`rounded px-3 py-1 text-sm ${language === "python" ? "bg-blue-600" : "bg-neutral-800"}`}
          >
            Python
          </button>
          <button
            onClick={() => handleLanguageChange("javascript")}
            className={`rounded px-3 py-1 text-sm ${language === "javascript" ? "bg-blue-600" : "bg-neutral-800"}`}
          >
            JavaScript
          </button>
        </div>
      </div>

      <CodeEditor value={code} language={language} onChange={setCode} />

      <button
        onClick={handleScan}
        disabled={loading}
        className="w-fit rounded bg-blue-600 px-4 py-2 font-semibold disabled:opacity-50"
      >
        {loading ? "Scanning..." : "Scan Code"}
      </button>

      {error && <p className="text-red-400">{error}</p>}

      {unfinished.length > 0 && (
        <p className="rounded border border-yellow-600 bg-yellow-950 p-3 text-sm text-yellow-200">
          Some checks did not finish ({unfinished.map(([name, status]) => `${name}: ${status}`).join(", ")}).
          This scan may have missed issues. Try scanning again.
        </p>
      )}

      {result && needLogin && (
        <p className="rounded border border-neutral-700 bg-neutral-900 p-3 text-sm">
          <Link href="/login" className="underline">
            Log in
          </Link>{" "}
          or{" "}
          <Link href="/register" className="underline">
            register
          </Link>{" "}
          and scan again to get explanations, practice exercises and your progress.
        </p>
      )}

      {result && issues.length > 0 && (
        <div>
          <h2 className="mb-3 text-lg font-semibold">Issues ({issues.length})</h2>
          <div className="flex flex-col gap-4">
            {issues.map((issue) => (
              <IssueCard key={issue.index} scanId={result.scan_id} issue={issue} />
            ))}
          </div>
        </div>
      )}

      {result && !needLogin && issues.length === 0 && result.findings.length === 0 && unfinished.length === 0 && (
        <p className="text-neutral-300">No issues found by the detectors.</p>
      )}

      <details>
        <summary className="cursor-pointer text-sm text-neutral-400">Raw detector output</summary>
        <div className="mt-3">
          <FindingsList findings={result?.findings ?? []} />
        </div>
      </details>
    </div>
  );
}