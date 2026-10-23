"use client";

import { useState } from "react";
import dynamic from "next/dynamic";
import FindingsList from "@/components/FindingsList";
import { post, ApiError } from "@/lib/api";
import type { Language, ScanResponse } from "@/types/scan";

const CodeEditor = dynamic(() => import("@/components/CodeEditor"), { ssr: false });

const DEFAULT_CODE: Record<Language, string> = {
  python: 'password = "hunter2"\nprint(password)\n',
  javascript: 'const password = "hunter2";\nconsole.log(password);\n',
};

export default function ScanPage() {
  const [language, setLanguage] = useState<Language>("python");
  const [code, setCode] = useState(DEFAULT_CODE.python);
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function handleLanguageChange(next: Language) {
    setLanguage(next);
    setCode(DEFAULT_CODE[next]);
    setResult(null);
  }

  async function handleScan() {
    setLoading(true);
    setError(null);
    try {
      const response = await post<ScanResponse>("/scan", { code, language });
      setResult(response);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    } finally {
      setLoading(false);
    }
  }

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

      <div>
        <h2 className="mb-3 text-lg font-semibold">Findings</h2>
        <FindingsList findings={result?.findings ?? []} />
      </div>
    </div>
  );
}