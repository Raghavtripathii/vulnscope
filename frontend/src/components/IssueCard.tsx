"use client";

import { useState } from "react";
import { post, ApiError } from "@/lib/api";
import type { Explanation, Issue } from "@/types/learning";

const SEVERITY_STYLES: Record<string, string> = {
  high: "border-red-500 bg-red-950 text-red-200",
  medium: "border-yellow-500 bg-yellow-950 text-yellow-200",
  low: "border-blue-500 bg-blue-950 text-blue-200",
};

interface IssueCardProps {
  scanId: number;
  issue: Issue;
}

export default function IssueCard({ scanId, issue }: IssueCardProps) {
  const [explanation, setExplanation] = useState<Explanation | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleExplain() {
    setLoading(true);
    setError(null);
    try {
      const result = await post<Explanation>("/explain", {
        scan_id: scanId,
        issue_index: issue.index,
      });
      setExplanation(result);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    } finally {
      setLoading(false);
    }
  }

  const style = SEVERITY_STYLES[issue.severity] ?? "border-neutral-600 bg-neutral-900 text-neutral-200";

  return (
    <div className="rounded-lg border border-neutral-700 bg-neutral-900">
      <div className={`rounded-t-lg border-b p-4 ${style}`}>
        <div className="flex items-center justify-between text-sm font-semibold uppercase tracking-wide">
          <span>{issue.label}</span>
          <span>{issue.severity}</span>
        </div>
        <p className="mt-1 text-xs opacity-80">
          {issue.line_number !== null ? `Line ${issue.line_number}` : "Line unknown"}
          {issue.cwe ? ` · ${issue.cwe}` : ""}
          {issue.owasp ? ` · ${issue.owasp}` : ""}
        </p>
        <p className="mt-1 text-xs opacity-80">Found by {issue.detectors.join(", ")}</p>
        {issue.code_snippet && (
          <pre className="mt-2 overflow-x-auto rounded bg-black/40 p-2 text-sm">{issue.code_snippet}</pre>
        )}
      </div>

      <div className="p-4">
        {!explanation && (
          <button
            onClick={handleExplain}
            disabled={loading}
            className="rounded bg-blue-600 px-3 py-1 text-sm font-semibold disabled:opacity-50"
          >
            {loading ? "Explaining..." : "Explain this issue"}
          </button>
        )}
        {error && <p className="mt-2 text-red-400">{error}</p>}

        {explanation && (
          <div className="flex flex-col gap-3">
            <div>
              <h3 className="text-sm font-semibold text-neutral-300">How it can be exploited</h3>
              <p className="mt-1 text-sm">{explanation.exploit_scenario}</p>
            </div>
            <div>
              <h3 className="text-sm font-semibold text-neutral-300">A safer version</h3>
              <pre className="mt-1 overflow-x-auto rounded bg-black/40 p-3 text-sm">{explanation.fixed_code_example}</pre>
            </div>
            <p className="text-xs text-neutral-400">
              {explanation.source === "llm"
                ? "AI-written explanation. The suggested fix was scanned again and no longer triggers a finding."
                : "Written explanation prepared in advance (no AI used)."}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}