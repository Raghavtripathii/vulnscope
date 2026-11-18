"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ApiError, get } from "@/lib/api";
import type { MyScan, MyStats } from "@/types/learning";

const CLASS_LABELS: Record<string, string> = {
  sql_injection: "SQL injection",
  xss: "Cross-site scripting (XSS)",
  hardcoded_secret: "Hardcoded secret",
  broken_authentication: "Broken authentication",
};

function labelFor(cls: string): string {
  return CLASS_LABELS[cls] ?? cls.replace(/_/g, " ");
}

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export default function DashboardPage() {
  const [stats, setStats] = useState<MyStats | null>(null);
  const [scans, setScans] = useState<MyScan[]>([]);
  const [needsLogin, setNeedsLogin] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    async function load() {
      try {
        const [s, list] = await Promise.all([
          get<MyStats>("/me/stats"),
          get<MyScan[]>("/me/scans?limit=20"),
        ]);
        setStats(s);
        setScans(list);
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) {
          setNeedsLogin(true);
        } else {
          setError(err instanceof ApiError ? err.message : "Could not load your dashboard");
        }
      } finally {
        setLoaded(true);
      }
    }
    load();
  }, []);

  if (!loaded) return <p className="text-neutral-400">Loading your dashboard…</p>;

  if (needsLogin) {
    return (
      <div>
        <h1 className="text-2xl font-bold">Your dashboard</h1>
        <p className="mt-4 text-neutral-300">
          Please{" "}
          <Link href="/login" className="underline">
            log in
          </Link>{" "}
          to see your scan history.
        </p>
      </div>
    );
  }

  if (error || !stats) {
    return (
      <div>
        <h1 className="text-2xl font-bold">Your dashboard</h1>
        <p className="mt-4 rounded border border-red-500 bg-red-950 p-3 text-red-200">
          {error ?? "Could not load your dashboard"}
        </p>
      </div>
    );
  }

  const classEntries = Object.entries(stats.issues_by_class).sort((a, b) => b[1] - a[1]);
  const maxCount = Math.max(1, ...classEntries.map(([, n]) => n));

  return (
    <div className="space-y-8">
      <h1 className="text-2xl font-bold">Your dashboard</h1>

      <div className="grid grid-cols-2 gap-4">
        <div className="rounded-lg border border-neutral-700 bg-neutral-900 p-4">
          <p className="text-sm text-neutral-400">Scans</p>
          <p className="text-3xl font-bold">{stats.scans_count}</p>
        </div>
        <div className="rounded-lg border border-neutral-700 bg-neutral-900 p-4">
          <p className="text-sm text-neutral-400">Issues found</p>
          <p className="text-3xl font-bold">{stats.issues_total}</p>
        </div>
      </div>

      {stats.scans_count === 0 && (
        <p className="text-neutral-300">
          You have no scans yet.{" "}
          <Link href="/" className="underline">
            Scan some code
          </Link>{" "}
          and your history will appear here.
        </p>
      )}

      {stats.repeated_mistakes.length > 0 && (
        <section>
          <h2 className="text-lg font-semibold">Mistakes you keep repeating</h2>
          <p className="mt-1 text-sm text-neutral-400">
            These problem types showed up in two or more of your separate scans.
          </p>
          <ul className="mt-3 space-y-2">
            {stats.repeated_mistakes.map((m) => (
              <li
                key={m.vulnerability_class}
                className="flex items-center justify-between rounded border border-yellow-600 bg-yellow-950 px-4 py-3 text-yellow-100"
              >
                <span className="font-medium">{m.label}</span>
                <span className="text-sm">
                  in {m.scans_affected} scans · {m.issues_total} issues
                </span>
              </li>
            ))}
          </ul>
          <Link href="/practice" className="mt-3 inline-block text-sm underline">
            Practice these in the exercises
          </Link>
        </section>
      )}

      {classEntries.length > 0 && (
        <section>
          <h2 className="text-lg font-semibold">Issues by type</h2>
          <ul className="mt-3 space-y-3">
            {classEntries.map(([cls, count]) => (
              <li key={cls}>
                <div className="flex justify-between text-sm">
                  <span>{labelFor(cls)}</span>
                  <span className="text-neutral-400">{count}</span>
                </div>
                <div className="mt-1 h-2 rounded bg-neutral-800">
                  <div
                    className="h-2 rounded bg-blue-500"
                    style={{ width: `${(count / maxCount) * 100}%` }}
                  />
                </div>
              </li>
            ))}
          </ul>
        </section>
      )}

      {scans.length > 0 && (
        <section>
          <h2 className="text-lg font-semibold">Recent scans</h2>
          <div className="mt-3 overflow-x-auto rounded-lg border border-neutral-700">
            <table className="w-full text-left text-sm">
              <thead className="bg-neutral-900 text-neutral-400">
                <tr>
                  <th className="px-4 py-2">When</th>
                  <th className="px-4 py-2">Language</th>
                  <th className="px-4 py-2">Issues</th>
                  <th className="px-4 py-2">Types</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((s) => (
                  <tr key={s.scan_id} className="border-t border-neutral-800">
                    <td className="px-4 py-2">{formatDate(s.created_at)}</td>
                    <td className="px-4 py-2">{s.language}</td>
                    <td className="px-4 py-2">{s.issue_count}</td>
                    <td className="px-4 py-2 text-neutral-300">
                      {Object.keys(s.issues_by_class).length === 0
                        ? "none found"
                        : Object.entries(s.issues_by_class)
                            .map(([cls, n]) => `${labelFor(cls)} (${n})`)
                            .join(", ")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}