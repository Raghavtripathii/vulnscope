"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ApiError, get } from "@/lib/api";
import type { TeacherStats } from "@/types/learning";

type Problem = "login" | "forbidden" | string | null;

export default function TeacherPage() {
  const [stats, setStats] = useState<TeacherStats | null>(null);
  const [problem, setProblem] = useState<Problem>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    async function load() {
      try {
        setStats(await get<TeacherStats>("/teacher/stats"));
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) setProblem("login");
        else if (err instanceof ApiError && err.status === 403) setProblem("forbidden");
        else setProblem(err instanceof ApiError ? err.message : "Could not load class statistics");
      } finally {
        setLoaded(true);
      }
    }
    load();
  }, []);

  if (!loaded) return <p className="text-neutral-400">Loading class statistics…</p>;

  if (problem === "login") {
    return (
      <div>
        <h1 className="text-2xl font-bold">Class overview</h1>
        <p className="mt-4 text-neutral-300">
          Please{" "}
          <Link href="/login" className="underline">
            log in
          </Link>{" "}
          with a teacher account.
        </p>
      </div>
    );
  }

  if (problem === "forbidden") {
    return (
      <div>
        <h1 className="text-2xl font-bold">Class overview</h1>
        <p className="mt-4 rounded border border-neutral-700 bg-neutral-900 p-3 text-neutral-300">
          This page is for teacher accounts only.
        </p>
      </div>
    );
  }

  if (problem || !stats) {
    return (
      <div>
        <h1 className="text-2xl font-bold">Class overview</h1>
        <p className="mt-4 rounded border border-red-500 bg-red-950 p-3 text-red-200">
          {problem ?? "Could not load class statistics"}
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold">Class overview</h1>
        <p className="mt-1 text-sm text-neutral-400">
          Totals across all students. Individual students are never shown.
        </p>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="rounded-lg border border-neutral-700 bg-neutral-900 p-4">
          <p className="text-sm text-neutral-400">Students</p>
          <p className="text-3xl font-bold">{stats.students_count}</p>
        </div>
        <div className="rounded-lg border border-neutral-700 bg-neutral-900 p-4">
          <p className="text-sm text-neutral-400">Scans</p>
          <p className="text-3xl font-bold">{stats.scans_count}</p>
        </div>
        <div className="rounded-lg border border-neutral-700 bg-neutral-900 p-4">
          <p className="text-sm text-neutral-400">Issues</p>
          <p className="text-3xl font-bold">{stats.issues_total}</p>
        </div>
      </div>

      {stats.students_count < 5 && (
        <p className="rounded border border-yellow-600 bg-yellow-950 p-3 text-sm text-yellow-100">
          With fewer than 5 students, these numbers can point to individuals. Treat them carefully.
        </p>
      )}

      <section>
        <h2 className="text-lg font-semibold">Where the class struggles</h2>
        <p className="mt-1 text-sm text-neutral-400">
          Sorted by how many students hit each problem. “Repeating” means the student hit it in two or
          more separate scans.
        </p>
        <div className="mt-3 overflow-x-auto rounded-lg border border-neutral-700">
          <table className="w-full text-left text-sm">
            <thead className="bg-neutral-900 text-neutral-400">
              <tr>
                <th className="px-4 py-2">Problem type</th>
                <th className="px-4 py-2">Students affected</th>
                <th className="px-4 py-2">Share of class</th>
                <th className="px-4 py-2">Repeating</th>
                <th className="px-4 py-2">Issues</th>
              </tr>
            </thead>
            <tbody>
              {stats.classes.map((c) => (
                <tr key={c.vulnerability_class} className="border-t border-neutral-800">
                  <td className="px-4 py-2 font-medium">{c.label}</td>
                  <td className="px-4 py-2">{c.students_affected}</td>
                  <td className="px-4 py-2">
                    <div className="flex items-center gap-2">
                      <div className="h-2 w-24 rounded bg-neutral-800">
                        <div
                          className="h-2 rounded bg-blue-500"
                          style={{ width: `${Math.round(c.share_of_students * 100)}%` }}
                        />
                      </div>
                      <span>{Math.round(c.share_of_students * 100)}%</span>
                    </div>
                  </td>
                  <td className="px-4 py-2">{c.students_repeating}</td>
                  <td className="px-4 py-2">{c.issues_total}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}