"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import CodeEditor from "@/components/CodeEditor";
import { ApiError, get, post } from "@/lib/api";
import type {
  AttemptResponse,
  ExerciseDetail,
  ExerciseSummary,
  ProgressResponse,
} from "@/types/learning";

export default function PracticePage() {
  const [exercises, setExercises] = useState<ExerciseSummary[]>([]);
  const [progress, setProgress] = useState<ProgressResponse | null>(null);
  const [needsLogin, setNeedsLogin] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);

  const [selected, setSelected] = useState<ExerciseDetail | null>(null);
  const [code, setCode] = useState("");
  const [showHint, setShowHint] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<AttemptResponse | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [list, prog] = await Promise.all([
        get<ExerciseSummary[]>("/exercises"),
        get<ProgressResponse>("/me/progress"),
      ]);
      setExercises(list);
      setProgress(prog);
      setNeedsLogin(false);
      setLoadError(null);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        setNeedsLogin(true);
      } else {
        setLoadError(err instanceof ApiError ? err.message : "Could not load exercises");
      }
    } finally {
      setLoaded(true);
    }
  }, []);

  useEffect(() => {
    async function init() {
      await refresh();
    }
    init();
  }, [refresh]);

  async function openExercise(id: string) {
    setResult(null);
    setSubmitError(null);
    setShowHint(false);
    try {
      const detail = await get<ExerciseDetail>(`/exercises/${id}`);
      setSelected(detail);
      setCode(detail.vulnerable_code);
    } catch (err) {
      setSubmitError(err instanceof ApiError ? err.message : "Could not open the exercise");
    }
  }

  async function handleSubmit() {
    if (!selected) return;
    setSubmitting(true);
    setSubmitError(null);
    setResult(null);
    try {
      const outcome = await post<AttemptResponse>(`/exercises/${selected.id}/attempt`, { code });
      setResult(outcome);
      refresh();
    } catch (err) {
      if (err instanceof ApiError && err.status === 503) {
        setSubmitError(
          "The checker could not finish this time (a scanner timed out). Nothing was recorded. Please try again."
        );
      } else {
        setSubmitError(err instanceof ApiError ? err.message : "Something went wrong");
      }
    } finally {
      setSubmitting(false);
    }
  }

  if (!loaded) {
    return <p className="text-neutral-400">Loading exercises…</p>;
  }

  if (needsLogin) {
    return (
      <div>
        <h1 className="text-2xl font-bold">Practice</h1>
        <p className="mt-4 text-neutral-300">
          Please{" "}
          <Link href="/login" className="underline">
            log in
          </Link>{" "}
          to practice. Your progress is saved to your account.
        </p>
      </div>
    );
  }

  if (loadError) {
    return (
      <div>
        <h1 className="text-2xl font-bold">Practice</h1>
        <p className="mt-4 rounded border border-red-500 bg-red-950 p-3 text-red-200">{loadError}</p>
      </div>
    );
  }

  const classes = Array.from(new Set(exercises.map((e) => e.vulnerability_class)));

  return (
    <div>
      <div className="flex items-end justify-between">
        <h1 className="text-2xl font-bold">Practice</h1>
        {progress && (
          <p className="text-sm text-neutral-400">
            {progress.exercises_completed} of {progress.exercises_total} completed
          </p>
        )}
      </div>

      <div className="mt-6 grid gap-6 md:grid-cols-[260px_1fr]">
        <aside className="space-y-5">
          {classes.map((cls) => {
            const items = exercises.filter((e) => e.vulnerability_class === cls);
            const done = items.filter((e) => e.completed).length;
            return (
              <div key={cls}>
                <h2 className="text-xs font-semibold uppercase tracking-wide text-neutral-400">
                  {items[0].label} · {done}/{items.length}
                </h2>
                <ul className="mt-2 space-y-1">
                  {items.map((e) => (
                    <li key={e.id}>
                      <button
                        onClick={() => openExercise(e.id)}
                        className={`w-full rounded px-3 py-2 text-left text-sm hover:bg-neutral-800 ${
                          selected?.id === e.id ? "bg-neutral-800" : ""
                        }`}
                      >
                        <span className="mr-2">{e.completed ? "✓" : "○"}</span>
                        {e.title}
                        <span className="ml-2 text-xs text-neutral-500">
                          {e.language === "python" ? "Py" : "JS"}
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
        </aside>

        <section>
          {!selected && (
            <p className="text-neutral-400">
              Pick an exercise on the left. Each one gives you vulnerable code. Fix it, then submit.
              The checker scans your code again and passes you when the problem is gone.
            </p>
          )}

          {selected && (
            <div className="space-y-4">
              <div>
                <h2 className="text-xl font-semibold">{selected.title}</h2>
                <p className="mt-1 text-sm text-neutral-400">
                  {selected.label} · {selected.language === "python" ? "Python" : "JavaScript"}
                </p>
                <p className="mt-3 text-neutral-200">{selected.scenario}</p>
              </div>

              <CodeEditor value={code} language={selected.language} onChange={setCode} />

              <div className="flex flex-wrap gap-3">
                <button
                  onClick={handleSubmit}
                  disabled={submitting || code.trim() === ""}
                  className="rounded bg-blue-600 px-5 py-2 font-semibold hover:bg-blue-500 disabled:opacity-50"
                >
                  {submitting ? "Checking…" : "Submit fix"}
                </button>
                <button
                  onClick={() => setShowHint((v) => !v)}
                  className="rounded border border-neutral-700 px-4 py-2 text-sm hover:bg-neutral-800"
                >
                  {showHint ? "Hide hint" : "Show hint"}
                </button>
                <button
                  onClick={() => {
                    setCode(selected.vulnerable_code);
                    setResult(null);
                  }}
                  className="rounded border border-neutral-700 px-4 py-2 text-sm hover:bg-neutral-800"
                >
                  Reset code
                </button>
              </div>

              {showHint && (
                <p className="rounded border border-neutral-700 bg-neutral-900 p-3 text-sm text-neutral-200">
                  {selected.hint}
                </p>
              )}

              {submitError && (
                <p className="rounded border border-red-500 bg-red-950 p-3 text-sm text-red-200">
                  {submitError}
                </p>
              )}

              {result && result.passed && (
                <div className="rounded border border-green-500 bg-green-950 p-4 text-green-100">
                  <p className="font-semibold">Passed. The scanners no longer flag this problem.</p>
                  <p className="mt-1 text-xs opacity-80">
                    Passing means no scanner reports this issue any more. It does not prove the code
                    is perfectly safe.
                  </p>
                  {result.reference_fix && (
                    <>
                      <p className="mt-3 text-sm font-semibold">One reference solution</p>
                      <pre className="mt-1 overflow-x-auto rounded bg-black/40 p-3 text-sm">
                        {result.reference_fix}
                      </pre>
                    </>
                  )}
                </div>
              )}

              {result && !result.passed && (
                <div className="rounded border border-yellow-500 bg-yellow-950 p-4 text-yellow-100">
                  <p className="font-semibold">Not yet. The scanners still report:</p>
                  <ul className="mt-2 list-disc pl-5 text-sm">
                    {result.remaining.map((r, i) => (
                      <li key={i}>
                        {r.label}
                        {r.line_number !== null ? ` on line ${r.line_number}` : ""}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}