import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import DashboardPage from "@/app/dashboard/page";
import TeacherPage from "@/app/teacher/page";

const get = vi.fn();

vi.mock("@/lib/api", async (importOriginal) => {
  const original = await importOriginal<typeof import("@/lib/api")>();
  return { ...original, get: (...args: unknown[]) => get(...args) };
});

describe("TeacherPage", () => {
  beforeEach(() => {
    get.mockReset();
  });

  it("tells non-teachers the page is not for them", async () => {
    const { ApiError } = await import("@/lib/api");
    get.mockRejectedValue(new ApiError(403, "teacher access only"));
    render(<TeacherPage />);
    expect(await screen.findByText(/teacher accounts only/)).toBeInTheDocument();
  });

  it("shows class totals and warns when the class is small", async () => {
    get.mockResolvedValue({
      students_count: 3,
      scans_count: 9,
      issues_total: 12,
      classes: [
        {
          vulnerability_class: "sql_injection",
          label: "SQL injection",
          issues_total: 7,
          students_affected: 2,
          students_repeating: 1,
          share_of_students: 0.667,
        },
      ],
    });
    render(<TeacherPage />);
    expect(await screen.findByText("Class overview")).toBeInTheDocument();
    expect(screen.getByText("SQL injection")).toBeInTheDocument();
    expect(screen.getByText("67%")).toBeInTheDocument();
    expect(screen.getByText(/fewer than 5 students/)).toBeInTheDocument();
  });

  it("does not show the small-class warning for five or more students", async () => {
    get.mockResolvedValue({ students_count: 5, scans_count: 9, issues_total: 0, classes: [] });
    render(<TeacherPage />);
    await screen.findByText("Class overview");
    expect(screen.queryByText(/fewer than 5 students/)).not.toBeInTheDocument();
  });
});

describe("DashboardPage", () => {
  beforeEach(() => {
    get.mockReset();
  });

  it("shows repeated mistakes and recent scans", async () => {
    get.mockImplementation(async (path: string) => {
      if (path === "/me/stats") {
        return {
          scans_count: 3,
          issues_total: 6,
          issues_by_class: { sql_injection: 3, hardcoded_secret: 3 },
          repeated_mistakes: [
            {
              vulnerability_class: "sql_injection",
              label: "SQL injection",
              scans_affected: 3,
              issues_total: 3,
              last_seen: null,
            },
          ],
        };
      }
      return [
        {
          scan_id: 1,
          language: "python",
          filename: null,
          created_at: "2026-11-18T07:04:57",
          issue_count: 2,
          issues_by_class: { sql_injection: 1, hardcoded_secret: 1 },
        },
      ];
    });
    render(<DashboardPage />);
    expect(await screen.findByText("Mistakes you keep repeating")).toBeInTheDocument();
    expect(screen.getByText(/in 3 scans · 3 issues/)).toBeInTheDocument();
    expect(screen.getByText("Recent scans")).toBeInTheDocument();
  });

  it("invites a new learner to scan something", async () => {
    get.mockImplementation(async (path: string) =>
      path === "/me/stats"
        ? { scans_count: 0, issues_total: 0, issues_by_class: {}, repeated_mistakes: [] }
        : [],
    );
    render(<DashboardPage />);
    expect(await screen.findByText(/You have no scans yet/)).toBeInTheDocument();
  });
});