import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import IssueCard from "@/components/IssueCard";
import type { Issue } from "@/types/learning";

const post = vi.fn();

vi.mock("@/lib/api", async (importOriginal) => {
  const original = await importOriginal<typeof import("@/lib/api")>();
  return { ...original, post: (...args: unknown[]) => post(...args) };
});

const issue: Issue = {
  index: 0,
  line_number: 8,
  vulnerability_class: "sql_injection",
  label: "SQL injection",
  cwe: "CWE-89",
  owasp: "A05:2025 Injection",
  severity: "high",
  code_snippet: 'cur.execute("SELECT " + name)',
  detectors: ["bandit", "semgrep"],
};

describe("IssueCard", () => {
  beforeEach(() => {
    post.mockReset();
  });

  it("shows what was found before anything is explained", () => {
    render(<IssueCard scanId={7} issue={issue} />);
    expect(screen.getByText("SQL injection")).toBeInTheDocument();
    expect(screen.getByText(/Line 8/)).toBeInTheDocument();
    expect(screen.getByText(/CWE-89/)).toBeInTheDocument();
    expect(screen.getByText(/Found by bandit, semgrep/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Explain this issue" })).toBeInTheDocument();
  });

  it("asks the backend for an explanation of this scan and issue", async () => {
    post.mockResolvedValue({
      vulnerability_type: "SQL injection",
      exploit_scenario: "An attacker types a quote.",
      fixed_code_example: "cur.execute(sql, (name,))",
      owasp_mapping: null,
      source: "llm",
      fix_rescan: "clean",
    });
    render(<IssueCard scanId={7} issue={issue} />);
    await userEvent.click(screen.getByRole("button", { name: "Explain this issue" }));

    expect(post).toHaveBeenCalledWith("/explain", { scan_id: 7, issue_index: 0 });
    expect(await screen.findByText("An attacker types a quote.")).toBeInTheDocument();
    expect(screen.getByText("cur.execute(sql, (name,))")).toBeInTheDocument();
    expect(screen.getByText(/AI-written explanation/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Explain this issue" })).not.toBeInTheDocument();
  });

  it("says plainly when the explanation was written in advance, not by AI", async () => {
    post.mockResolvedValue({
      vulnerability_type: "SQL injection",
      exploit_scenario: "Static text.",
      fixed_code_example: "safe()",
      owasp_mapping: null,
      source: "static",
      fix_rescan: "not_checked",
    });
    render(<IssueCard scanId={7} issue={issue} />);
    await userEvent.click(screen.getByRole("button", { name: "Explain this issue" }));
    expect(await screen.findByText(/no AI used/)).toBeInTheDocument();
  });

  it("shows the server's message when explaining fails", async () => {
    const { ApiError } = await import("@/lib/api");
    post.mockRejectedValue(new ApiError(429, "too many explanation requests, please wait"));
    render(<IssueCard scanId={7} issue={issue} />);
    await userEvent.click(screen.getByRole("button", { name: "Explain this issue" }));
    expect(await screen.findByText(/too many explanation requests/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Explain this issue" })).toBeInTheDocument();
  });
});