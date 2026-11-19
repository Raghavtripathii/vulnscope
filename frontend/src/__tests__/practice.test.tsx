import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import PracticePage from "@/app/practice/page";

const get = vi.fn();
const post = vi.fn();

vi.mock("@/lib/api", async (importOriginal) => {
  const original = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...original,
    get: (...args: unknown[]) => get(...args),
    post: (...args: unknown[]) => post(...args),
  };
});

vi.mock("@/components/CodeEditor", () => ({
  default: ({ value, onChange }: { value: string; onChange: (v: string) => void }) => (
    <textarea aria-label="code" value={value} onChange={(e) => onChange(e.target.value)} />
  ),
}));

const exercises = [
  {
    id: "sqli-py-login",
    vulnerability_class: "sql_injection",
    label: "SQL injection",
    language: "python",
    title: "Look up a user by username",
    completed: true,
  },
  {
    id: "secret-py-api-key",
    vulnerability_class: "hardcoded_secret",
    label: "Hardcoded secret",
    language: "python",
    title: "Remove the payment key from the source",
    completed: false,
  },
];

const detail = {
  ...exercises[1],
  scenario: "A payment key is typed into the file.",
  vulnerable_code: 'KEY = "sk_live_123"',
  hint: "Read it from the environment.",
};

const progress = { exercises_total: 2, exercises_completed: 1, by_class: [], exercises: [] };

function serve() {
  get.mockImplementation(async (path: string) => {
    if (path === "/exercises") return exercises;
    if (path === "/me/progress") return progress;
    if (path === "/exercises/secret-py-api-key") return detail;
    throw new Error(`unexpected ${path}`);
  });
}

async function openSecretExercise() {
  render(<PracticePage />);
  await userEvent.click(await screen.findByText("Remove the payment key from the source"));
  await screen.findByText("A payment key is typed into the file.");
}

describe("PracticePage", () => {
  beforeEach(() => {
    get.mockReset();
    post.mockReset();
  });

  it("asks a signed-out visitor to log in", async () => {
    const { ApiError } = await import("@/lib/api");
    get.mockRejectedValue(new ApiError(401, "login required"));
    render(<PracticePage />);
    expect(await screen.findByText(/to practice/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "log in" })).toHaveAttribute("href", "/login");
  });

  it("lists exercises by class with progress and ticks", async () => {
    serve();
    render(<PracticePage />);
    expect(await screen.findByText("1 of 2 completed")).toBeInTheDocument();
    expect(screen.getByText(/SQL injection · 1\/1/)).toBeInTheDocument();
    expect(screen.getByText(/Hardcoded secret · 0\/1/)).toBeInTheDocument();
    expect(screen.getByText("✓")).toBeInTheDocument();
  });

  it("opens an exercise with its vulnerable code and a hint on request", async () => {
    serve();
    await openSecretExercise();
    expect(screen.getByLabelText("code")).toHaveValue('KEY = "sk_live_123"');
    expect(screen.queryByText("Read it from the environment.")).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Show hint" }));
    expect(screen.getByText("Read it from the environment.")).toBeInTheDocument();
  });

  it("sends the edited code and shows a pass with the reference solution", async () => {
    serve();
    post.mockResolvedValue({
      passed: true,
      remaining: [],
      detectors: { semgrep: "ok", bandit: "ok" },
      reference_fix: "KEY = os.environ['KEY']",
    });
    await openSecretExercise();
    const editor = screen.getByLabelText("code");
    await userEvent.clear(editor);
    await userEvent.type(editor, "fixed");
    await userEvent.click(screen.getByRole("button", { name: "Submit fix" }));

    expect(post).toHaveBeenCalledWith("/exercises/secret-py-api-key/attempt", { code: "fixed" });
    expect(await screen.findByText(/Passed\./)).toBeInTheDocument();
    expect(screen.getByText("KEY = os.environ['KEY']")).toBeInTheDocument();
  });

  it("lists what is still wrong when the fix does not pass", async () => {
    serve();
    post.mockResolvedValue({
      passed: false,
      remaining: [{ line_number: 1, vulnerability_class: "hardcoded_secret", label: "Hardcoded secret" }],
      detectors: { semgrep: "ok", bandit: "ok" },
      reference_fix: null,
    });
    await openSecretExercise();
    await userEvent.click(screen.getByRole("button", { name: "Submit fix" }));
    expect(await screen.findByText(/Not yet/)).toBeInTheDocument();
    expect(screen.getByText(/Hardcoded secret on line 1/)).toBeInTheDocument();
  });

  it("tells the learner to try again when the checker could not finish", async () => {
    serve();
    const { ApiError } = await import("@/lib/api");
    post.mockRejectedValue(new ApiError(503, "could not check"));
    await openSecretExercise();
    await userEvent.click(screen.getByRole("button", { name: "Submit fix" }));
    expect(await screen.findByText(/Nothing was recorded/)).toBeInTheDocument();
  });
});