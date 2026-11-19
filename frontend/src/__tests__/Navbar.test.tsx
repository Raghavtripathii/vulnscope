import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Navbar from "@/components/Navbar";

const get = vi.fn();
const post = vi.fn();
const push = vi.fn();

vi.mock("@/lib/api", async (importOriginal) => {
  const original = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...original,
    get: (...args: unknown[]) => get(...args),
    post: (...args: unknown[]) => post(...args),
  };
});

vi.mock("next/navigation", () => ({
  usePathname: () => "/",
  useRouter: () => ({ push }),
}));

describe("Navbar", () => {
  beforeEach(() => {
    get.mockReset();
    post.mockReset();
    push.mockReset();
  });

  it("offers Login and Register to someone who is not signed in", async () => {
    const { ApiError } = await import("@/lib/api");
    get.mockRejectedValue(new ApiError(401, "login required"));
    render(<Navbar />);
    expect(await screen.findByText("Login")).toBeInTheDocument();
    expect(screen.getByText("Register")).toBeInTheDocument();
    expect(screen.queryByText("Practice")).not.toBeInTheDocument();
  });

  it("shows the signed-in email and learner links to a student, without Teacher", async () => {
    get.mockResolvedValue({ id: 1, email: "student@example.com", is_teacher: false });
    render(<Navbar />);
    expect(await screen.findByText("student@example.com")).toBeInTheDocument();
    expect(screen.getByText("Practice")).toBeInTheDocument();
    expect(screen.getByText("Dashboard")).toBeInTheDocument();
    expect(screen.queryByText("Teacher")).not.toBeInTheDocument();
    expect(screen.queryByText("Login")).not.toBeInTheDocument();
  });

  it("shows the Teacher link only for teachers", async () => {
    get.mockResolvedValue({ id: 2, email: "teacher@example.com", is_teacher: true });
    render(<Navbar />);
    expect(await screen.findByText("Teacher")).toBeInTheDocument();
  });

  it("logs out and goes to the login page", async () => {
    get.mockResolvedValue({ id: 1, email: "student@example.com", is_teacher: false });
    post.mockResolvedValue(undefined);
    render(<Navbar />);
    await userEvent.click(await screen.findByText("Logout"));
    expect(post).toHaveBeenCalledWith("/auth/logout", {});
    expect(push).toHaveBeenCalledWith("/login");
    expect(await screen.findByText("Login")).toBeInTheDocument();
  });
});