"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { get, post } from "@/lib/api";

export default function Navbar() {
  const pathname = usePathname();
  const router = useRouter();
  const [loggedIn, setLoggedIn] = useState<boolean | null>(null);

  useEffect(() => {
    async function check() {
      try {
        await get("/me/scans?limit=1");
        setLoggedIn(true);
      } catch {
        setLoggedIn(false);
      }
    }
    check();
  }, [pathname]);

  async function handleLogout() {
    try {
      await post("/auth/logout", {});
    } finally {
      setLoggedIn(false);
      router.push("/login");
    }
  }

  return (
    <nav className="flex items-center justify-between border-b border-neutral-800 px-6 py-4">
      <Link href="/" className="text-lg font-bold">
        VulnScope
      </Link>
      <div className="flex gap-4 text-sm">
        <Link href="/" className="hover:underline">
          Scan
        </Link>
        {loggedIn && (
          <>
            <Link href="/practice" className="hover:underline">
              Practice
            </Link>
            <Link href="/dashboard" className="hover:underline">
              Dashboard
            </Link>
            <Link href="/teacher" className="hover:underline">
              Teacher
            </Link>
            <button onClick={handleLogout} className="hover:underline">
              Logout
            </button>
          </>
        )}
        {loggedIn === false && (
          <>
            <Link href="/login" className="hover:underline">
              Login
            </Link>
            <Link href="/register" className="hover:underline">
              Register
            </Link>
          </>
        )}
      </div>
    </nav>
  );
}